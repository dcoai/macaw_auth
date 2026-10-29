defmodule Macaw.Auth.Native.Throttle do
  @moduledoc """
  Sign-in throttling for `Macaw.Auth.Native.authenticate/2` (ported from
  exio's and macaw's `Accounts.Throttle`, which are the same mechanism).

  Failures are counted per account and per client address. The first
  five are free; after `n` consecutive failures (n ≥ 5) a key waits
  `2^(n-5)` seconds from its last failure, capped at 15 minutes, and an
  attempt inside the wait is refused (`:throttled`) without checking the
  password. Nothing is ever locked for good: the right password succeeds
  once the wait has passed, so a guesser can't lock a user out for longer
  than the cap.

  - **Both keys.** The user key slows guessing one account from many
    addresses; the address key slows one address trying many accounts.
    An attempt waits for the longer of the two.
  - **The account, not its name.** A username that names an account is
    counted on the account's id (`user_key/1`), so renaming it keeps the
    count. A name no account has is counted on the name, with the same
    curve, so an unknown name is slowed exactly as a known one and the
    wait tells a guesser nothing about which names exist.
  - **A success resets the user key only.** Resetting the address too
    would let a guesser who holds one valid account clear their address's
    count between guesses at others.
  - **No address, no address key.** A caller that passes no `:remote_ip`
    (a console task) is throttled by its user key alone, rather than
    sharing one "unknown address" key with every other such caller.
  - **In the database.** The counts are rows of `macaw_auth_throttle`
    (`Macaw.Auth.Native.ThrottleRecord`) in the configured repo, so a
    restart, a crash or a deploy gives a guesser no fresh budget.
  - **Idle keys are swept.** A key whose last failure is more than a day
    old is deleted, so the table holds recent failures only, whatever an
    attacker sends.
  - **Not a request rate limit.** `Macaw.Plug.RateLimit` limits requests
    per window; this is a different policy (backoff after failures, reset
    by success), so it is its own small table rather than a configuration
    of that one.

  This process, which the macaw_auth application starts, only runs the
  sweep. Every function takes the time as `now`, in milliseconds of the
  system clock, so tests drive it without sleeping. The values are
  constants: mechanism, not a host's policy.
  """

  use GenServer

  import Ecto.Query, only: [from: 2, dynamic: 2]

  alias Macaw.Auth.Native.{Config, ThrottleRecord, UserRecord}

  @free 5
  @cap_ms 15 * 60 * 1000
  @idle_ms 24 * 60 * 60 * 1000
  @sweep_every_ms 10 * 60 * 1000

  @typedoc """
  A user key: `{:account, id}` for a username that names an account,
  `{:name, name}` for a normalized username no account has, `:invalid`
  for anything that can't be a username, or `{:second_factor, id}` (an
  account's code attempts, counted apart from its passwords:
  `Macaw.Auth.Native`).
  """
  @type user ::
          {:account, Ecto.UUID.t()}
          | {:name, String.t()}
          | :invalid
          | {:second_factor, Ecto.UUID.t()}
  @type key :: {:user, user()} | {:ip, String.t()}

  @doc """
  Starts the sweep's owner. Options: `:sweep_every_ms` (default ten
  minutes) and `:clock` (a zero-arity function giving `now` in ms, default
  the system clock).
  """
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "The wait after `failures` consecutive failures, in ms."
  @spec delay_ms(non_neg_integer()) :: non_neg_integer()
  def delay_ms(failures) when failures < @free, do: 0
  def delay_ms(failures) when failures >= @free + 10, do: @cap_ms
  def delay_ms(failures), do: min(Integer.pow(2, failures - @free) * 1000, @cap_ms)

  @doc """
  The user key for a typed `username`: `{:account, id}` when a users row
  has it (normalized as the table stores it), else `{:name, name}`, or
  `:invalid` when it can't be a username. One indexed look-up, known name
  or not.
  """
  @spec user_key(term()) :: user()
  def user_key(username) do
    case UserRecord.normalize_username(username) do
      {:ok, name} ->
        case repo().one(from(u in UserRecord, where: u.username == ^name, select: u.id)) do
          nil -> {:name, name}
          id -> {:account, id}
        end

      {:error, :invalid_username} ->
        :invalid
    end
  end

  @doc """
  `:ok`, or `{:delay, ms}` left before `user` or `ip` may try again at
  `now`.
  """
  @spec check(user(), String.t() | nil, integer()) :: :ok | {:delay, pos_integer()}
  def check(user, ip, now) do
    user
    |> keys(ip)
    |> lookup()
    |> Enum.map(fn {_key, failures, last} -> max(delay_ms(failures) - (now - last), 0) end)
    |> Enum.max(fn -> 0 end)
    |> case do
      0 -> :ok
      ms -> {:delay, ms}
    end
  end

  # The keys' rows, read in one query.
  defp lookup(keys) do
    match =
      keys
      |> Enum.map(fn key ->
        {kind, subject} = ThrottleRecord.columns(key)
        dynamic([r], r.kind == ^kind and r.subject == ^subject)
      end)
      |> Enum.reduce(&dynamic([r], ^&2 or ^&1))

    from(r in ThrottleRecord, where: ^match) |> repo().all() |> Enum.map(&row/1)
  end

  @doc "Records a failure for `user` and `ip` at `now`."
  @spec failure(user(), String.t() | nil, integer()) :: :ok
  def failure(user, ip, now) do
    # Sorted, so concurrent failures lock rows in one order and never
    # deadlock each other on a database that locks rows (Postgres).
    rows =
      user
      |> keys(ip)
      |> Enum.map(&ThrottleRecord.columns/1)
      |> Enum.sort()
      |> Enum.map(fn {kind, subject} ->
        %{kind: kind, subject: subject, failures: 1, last_failure_ms: now}
      end)

    {_count, nil} =
      repo().insert_all(ThrottleRecord, rows,
        on_conflict: count(now),
        conflict_target: [:kind, :subject]
      )

    :ok
  end

  # One failure, in one atomic upsert of each row: a new row holds one
  # failure at `now`; an existing one gets one more failure, and the later
  # of its time and `now`. Concurrent failures each count, and the row
  # keeps the latest of their times, whichever is recorded last: a sign-in
  # takes `now` before it hashes, so an earlier `now` can arrive second.
  # (Counting, then writing `now` in a second statement, let it overwrite
  # a later time, and let a check between the two see the new count from
  # the old time: both shortened the wait, spec/10 §7.) `CASE`, not
  # `max`/`GREATEST`, which are each one database's.
  defp count(now) do
    from(r in ThrottleRecord,
      update: [
        inc: [failures: 1],
        set: [
          last_failure_ms:
            fragment(
              "CASE WHEN ? < ? THEN ? ELSE ? END",
              r.last_failure_ms,
              type(^now, :integer),
              type(^now, :integer),
              r.last_failure_ms
            )
        ]
      ]
    )
  end

  @doc "A success resets the user key's count (not the address's)."
  @spec success(user()) :: :ok
  def success(user) do
    {kind, subject} = ThrottleRecord.columns({:user, user})
    repo().delete_all(from(r in ThrottleRecord, where: r.kind == ^kind and r.subject == ^subject))
    :ok
  end

  @doc "Forgets keys whose last failure is older than a day at `now`; returns how many."
  @spec sweep(integer()) :: non_neg_integer()
  def sweep(now) do
    cutoff = now - @idle_ms

    {forgot, nil} =
      repo().delete_all(from(r in ThrottleRecord, where: r.last_failure_ms < ^cutoff))

    forgot
  end

  @doc "Forgets everything (tests, and an operator's reset)."
  @spec reset() :: :ok
  def reset do
    repo().delete_all(ThrottleRecord)
    :ok
  end

  @doc """
  Every row as `{key, failures, last_failure_ms}`, sorted: what an
  operator reads to see who waits, and what the tests compare.
  """
  @spec rows() :: [{key(), pos_integer(), integer()}]
  def rows, do: ThrottleRecord |> repo().all() |> Enum.map(&row/1) |> Enum.sort()

  defp row(%ThrottleRecord{} = r),
    do: {ThrottleRecord.key(r.kind, r.subject), r.failures, r.last_failure_ms}

  @doc "The system clock in ms, the time every caller passes as `now`."
  @spec now() :: integer()
  def now, do: System.system_time(:millisecond)

  defp keys(user, nil), do: [{:user, user}]
  defp keys(user, ip), do: [{:user, user}, {:ip, ip}]

  defp repo, do: Config.get().repo

  @impl true
  def init(opts) do
    state = %{every: Keyword.get(opts, :sweep_every_ms, @sweep_every_ms), clock: clock(opts)}
    schedule(state)
    {:ok, state}
  end

  defp clock(opts), do: Keyword.get(opts, :clock, &now/0)

  # The application starts this process whichever backend is configured;
  # with no native configuration there is no table to sweep. A native
  # configuration with a fault is not this process's to report: boot, or
  # the first sign-in, raises it.
  @impl true
  def handle_info(:sweep, state) do
    case Config.fetch() do
      {:ok, _config} -> sweep(state.clock.())
      {:error, _no_native_backend} -> 0
    end

    schedule(state)
    {:noreply, state}
  end

  defp schedule(%{every: every}), do: Process.send_after(self(), :sweep, every)
end
