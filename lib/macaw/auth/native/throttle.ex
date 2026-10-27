defmodule Macaw.Auth.Native.Throttle do
  @moduledoc """
  Sign-in throttling for `Macaw.Auth.Native.authenticate/2` (ported from
  exio's and macaw's `Accounts.Throttle`, which are the same mechanism).

  Failures are counted per normalized username and per client address.
  The first five are free; after `n` consecutive failures (n ≥ 5) a key
  waits `2^(n-5)` seconds from its last failure, capped at 15 minutes, and
  an attempt inside the wait is refused (`:throttled`) without checking
  the password. Nothing is ever locked for good: the right password
  succeeds once the wait has passed, so a guesser can't lock a user out
  for longer than the cap.

  - **Both keys.** The username key slows guessing one account from many
    addresses; the address key slows one address trying many accounts.
    An attempt waits for the longer of the two.
  - **A success resets the username only.** Resetting the address too
    would let a guesser who holds one valid account clear their address's
    count between guesses at others.
  - **No address, no address key.** A caller that passes no `:remote_ip`
    (a console task) is throttled by username alone, rather than sharing
    one "unknown address" key with every other such caller.
  - **Idle keys are swept.** A key whose last failure is more than a day
    old is forgotten, so the table holds recent failures only, whatever
    an attacker sends.
  - **Not a request rate limit.** `Macaw.Plug.RateLimit` limits requests
    per window; this is a different policy (backoff after failures, reset
    by success), so it is its own small table rather than a configuration
    of that one.

  The counts live in a public ETS table owned by this process, which the
  macaw_auth application starts. Every function takes the time as `now`,
  in milliseconds of the system clock, so tests drive it without
  sleeping. The values are constants: mechanism, not a host's policy.
  """

  use GenServer

  @table __MODULE__
  @free 5
  @cap_ms 15 * 60 * 1000
  @idle_ms 24 * 60 * 60 * 1000
  @sweep_every_ms 10 * 60 * 1000

  @type key :: {:user, String.t() | :invalid} | {:ip, String.t()}

  @doc """
  Starts the table's owner. Options: `:sweep_every_ms` (default ten
  minutes) and `:clock` (a zero-arity function giving `now` in ms, default
  the system clock), for the periodic sweep.
  """
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "The wait after `failures` consecutive failures, in ms."
  @spec delay_ms(non_neg_integer()) :: non_neg_integer()
  def delay_ms(failures) when failures < @free, do: 0
  def delay_ms(failures) when failures >= @free + 10, do: @cap_ms
  def delay_ms(failures), do: min(Integer.pow(2, failures - @free) * 1000, @cap_ms)

  @doc """
  `:ok`, or `{:delay, ms}` left before `username` or `ip` may try again
  at `now`.
  """
  @spec check(String.t() | :invalid, String.t() | nil, integer()) :: :ok | {:delay, pos_integer()}
  def check(username, ip, now) do
    username
    |> keys(ip)
    |> Enum.map(&remaining(&1, now))
    |> Enum.max()
    |> case do
      0 -> :ok
      ms -> {:delay, ms}
    end
  end

  defp remaining(key, now) do
    case :ets.lookup(@table, key) do
      [{^key, failures, last}] -> max(delay_ms(failures) - (now - last), 0)
      [] -> 0
    end
  end

  @doc "Records a failure for `username` and `ip` at `now`."
  @spec failure(String.t() | :invalid, String.t() | nil, integer()) :: :ok
  def failure(username, ip, now) do
    for key <- keys(username, ip) do
      # Both atomic: concurrent failures each count, and the last-failure
      # time is one of theirs.
      :ets.update_counter(@table, key, {2, 1}, {key, 0, now})
      :ets.update_element(@table, key, {3, now})
    end

    :ok
  end

  @doc "A success resets the username's count (not the address's)."
  @spec success(String.t() | :invalid) :: :ok
  def success(username) do
    :ets.delete(@table, {:user, username})
    :ok
  end

  @doc "Forgets keys whose last failure is older than a day at `now`; returns how many."
  @spec sweep(integer()) :: non_neg_integer()
  def sweep(now) do
    cutoff = now - @idle_ms
    :ets.select_delete(@table, [{{:_, :_, :"$1"}, [{:<, :"$1", cutoff}], [true]}])
  end

  @doc "Forgets everything (tests, and an operator's reset)."
  @spec reset() :: :ok
  def reset do
    :ets.delete_all_objects(@table)
    :ok
  end

  @doc "The system clock in ms, the time every caller passes as `now`."
  @spec now() :: integer()
  def now, do: System.system_time(:millisecond)

  defp keys(username, nil), do: [{:user, username}]
  defp keys(username, ip), do: [{:user, username}, {:ip, ip}]

  @impl true
  def init(opts) do
    :ets.new(@table, [:named_table, :public, :set, write_concurrency: true])
    state = %{every: Keyword.get(opts, :sweep_every_ms, @sweep_every_ms), clock: clock(opts)}
    schedule(state)
    {:ok, state}
  end

  defp clock(opts), do: Keyword.get(opts, :clock, &now/0)

  @impl true
  def handle_info(:sweep, state) do
    sweep(state.clock.())
    schedule(state)
    {:noreply, state}
  end

  defp schedule(%{every: every}), do: Process.send_after(self(), :sweep, every)
end
