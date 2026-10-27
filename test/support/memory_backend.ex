defmodule Macaw.Auth.Test.MemoryBackend do
  @moduledoc """
  A backend that keeps users and sessions in ETS: the smallest correct
  implementation of `Macaw.Auth.Backend`, which proves the contract, the
  plugs and the hooks without a database. Tokens are stored as SHA-256.

  Its second factor is TOTP (`NimbleTOTP`, ±1 step) with the same replay
  guard as the native backend's: the last accepted step is replaced only
  by a later one, atomically (`:ets.select_replace/2`). No throttle and no
  recovery codes: the kit doesn't ask for them.
  """

  @behaviour Macaw.Auth.Backend
  @behaviour Macaw.Auth.Conformance.Fixtures

  alias Macaw.Auth.{Session, User}

  @users __MODULE__.Users
  @sessions __MODULE__.Sessions
  @factors __MODULE__.Factors
  @idle 3_600
  @touch_every 300

  # ── Fixtures ──────────────────────────────────────────────────────────

  @impl Macaw.Auth.Conformance.Fixtures
  def reset! do
    for t <- [@users, @sessions, @factors] do
      if :ets.whereis(t) == :undefined,
        do: :ets.new(t, [:named_table, :public, :set]),
        else: :ets.delete_all_objects(t)
    end

    :ok
  end

  @impl Macaw.Auth.Conformance.Fixtures
  def user!(attrs) do
    n = System.unique_integer([:positive])
    password = "correct horse #{n}"

    user = %User{
      id: n,
      username: Map.get(attrs, :username, "user#{n}"),
      roles: Map.get(attrs, :roles, ["viewer"]),
      source: "local",
      second_factor: Map.get(attrs, :second_factor, :none),
      must_change_password: Map.get(attrs, :must_change_password, false)
    }

    :ets.insert(@users, {user.username, user, :crypto.hash(:sha256, password)})
    {user, %{username: user.username, password: password}}
  end

  @impl Macaw.Auth.Conformance.Fixtures
  def disable!(%User{username: name}) do
    [{^name, user, hash}] = :ets.lookup(@users, name)
    :ets.insert(@users, {name, %{user | disabled: true}, hash})
    :ok
  end

  @impl Macaw.Auth.Conformance.Fixtures
  def delete!(%User{username: name}) do
    :ets.delete(@users, name)
    :ok
  end

  @doc "Changes a user's fields (`:roles`, `:must_change_password`), as an admin would."
  def update_user!(%User{username: name}, changes) do
    [{^name, user, hash}] = :ets.lookup(@users, name)
    :ets.insert(@users, {name, struct!(user, changes), hash})
    :ok
  end

  @impl Macaw.Auth.Conformance.Fixtures
  def enroll_second_factor!(%User{username: name, id: id}) do
    secret = NimbleTOTP.secret()
    # Confirmed with the previous step's code, so the current one is unspent.
    :ets.insert(@factors, {id, secret, step(System.os_time(:second)) - 1})
    [{^name, user, hash}] = :ets.lookup(@users, name)
    :ets.insert(@users, {name, %{user | second_factor: :enrolled}, hash})
    fn -> NimbleTOTP.verification_code(secret) end
  end

  defp step(seconds), do: div(seconds, 30)

  @impl Macaw.Auth.Conformance.Fixtures
  def idle_seconds, do: @idle

  @doc """
  Moves session `id`'s last use `seconds` into the past, as if it had sat
  unused that long: a request on the real clock then finds a touch due.
  """
  def age_session!(id, seconds) do
    {h, s} = Enum.find(:ets.tab2list(@sessions), fn {_, s} -> s.id == id end)
    :ets.insert(@sessions, {h, %{s | last_used_at: DateTime.add(s.last_used_at, -seconds)}})
    :ok
  end

  @impl Macaw.Auth.Conformance.Fixtures
  def stored_session_values,
    do: for({hash, _session} <- :ets.tab2list(@sessions), do: hash)

  # ── Backend ───────────────────────────────────────────────────────────

  @impl Macaw.Auth.Backend
  def authenticate(%{username: name, password: password}, _opts) do
    given = :crypto.hash(:sha256, password)

    case :ets.lookup(@users, name) do
      [{_, user, hash}] ->
        # A disabled user is told so only with the right password, so
        # disabled accounts can't be probed (spec 01 §2.1).
        cond do
          not Plug.Crypto.secure_compare(hash, given) -> {:error, :invalid_credentials}
          user.disabled -> {:error, :disabled}
          true -> {:ok, user}
        end

      [] ->
        # The same work as a wrong password, so an unknown user takes the same time.
        Plug.Crypto.secure_compare(given, :crypto.hash(:sha256, "no such user"))
        {:error, :invalid_credentials}
    end
  end

  # A user deleted since signing in gets no session.
  @impl Macaw.Auth.Backend
  def create_session(%User{} = user, opts) do
    case user_by_id(user.id) do
      nil -> {:error, :invalid}
      _user -> start_session(user, opts)
    end
  end

  defp start_session(user, opts) do
    token = :crypto.strong_rand_bytes(32)
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)

    session = %Session{
      id: System.unique_integer([:positive, :monotonic]),
      user_id: user.id,
      created_at: now,
      last_used_at: now,
      remote_ip: Keyword.get(opts, :remote_ip),
      user_agent: Keyword.get(opts, :user_agent),
      second_factor_passed: Keyword.get(opts, :second_factor_passed, true)
    }

    :ets.insert(@sessions, {:crypto.hash(:sha256, token), session})
    {:ok, token, session}
  end

  @impl Macaw.Auth.Backend
  def fetch_session(token, opts) do
    case :ets.lookup(@sessions, :crypto.hash(:sha256, token)) do
      [{hash, session}] -> validate(hash, session, opts)
      [] -> {:error, :invalid}
    end
  end

  @impl Macaw.Auth.Backend
  def fetch_session_by_id(id, opts) do
    case Enum.find(:ets.tab2list(@sessions), fn {_, s} -> s.id == id end) do
      {hash, session} -> validate(hash, session, opts)
      nil -> {:error, :invalid}
    end
  end

  defp validate(hash, session, opts) do
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)
    user = user_by_id(session.user_id)
    idle = DateTime.diff(now, session.last_used_at)

    cond do
      user == nil or user.disabled ->
        :ets.delete(@sessions, hash)
        {:error, :disabled}

      idle > @idle ->
        :ets.delete(@sessions, hash)
        {:error, :expired}

      Keyword.get(opts, :touch, false) and idle >= @touch_every ->
        session = %{session | last_used_at: now}
        :ets.insert(@sessions, {hash, session})
        {:ok, user, session}

      true ->
        {:ok, user, session}
    end
  end

  @impl Macaw.Auth.Backend
  def session_idle_seconds(_opts), do: @idle

  # Nothing to check: its users, sessions and idle limit are its own.
  @impl Macaw.Auth.Backend
  def check_config!, do: :ok

  @impl Macaw.Auth.Backend
  def list_sessions(user_id, _opts) do
    for({_, s} <- :ets.tab2list(@sessions), s.user_id == user_id, do: s)
    |> Enum.sort_by(& &1.id, :desc)
  end

  @impl Macaw.Auth.Backend
  def revoke_sessions({:user, user_id}, opts) do
    except = Keyword.get(opts, :except)

    gone =
      for {h, s} <- :ets.tab2list(@sessions), s.user_id == user_id, s.id != except, do: {h, s.id}

    Enum.each(gone, fn {h, _} -> :ets.delete(@sessions, h) end)
    {user_id, Enum.map(gone, &elem(&1, 1))}
  end

  def revoke_sessions(id, _opts) do
    case Enum.find(:ets.tab2list(@sessions), fn {_, s} -> s.id == id end) do
      {h, s} ->
        :ets.delete(@sessions, h)
        {s.user_id, [id]}

      nil ->
        {nil, []}
    end
  end

  @impl Macaw.Auth.Backend
  def complete_step(id, step, _opts) do
    case Enum.find(:ets.tab2list(@sessions), fn {_, s} -> s.id == id end) do
      {h, s} ->
        :ets.insert(@sessions, {h, with_step(s, step)})
        :ok

      nil ->
        {:error, :invalid}
    end
  end

  defp with_step(s, step) when step in [:second_factor, :second_factor_enroll],
    do: %{s | second_factor_passed: true}

  defp with_step(s, step), do: %{s | completed_steps: Enum.uniq([step | s.completed_steps])}

  @impl Macaw.Auth.Backend
  def verify_second_factor(session_id, code, opts) do
    with {:ok, user, _session} <- fetch_session_by_id(session_id, touch: false),
         [{_, secret, last}] <- :ets.lookup(@factors, user.id),
         {:ok, step} <- matching_step(secret, code, opts, last),
         1 <-
           :ets.select_replace(@factors, [
             {{user.id, secret, :"$1"}, [{:<, :"$1", step}], [{{user.id, secret, step}}]}
           ]) do
      complete_step(session_id, :second_factor, opts)
    else
      {:error, reason} when reason in [:invalid, :expired, :disabled] -> {:error, reason}
      _ -> {:error, :invalid_code}
    end
  end

  defp matching_step(secret, code, opts, last) when is_binary(code) do
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0) |> DateTime.to_unix()

    Enum.find_value([-1, 0, 1], :error, fn offset ->
      step = step(now) + offset

      if step > last and
           Plug.Crypto.secure_compare(NimbleTOTP.verification_code(secret, time: step * 30), code),
         do: {:ok, step}
    end)
  end

  defp matching_step(_secret, _code, _opts, _last), do: :error

  defp user_by_id(id) do
    Enum.find_value(:ets.tab2list(@users), fn {_, u, _} -> if u.id == id, do: u end)
  end
end
