defmodule Macaw.Auth.Native.Sessions do
  @moduledoc """
  The native backend's sessions (ported from exio's `Accounts.Sessions`),
  in `macaw_auth_sessions` (`Macaw.Auth.Native.SessionRecord`).

  - **Only a hash is stored.** A session's token is 32 random bytes; the
    client holds it and the table holds its SHA-256. The token is never
    written, so reading the table (a backup, a leaked dump) signs nobody in,
    and since the token is uniformly random, a plain unsalted hash is as
    strong as the token: there is nothing to guess.
  - **Idle expiry slides.** A session unused for `session_idle_days`
    (`Macaw.Auth.Native.Config`, default 14) expires and is deleted at its
    next look-up. A request (`touch: true`) records use, but writes
    `last_used_at` at most once an hour: a write per request would make
    every page view a database write, which SQLite's single writer feels.
    A re-check (`touch: false`, an open page's periodic look) never
    extends a session, or an idle browser tab would keep it alive forever.
  - **A disabled user has no session.** Looking one up deletes it and
    refuses it, so disabling a user takes effect at their next request,
    and their open pages leave at their next re-check.
  - **Revocation only deletes.** `revoke/2` returns `{user_id, ids}`; the
    push to open pages is the facade's (`Macaw.Auth.revoke/2`), the same
    for every backend.

  Every function honors `:now` (a `DateTime`). Telemetry
  `[:macaw_auth, :native, :session]`: `%{count: n}` with `%{event:
  :created | :expired | :revoked, reason: atom | nil, user_id: id}`;
  never a token or its hash.
  """

  import Ecto.Query

  alias Macaw.Auth
  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Config, SessionRecord, UserRecord}
  alias Macaw.Auth.{Session, User}

  @touch_every 3_600
  @user_agent_max 255

  @doc """
  Starts a session for `user`: `{:ok, token, session}`, the token for the
  client only, or `{:error, :invalid}` when the user no longer exists
  (deleted since signing in). Options: `:remote_ip` (a string or an
  address tuple), `:user_agent`, `:second_factor_passed` (default true),
  `:now`.
  """
  @spec create(User.t(), keyword()) :: {:ok, binary(), Session.t()} | {:error, :invalid}
  def create(%User{} = user, opts) do
    %Config{repo: repo} = Config.get()
    now = now(opts)
    token = :crypto.strong_rand_bytes(32)

    with {:ok, user_id} <- Ecto.UUID.cast(user.id),
         record = %SessionRecord{
           id: Ecto.UUID.generate(),
           user_id: user_id,
           token_hash: hash(token),
           remote_ip: ip(Keyword.get(opts, :remote_ip)),
           user_agent: truncate(Keyword.get(opts, :user_agent)),
           second_factor_passed: Keyword.get(opts, :second_factor_passed, true),
           completed_steps: [],
           last_used_at: now,
           inserted_at: now,
           updated_at: now
         },
         {1, _} <- repo.insert_all(SessionRecord, from_user(record)) do
      event(:created, nil, user_id)
      {:ok, token, to_session(record)}
    else
      _no_user -> {:error, :invalid}
    end
  end

  # The row, selected from its user's: one statement inserts it only while
  # the user exists, so a user deleted since signing in gets no session
  # (nor a foreign-key error), and no gap is left between a check and the
  # insert.
  defp from_user(%SessionRecord{} = r) do
    from(u in UserRecord,
      where: u.id == ^r.user_id,
      select: %{
        id: type(^r.id, :binary_id),
        user_id: u.id,
        token_hash: type(^r.token_hash, :binary),
        remote_ip: type(^r.remote_ip, :string),
        user_agent: type(^r.user_agent, :string),
        second_factor_passed: type(^r.second_factor_passed, :boolean),
        completed_steps: type(^r.completed_steps, {:array, :string}),
        last_used_at: type(^r.last_used_at, :utc_datetime_usec),
        inserted_at: type(^r.inserted_at, :utc_datetime_usec),
        updated_at: type(^r.updated_at, :utc_datetime_usec)
      }
    )
  end

  defp ip(nil), do: nil
  defp ip(ip) when is_binary(ip), do: ip
  defp ip(ip) when is_tuple(ip), do: ip |> :inet.ntoa() |> to_string()

  defp truncate(agent) when is_binary(agent), do: String.slice(agent, 0, @user_agent_max)
  defp truncate(_), do: nil

  @doc """
  Resolves a token: `{:ok, user, session}` or `{:error, :invalid |
  :expired | :disabled}`. Options: `:touch` (default false), `:now`.
  """
  @spec fetch(binary(), keyword()) ::
          {:ok, User.t(), Session.t()} | {:error, :invalid | :expired | :disabled}
  def fetch(token, opts) when is_binary(token) do
    %Config{repo: repo} = config = Config.get()
    validate(config, repo.get_by(SessionRecord, token_hash: hash(token)), opts)
  end

  def fetch(_token, _opts), do: {:error, :invalid}

  @doc "As `fetch/2`, by session id: what an open page re-checks with."
  @spec fetch_by_id(term(), keyword()) ::
          {:ok, User.t(), Session.t()} | {:error, :invalid | :expired | :disabled}
  def fetch_by_id(id, opts) do
    %Config{repo: repo} = config = Config.get()

    case Ecto.UUID.cast(id) do
      {:ok, id} -> validate(config, repo.get(SessionRecord, id), opts)
      :error -> {:error, :invalid}
    end
  end

  defp validate(_config, nil, _opts), do: {:error, :invalid}

  defp validate(%Config{repo: repo} = config, %SessionRecord{} = record, opts) do
    now = now(opts)
    idle = DateTime.diff(now, record.last_used_at)

    case repo.get(UserRecord, record.user_id) do
      nil ->
        {:error, :invalid}

      %UserRecord{disabled_at: disabled} when disabled != nil ->
        delete(repo, record, :revoked, :disabled)
        {:error, :disabled}

      user ->
        cond do
          idle > config.session_idle_days * 86_400 ->
            delete(repo, record, :expired, :idle)
            {:error, :expired}

          Keyword.get(opts, :touch, false) and idle >= @touch_every ->
            touch(repo, record, user, now)

          true ->
            {:ok, Native.to_user(user), to_session(record)}
        end
    end
  end

  # A row deleted since the look-up (a revocation racing it) updates
  # nothing: the session is revoked, so it is refused as one.
  defp touch(repo, record, user, now) do
    case repo.update_all(where(SessionRecord, id: ^record.id),
           set: [last_used_at: now, updated_at: now]
         ) do
      {1, _} -> {:ok, Native.to_user(user), to_session(%{record | last_used_at: now})}
      {0, _} -> {:error, :invalid}
    end
  end

  # Gone already (a revocation racing this look-up) is as good as deleted.
  defp delete(repo, record, event, reason) do
    case repo.delete_all(where(SessionRecord, id: ^record.id)) do
      {1, _} -> event(event, reason, record.user_id)
      {0, _} -> :ok
    end
  end

  @doc "A user's sessions, newest first (created at, then id: timestamps can tie)."
  @spec list(term(), keyword()) :: [Session.t()]
  def list(user_id, _opts) do
    %Config{repo: repo} = Config.get()

    case Ecto.UUID.cast(user_id) do
      {:ok, user_id} ->
        SessionRecord
        |> where(user_id: ^user_id)
        |> order_by(desc: :inserted_at, desc: :id)
        |> repo.all()
        |> Enum.map(&to_session/1)

      :error ->
        []
    end
  end

  @doc """
  Deletes every session of user `user_id`'s, `reason` going to telemetry,
  and tells their open pages (`Macaw.Auth.announce_revoked/2`), which
  disconnect, unless option `announce: false`: a process that is not the
  app's node (a release's `eval`, a mix task) has no page to tell, and the
  pages leave at their next re-check. What an administrator's change of a
  user (`Macaw.Auth.Native.set_password/3`, `admin_reset/2`) revokes with.
  """
  @spec revoke_all(term(), atom(), keyword()) :: :ok
  def revoke_all(user_id, reason, opts) do
    {user_id, ids} = revoke({:user, user_id}, reason: reason)

    if Keyword.get(opts, :announce, true),
      do: Macaw.Auth.announce_revoked(user_id, ids),
      else: :ok
  end

  @doc """
  Deletes one session (an id) or a user's (`{:user, id}`, keeping
  `:except`): `{user_id, ids}`, the ids empty when nothing was there.
  `:reason` goes to telemetry.
  """
  @spec revoke(term() | {:user, term()}, keyword()) :: {term(), [term()]}
  def revoke({:user, user_id}, opts) do
    %Config{repo: repo} = Config.get()

    with {:ok, uid} <- Ecto.UUID.cast(user_id) do
      query = from(s in SessionRecord, where: s.user_id == ^uid, select: s.id)

      # An `:except` that is no session id keeps nothing.
      query =
        case Ecto.UUID.cast(Keyword.get(opts, :except)) do
          {:ok, except} -> where(query, [s], s.id != ^except)
          :error -> query
        end

      {_n, ids} = repo.delete_all(query)
      revoked(uid, ids, opts)
    else
      :error -> {user_id, []}
    end
  end

  def revoke(id, opts) do
    %Config{repo: repo} = Config.get()

    with {:ok, id} <- Ecto.UUID.cast(id),
         {1, [user_id]} <-
           repo.delete_all(from(s in SessionRecord, where: s.id == ^id, select: s.user_id)) do
      revoked(user_id, [id], opts)
    else
      _nothing -> {nil, []}
    end
  end

  defp revoked(user_id, [], _opts), do: {user_id, []}

  defp revoked(user_id, ids, opts) do
    :telemetry.execute([:macaw_auth, :native, :session], %{count: length(ids)}, %{
      event: :revoked,
      reason: Keyword.get(opts, :reason),
      user_id: user_id
    })

    {user_id, ids}
  end

  @doc """
  Records a completed step: `:second_factor` marks the second factor
  passed; any other step joins `completed_steps`. A session that doesn't
  exist, or was deleted meanwhile (a revocation racing the step), is left
  gone and refused: `{:error, :invalid}`.
  """
  @spec complete_step(term(), Auth.step(), keyword()) :: :ok | {:error, :invalid}
  def complete_step(id, :second_factor, opts) do
    %Config{repo: repo} = Config.get()

    with {:ok, id} <- Ecto.UUID.cast(id),
         {1, _} <-
           repo.update_all(where(SessionRecord, id: ^id),
             set: [second_factor_passed: true, updated_at: now(opts)]
           ) do
      :ok
    else
      _gone -> {:error, :invalid}
    end
  end

  def complete_step(id, step, opts) do
    %Config{repo: repo} = Config.get()
    name = Atom.to_string(step)

    with {:ok, id} <- Ecto.UUID.cast(id),
         %SessionRecord{} = record <- repo.get(SessionRecord, id) do
      add_step(repo, record, name, opts)
    else
      _gone -> {:error, :invalid}
    end
  end

  # A row deleted between the read and this write is stale: with
  # `stale_error_field` that is an error value, not a raise. `updated_at` is
  # forced: a `now` equal to the row's own would otherwise be no change, and
  # Ecto would stamp the system clock in its place, ignoring `:now`.
  defp add_step(repo, %SessionRecord{completed_steps: done} = record, name, opts) do
    if name in done do
      :ok
    else
      record
      |> Ecto.Changeset.change(completed_steps: done ++ [name])
      |> Ecto.Changeset.force_change(:updated_at, now(opts))
      |> repo.update(stale_error_field: :id)
      |> case do
        {:ok, _record} -> :ok
        {:error, _stale} -> {:error, :invalid}
      end
    end
  end

  @doc "A row as the contract's `%Macaw.Auth.Session{}`."
  @spec to_session(SessionRecord.t()) :: Session.t()
  def to_session(%SessionRecord{} = r) do
    %Session{
      id: r.id,
      user_id: r.user_id,
      created_at: r.inserted_at,
      last_used_at: r.last_used_at,
      remote_ip: r.remote_ip,
      user_agent: r.user_agent,
      second_factor_passed: r.second_factor_passed,
      completed_steps: steps(r.completed_steps || [])
    }
  end

  # By lookup among the contract's steps: a stored name that isn't one (a
  # row from a later version) is dropped, never made into an atom.
  defp steps(names),
    do: for(step <- Auth.steps(), Atom.to_string(step) in names, do: step)

  @doc "The SHA-256 of a token: what the table stores."
  @spec hash(binary()) :: binary()
  def hash(token), do: :crypto.hash(:sha256, token)

  # The `:now` option, else the clock, at the microsecond precision the
  # columns hold.
  defp now(opts) do
    %DateTime{microsecond: {us, _}} =
      now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)

    %{now | microsecond: {us, 6}}
  end

  defp event(event, reason, user_id) do
    :telemetry.execute([:macaw_auth, :native, :session], %{count: 1}, %{
      event: event,
      reason: reason,
      user_id: user_id
    })
  end
end
