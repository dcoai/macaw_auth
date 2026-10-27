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
  client only. Options: `:remote_ip` (a string or an address tuple),
  `:user_agent`, `:second_factor_passed` (default true), `:now`.
  """
  @spec create(User.t(), keyword()) :: {:ok, binary(), Session.t()}
  def create(%User{} = user, opts) do
    %Config{repo: repo} = Config.get()
    now = now(opts)
    token = :crypto.strong_rand_bytes(32)

    record =
      repo.insert!(%SessionRecord{
        user_id: user.id,
        token_hash: hash(token),
        remote_ip: ip(Keyword.get(opts, :remote_ip)),
        user_agent: truncate(Keyword.get(opts, :user_agent)),
        second_factor_passed: Keyword.get(opts, :second_factor_passed, true),
        completed_steps: [],
        last_used_at: now,
        inserted_at: now,
        updated_at: now
      })

    event(:created, nil, user.id)
    {:ok, token, to_session(record)}
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
            {1, _} =
              repo.update_all(where(SessionRecord, id: ^record.id),
                set: [last_used_at: now, updated_at: now]
              )

            {:ok, Native.to_user(user), to_session(%{record | last_used_at: now})}

          true ->
            {:ok, Native.to_user(user), to_session(record)}
        end
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
  Records a completed step: `:second_factor` and `:second_factor_enroll`
  mark the second factor passed; any other step joins `completed_steps`.
  A session gone meanwhile is left gone (`:ok`): the caller's next look-up
  finds it so.
  """
  @spec complete_step(term(), Auth.step(), keyword()) :: :ok
  def complete_step(id, step, opts) when step in [:second_factor, :second_factor_enroll] do
    %Config{repo: repo} = Config.get()

    with {:ok, id} <- Ecto.UUID.cast(id) do
      repo.update_all(where(SessionRecord, id: ^id),
        set: [second_factor_passed: true, updated_at: now(opts)]
      )
    end

    :ok
  end

  def complete_step(id, step, opts) do
    %Config{repo: repo} = Config.get()
    name = Atom.to_string(step)

    with {:ok, id} <- Ecto.UUID.cast(id),
         %SessionRecord{completed_steps: done} = record <- repo.get(SessionRecord, id),
         false <- name in done do
      record
      |> Ecto.Changeset.change(completed_steps: done ++ [name], updated_at: now(opts))
      |> repo.update!()
    end

    :ok
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
