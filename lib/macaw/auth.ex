defmodule Macaw.Auth do
  @moduledoc """
  Authentication for Phoenix hosts: one contract, with a backend behind it.

  An app configures a backend and its paths:

      config :macaw_auth,
        backend: Macaw.Auth.Native,
        paths: %{sign_in: "/login", sign_out: "/logout", home: "/",
                 second_factor: "/login/totp", second_factor_enroll: "/totp/enroll",
                 password_change: "/password"},
        pubsub: MyApp.PubSub,
        endpoint: MyAppWeb.Endpoint,
        authorizer: MyApp.Authorizer

  and uses the plugs (`Macaw.Auth.Plug`) and LiveView hooks
  (`Macaw.Auth.Live`). Everything here is the same for every backend:

  - **Steps.** A session may owe steps before the app is open to it, in
    order: a second factor (an enrolled user), a password change.
    Meanwhile only that step's page and sign-out are reachable.
  - **Enrollment owed at sign-in has no session.** A user whom policy
    requires to enroll a second factor (`second_factor: :required`) gets
    an enrollment ticket instead (`enrollment_ticket/2`), sealed and short
    lived, that can do nothing but enroll; enrolling from it
    (`enroll_second_factor/3`) gives the enrolled user, for whom a session
    may then start. `create_session/2` refuses such a user.
  - **Revocation reaches open pages.** Every revocation goes through
    `revoke/2`, which tells each open LiveView of the user's sessions, so a
    revoked page disconnects at once. Without `:pubsub` that is this node
    (a `Registry`); with it, every node. With `:endpoint` (the host's
    Phoenix endpoint), it also broadcasts `"disconnect"` on each revoked
    session's `live_socket_id/1`, which `Macaw.Auth.Plug.log_in/3` puts in
    the session, so Phoenix drops those sockets too:

        config :macaw_auth, endpoint: MyAppWeb.Endpoint
  - **The viewer.** `viewer/1` gives a Macaw page the viewer: identity and
    roles, never preferences.
  - **What a user may do is the app's.** `authorize/3` asks the app's
    `Macaw.Auth.Authorizer`; with none configured, nothing is allowed.
  """

  alias Macaw.Auth.{Session, User}

  @type step :: :second_factor | :password_change

  @steps [:second_factor, :password_change]

  @default_paths %{
    sign_in: "/login",
    sign_out: "/logout",
    home: "/",
    second_factor: "/login/second-factor",
    second_factor_enroll: "/second-factor/enroll",
    password_change: "/password"
  }

  @known_paths @default_paths |> Map.keys() |> Enum.sort() |> Enum.map_join(", ", &inspect/1)

  @doc "The configured backend module."
  @spec backend() :: module()
  def backend, do: Application.fetch_env!(:macaw_auth, :backend)

  @doc """
  A configured path (`:sign_in`, `:home`, a step), else its default. A
  name neither configured nor one of the defaults raises `ArgumentError`
  naming it.
  """
  @spec path(atom()) :: String.t()
  def path(name) do
    paths = Application.get_env(:macaw_auth, :paths, %{})

    case Map.get(paths, name) || Map.get(@default_paths, name) do
      nil ->
        raise ArgumentError,
              "unknown path #{inspect(name)}: neither configured (config :macaw_auth, paths:) " <>
                "nor one of #{@known_paths}"

      path ->
        path
    end
  end

  @doc "The steps, in the order a session owes them."
  @spec steps() :: [step()]
  def steps, do: @steps

  @doc """
  The step a session owes before the app, or nil: a second factor (a user
  with one, who hasn't passed it this session), then a password change.

  A session's user owing enrollment (`:required`) owes the second factor
  too, which no code passes: no session is started for such a user
  (`create_session/2`), so one can only be a session from before policy
  required it, and it leads nowhere but sign-out. Signing in again gives
  the enrollment ticket.
  """
  @spec pending_step(User.t(), Session.t()) :: step() | nil
  def pending_step(%User{} = user, %Session{} = session) do
    cond do
      not session.second_factor_passed and user.second_factor != :none ->
        :second_factor

      user.must_change_password and :password_change not in session.completed_steps ->
        :password_change

      true ->
        nil
    end
  end

  @doc "The paths reachable while a session owes `step`."
  @spec allowed_paths(step()) :: [String.t()]
  def allowed_paths(step), do: [path(step), path(:sign_out)]

  @doc "Checks credentials through the backend."
  @spec authenticate(map(), keyword()) :: {:ok, User.t()} | {:error, term()}
  def authenticate(credentials, opts \\ []), do: backend().authenticate(credentials, opts)

  @doc """
  Starts a session. The second factor counts as passed unless the user has
  one enrolled, which the session then owes. `{:error, :invalid}` when the
  backend refuses it (the user no longer exists).

  A user who owes enrollment (`second_factor: :required`) gets no session,
  whatever the options say: `{:error, :enrollment_required}`, without
  asking the backend. They get an enrollment ticket instead
  (`enrollment_ticket/2`).
  """
  @spec create_session(User.t(), keyword()) ::
          {:ok, binary(), Session.t()} | {:error, :invalid | :enrollment_required}
  def create_session(user, opts \\ [])

  def create_session(%User{second_factor: :required}, _opts), do: {:error, :enrollment_required}

  def create_session(%User{} = user, opts) do
    passed = Keyword.get(opts, :second_factor_passed, user.second_factor == :none)
    backend().create_session(user, Keyword.put(opts, :second_factor_passed, passed))
  end

  @doc """
  The enrollment ticket for a user who owes enrollment
  (`second_factor: :required`), issued in place of a session:
  `{:ok, ticket}`, sealed bytes for the client to hold, or
  `{:error, :invalid}` for a user who doesn't owe one (gone, disabled,
  enrolled, not required). Option `:now`.
  """
  @spec enrollment_ticket(User.t(), keyword()) :: {:ok, binary()} | {:error, atom()}
  def enrollment_ticket(%User{} = user, opts \\ []),
    do: backend().enrollment_ticket(user, opts)

  @doc """
  What the enrollment page shows of a ticket: `{:ok, %{secret, uri}}`, the
  TOTP secret and its `otpauth://` URI (the QR code), or
  `{:error, :invalid_ticket}`. Option `:now`.
  """
  @spec enrollment(term(), keyword()) ::
          {:ok, %{secret: binary(), uri: String.t()}} | {:error, atom()}
  def enrollment(ticket, opts \\ []), do: backend().enrollment(ticket, opts)

  @doc """
  Completes the enrollment a ticket carries with a valid code:
  `{:ok, user, recovery_codes}`, the user now `:enrolled` (a session may
  start for them, its second factor passed) and the codes to show once;
  or `{:error, :invalid_code | :throttled | :invalid_ticket}`. Options:
  `:remote_ip` (for the throttle), `:now`.
  """
  @spec enroll_second_factor(term(), term(), keyword()) ::
          {:ok, User.t(), [String.t()]} | {:error, atom()}
  def enroll_second_factor(ticket, code, opts \\ []),
    do: backend().enroll_second_factor(ticket, code, opts)

  @doc "Resolves a token: `{:ok, user, session}` or `{:error, reason}`."
  @spec fetch(binary() | nil, keyword()) :: {:ok, User.t(), Session.t()} | {:error, atom()}
  def fetch(token, opts \\ [])
  def fetch(token, opts) when is_binary(token), do: backend().fetch_session(token, opts)
  def fetch(_token, _opts), do: {:error, :invalid}

  @doc "Resolves a session by id (an open page's re-check)."
  @spec fetch_by_id(term(), keyword()) :: {:ok, User.t(), Session.t()} | {:error, atom()}
  def fetch_by_id(id, opts \\ []), do: backend().fetch_session_by_id(id, opts)

  @doc """
  How long a session may go unused before the backend expires it, in
  seconds: the remember cookie's `max_age`.
  """
  @spec session_idle_seconds(keyword()) :: pos_integer()
  def session_idle_seconds(opts \\ []), do: backend().session_idle_seconds(opts)

  @doc "A user's sessions, newest first."
  @spec list_sessions(term(), keyword()) :: [Session.t()]
  def list_sessions(user_id, opts \\ []), do: backend().list_sessions(user_id, opts)

  @doc """
  Records a completed step on a session: `:ok`, or `{:error, :invalid}`
  when the session no longer exists (revoked meanwhile).
  """
  @spec complete_step(term(), step(), keyword()) :: :ok | {:error, :invalid}
  def complete_step(session_id, step, opts \\ []) when step in @steps,
    do: backend().complete_step(session_id, step, opts)

  @doc """
  Checks a second-factor code for session `session_id`'s user; on success
  the session's `:second_factor` step is complete. Options: `:remote_ip`
  (for the throttle), `:now`.
  """
  @spec verify_second_factor(term(), term(), keyword()) :: :ok | {:error, atom()}
  def verify_second_factor(session_id, code, opts \\ []),
    do: backend().verify_second_factor(session_id, code, opts)

  @doc """
  Revokes one session (an id) or all of a user's (`{:user, id}`, with
  `:except`), and tells their open pages, which disconnect.
  """
  @spec revoke(term() | {:user, term()}, keyword()) :: :ok
  def revoke(target, opts \\ []) do
    case backend().revoke_sessions(target, opts) do
      {_user_id, []} -> :ok
      {user_id, ids} -> announce_revoked(user_id, ids)
    end
  end

  @doc "Subscribes the caller to revocations of `user_id`'s sessions."
  @spec subscribe(term()) :: :ok
  def subscribe(user_id) do
    case Application.get_env(:macaw_auth, :pubsub) do
      nil ->
        {:ok, _} = Registry.register(Macaw.Auth.Registry, topic(user_id), nil)
        :ok

      pubsub ->
        Phoenix.PubSub.subscribe(pubsub, topic(user_id))
    end
  end

  @doc """
  Tells `user_id`'s open pages that sessions `ids` ended, so they disconnect.

  `revoke/2` calls this after its backend revokes. A backend whose sessions
  can also be revoked outside macaw_auth (an Ash token revoked through Ash,
  say) calls it from that path too, so open pages hear of every revocation,
  whoever made it. Announcing nothing is a no-op.

  With `config :macaw_auth, endpoint: MyAppWeb.Endpoint`, it also
  broadcasts `"disconnect"` on each session's `live_socket_id/1`, so
  Phoenix closes those sessions' LiveView sockets as well. Without
  `:endpoint` that broadcast is skipped; the hooks' guard
  (`Macaw.Auth.Live`) still takes the open pages away.
  """
  @spec announce_revoked(term(), [term()]) :: :ok
  def announce_revoked(_user_id, []), do: :ok

  def announce_revoked(user_id, ids) when is_list(ids) do
    :ok = broadcast(user_id, {:sessions_revoked, ids})
    disconnect_sockets(Application.get_env(:macaw_auth, :endpoint), ids)
  end

  @doc """
  The `live_socket_id` of session `session_id`,
  `"macaw_auth_sessions:<session id>"`: `Macaw.Auth.Plug.log_in/3` puts it
  in the session, so Phoenix names that session's LiveView sockets by it,
  and a revocation broadcasts `"disconnect"` on it (`announce_revoked/2`).
  """
  @spec live_socket_id(term()) :: String.t()
  def live_socket_id(session_id), do: "macaw_auth_sessions:#{session_id}"

  defp disconnect_sockets(nil, _ids), do: :ok

  defp disconnect_sockets(endpoint, ids) do
    Enum.each(ids, &endpoint.broadcast(live_socket_id(&1), "disconnect", %{}))
  end

  defp broadcast(user_id, message) do
    case Application.get_env(:macaw_auth, :pubsub) do
      nil ->
        Registry.dispatch(Macaw.Auth.Registry, topic(user_id), fn entries ->
          for {pid, _} <- entries, do: send(pid, message)
        end)

      pubsub ->
        Phoenix.PubSub.broadcast(pubsub, topic(user_id), message)
    end
  end

  defp topic(user_id), do: "macaw_auth:user_sessions:#{user_id}"

  @doc """
  Whether `user` may do `action` to `resource`: the answer of the app's
  authorizer (`config :macaw_auth, authorizer: MyApp.Authorizer`, a
  `Macaw.Auth.Authorizer`), and `false` when none is configured. An answer
  other than `true` or `false` raises `CaseClauseError`, and whatever the
  authorizer raises goes on up: a fault in the app is never a refusal.
  """
  @spec authorize(User.t(), atom(), term()) :: boolean()
  def authorize(%User{} = user, action, resource) when is_atom(action) do
    case Application.get_env(:macaw_auth, :authorizer) do
      nil ->
        false

      authorizer ->
        case authorizer.authorize(user, action, resource) do
          answer when is_boolean(answer) -> answer
        end
    end
  end

  @doc """
  The viewer for a Macaw page: `%{id, username, roles, source}`, or nil when
  signed out. Identity and access only; display preferences are state,
  never part of the viewer (macaw_compose spec 01 §2).
  """
  @spec viewer(Plug.Conn.t() | map()) :: map() | nil
  def viewer(%{assigns: assigns}), do: viewer(assigns)

  def viewer(%{current_user: %User{} = u}),
    do: %{id: u.id, username: u.username, roles: u.roles, source: u.source}

  def viewer(_), do: nil
end
