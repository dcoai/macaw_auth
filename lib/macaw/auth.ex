defmodule Macaw.Auth do
  @moduledoc """
  Authentication for Phoenix hosts: one contract, with a backend behind it.

  An app configures a backend and its paths:

      config :macaw_auth,
        backend: Macaw.Auth.Native,
        paths: %{sign_in: "/login", sign_out: "/logout", home: "/",
                 second_factor: "/login/totp", second_factor_enroll: "/totp/enroll",
                 password_change: "/password"},
        pubsub: MyApp.PubSub

  and uses the plugs (`Macaw.Auth.Plug`) and LiveView hooks
  (`Macaw.Auth.Live`). Everything here is the same for every backend:

  - **Steps.** A session may owe steps before the app is open to it, in
    order: a second factor (an enrolled user), enrolling one (policy
    requires it), a password change. Meanwhile only that step's page and
    sign-out are reachable.
  - **Revocation reaches open pages.** Every revocation goes through
    `revoke/2`, which tells each open LiveView of the user's sessions, so a
    revoked page disconnects at once. Without `:pubsub` that is this node
    (a `Registry`); with it, every node.
  - **The viewer.** `viewer/1` gives a Macaw page the viewer: identity and
    roles, never preferences.
  """

  alias Macaw.Auth.{Session, User}

  @type step :: :second_factor | :second_factor_enroll | :password_change

  @steps [:second_factor, :second_factor_enroll, :password_change]

  @doc "The configured backend module."
  @spec backend() :: module()
  def backend, do: Application.fetch_env!(:macaw_auth, :backend)

  @doc "A configured path (`:sign_in`, `:home`, a step)."
  @spec path(atom()) :: String.t()
  def path(name) do
    paths = Application.get_env(:macaw_auth, :paths, %{})
    Map.get(paths, name) || default_path(name)
  end

  defp default_path(:sign_in), do: "/login"
  defp default_path(:sign_out), do: "/logout"
  defp default_path(:home), do: "/"
  defp default_path(:second_factor), do: "/login/second-factor"
  defp default_path(:second_factor_enroll), do: "/second-factor/enroll"
  defp default_path(:password_change), do: "/password"

  @doc "The steps, in the order a session owes them."
  @spec steps() :: [step()]
  def steps, do: @steps

  @doc """
  The step a session owes before the app, or nil: a second factor (an
  enrolled user who hasn't passed it this session), enrolling one (policy
  requires it), then a password change.
  """
  @spec pending_step(User.t(), Session.t()) :: step() | nil
  def pending_step(%User{} = user, %Session{} = session) do
    cond do
      not session.second_factor_passed and user.second_factor == :enrolled ->
        :second_factor

      not session.second_factor_passed and user.second_factor == :required ->
        :second_factor_enroll

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
  one enrolled or required, which the session then owes.
  """
  @spec create_session(User.t(), keyword()) :: {:ok, binary(), Session.t()}
  def create_session(%User{} = user, opts \\ []) do
    passed = Keyword.get(opts, :second_factor_passed, user.second_factor == :none)
    backend().create_session(user, Keyword.put(opts, :second_factor_passed, passed))
  end

  @doc "Resolves a token: `{:ok, user, session}` or `{:error, reason}`."
  @spec fetch(binary() | nil, keyword()) :: {:ok, User.t(), Session.t()} | {:error, atom()}
  def fetch(token, opts \\ [])
  def fetch(token, opts) when is_binary(token), do: backend().fetch_session(token, opts)
  def fetch(_token, _opts), do: {:error, :invalid}

  @doc "Resolves a session by id (an open page's re-check)."
  @spec fetch_by_id(term(), keyword()) :: {:ok, User.t(), Session.t()} | {:error, atom()}
  def fetch_by_id(id, opts \\ []), do: backend().fetch_session_by_id(id, opts)

  @doc "A user's sessions, newest first."
  @spec list_sessions(term(), keyword()) :: [Session.t()]
  def list_sessions(user_id, opts \\ []), do: backend().list_sessions(user_id, opts)

  @doc "Records a completed step on a session."
  @spec complete_step(term(), step(), keyword()) :: :ok
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
  """
  @spec announce_revoked(term(), [term()]) :: :ok
  def announce_revoked(_user_id, []), do: :ok

  def announce_revoked(user_id, ids) when is_list(ids),
    do: broadcast(user_id, {:sessions_revoked, ids})

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
  The viewer for a Macaw page: `%{id, username, roles, source}`, or nil when
  signed out. Identity and access only; display preferences are state,
  never part of the viewer (Macaw spec 02 §2).
  """
  @spec viewer(Plug.Conn.t() | map()) :: map() | nil
  def viewer(%{assigns: assigns}), do: viewer(assigns)

  def viewer(%{current_user: %User{} = u}),
    do: %{id: u.id, username: u.username, roles: u.roles, source: u.source}

  def viewer(_), do: nil
end
