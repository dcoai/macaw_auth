defmodule Macaw.Auth.Plug do
  @moduledoc """
  The request side of `Macaw.Auth`, for a Phoenix router.

      import Macaw.Auth.Plug

      pipeline :browser do
        plug :fetch_session
        plug :fetch_flash
        plug Macaw.Plug.ClientIp, trusted_proxies: [...]
        plug :fetch_current_user
      end

      pipeline :signed_in do
        plug :require_authenticated
      end

  `fetch_current_user/2` assigns `:current_user`, `:current_session` and
  `:pending_step` (all nil when signed out). `require_authenticated/2` sends
  a signed-out visitor to the sign-in page (remembering where a `GET` was
  going) and a session that owes a step to that step's page; only the
  step's page and sign-out are reachable meanwhile.

  Run `Macaw.Plug.ClientIp` before these, so a session records, and the
  throttle counts, the client's address, not a proxy's. Run `fetch_flash`
  before `require_role/2`, or its refusal goes home without saying why.

  Redirects are `Phoenix.Controller.redirect/2`'s, behind this module's own
  check that the target is a path on this site (`site_path?/1`). A
  remembered path came from a request, and Phoenix raises on one that
  isn't safe, so anything else goes home instead: it neither leaves the
  site nor fails the request.
  """

  import Plug.Conn

  alias Macaw.Auth

  @token_key "macaw_auth_token"
  @return_key "macaw_auth_return_to"

  @doc "Assigns the signed-in user, session and pending step, or nils."
  def fetch_current_user(conn, _opts) do
    case Auth.fetch(get_session(conn, @token_key), touch: true) do
      {:ok, user, session} ->
        conn
        |> assign(:current_user, user)
        |> assign(:current_session, session)
        |> assign(:pending_step, Auth.pending_step(user, session))

      {:error, _} ->
        conn
        |> delete_session(@token_key)
        |> assign(:current_user, nil)
        |> assign(:current_session, nil)
        |> assign(:pending_step, nil)
    end
  end

  @doc """
  Sends a signed-out visitor to sign in, and a session owing a step to that
  step's page.
  """
  def require_authenticated(conn, _opts) do
    case {conn.assigns[:current_user], conn.assigns[:pending_step]} do
      {nil, _} ->
        conn |> remember_return() |> redirect(Auth.path(:sign_in))

      {_user, nil} ->
        conn

      {_user, step} ->
        if conn.request_path in Auth.allowed_paths(step),
          do: conn,
          else: redirect(conn, Auth.path(step))
    end
  end

  @doc """
  Sends a user with none of `roles` home, with an error flash when the
  pipeline ran `fetch_flash` (without it, home with no message). What a
  role allows is the app's to decide; this only checks membership.
  """
  def require_role(conn, roles) when is_list(roles) do
    user = conn.assigns[:current_user]

    if user && Enum.any?(user.roles, &(&1 in roles)),
      do: conn,
      else:
        conn
        |> flash(:error, "You are not allowed to do that.")
        |> redirect(Auth.path(:home))
  end

  defp flash(%Plug.Conn{assigns: %{flash: _}} = conn, kind, message),
    do: Phoenix.Controller.put_flash(conn, kind, message)

  defp flash(conn, _kind, _message), do: conn

  @doc """
  Checks credentials as `Macaw.Auth.authenticate/2` does, passing the
  client's address (`conn.remote_ip`, the client's after
  `Macaw.Plug.ClientIp`) as `:remote_ip`, for the backend's throttle.
  """
  def authenticate(conn, credentials, opts \\ []),
    do: Auth.authenticate(credentials, Keyword.put_new(opts, :remote_ip, client_ip(conn)))

  defp client_ip(conn), do: conn.remote_ip |> :inet.ntoa() |> to_string()

  @doc "Sends a signed-in visitor away from the sign-in page."
  def redirect_if_signed_in(conn, _opts) do
    if conn.assigns[:current_user], do: redirect(conn, Auth.path(:home)), else: conn
  end

  @doc """
  Starts a session for a user who passed `Macaw.Auth.authenticate/2`: the
  old session is renewed (no fixation), the token stored, and the browser
  sent to the step the session owes, else where it was going, else home.
  """
  def log_in(conn, user, opts \\ []) do
    {:ok, token, session} =
      Auth.create_session(
        user,
        Keyword.merge(
          [
            remote_ip: client_ip(conn),
            user_agent: conn |> get_req_header("user-agent") |> List.first()
          ],
          opts
        )
      )

    return_to = get_session(conn, @return_key)

    conn
    |> configure_session(renew: true)
    |> clear_session()
    |> put_session(@token_key, token)
    |> then(&if(return_to, do: put_session(&1, @return_key, return_to), else: &1))
    |> assign(:current_user, user)
    |> assign(:current_session, session)
    |> assign(:pending_step, Auth.pending_step(user, session))
    |> continue()
  end

  @doc """
  Records a step the current session completed and sends it on: to the next
  step, else where it was going.
  """
  def complete_step(conn, step) do
    :ok = Auth.complete_step(conn.assigns.current_session.id, step)

    case Auth.fetch_by_id(conn.assigns.current_session.id) do
      {:ok, user, session} ->
        conn
        |> assign(:current_user, user)
        |> assign(:current_session, session)
        |> assign(:pending_step, Auth.pending_step(user, session))
        |> continue()

      {:error, _} ->
        log_out(conn)
    end
  end

  @doc "Revokes the session (telling its open pages), renews the cookie, and goes to sign in."
  def log_out(conn) do
    if session = conn.assigns[:current_session], do: Auth.revoke(session.id)

    conn
    |> configure_session(renew: true)
    |> clear_session()
    |> redirect(Auth.path(:sign_in))
  end

  @doc "Sends the browser to the session's next step, or where it was going."
  def continue(conn) do
    case conn.assigns[:pending_step] do
      nil ->
        to = get_session(conn, @return_key) || Auth.path(:home)
        conn |> delete_session(@return_key) |> redirect(to)

      step ->
        redirect(conn, Auth.path(step))
    end
  end

  @doc "The session key holding the token, for hosts that need it (LiveView's session)."
  def token_key, do: @token_key

  defp remember_return(%Plug.Conn{method: "GET"} = conn) do
    path =
      if conn.query_string == "",
        do: conn.request_path,
        else: conn.request_path <> "?" <> conn.query_string

    put_session(conn, @return_key, path)
  end

  defp remember_return(conn), do: conn

  # Only paths on this site. A remembered path came from a request, so it
  # could be "//evil.example/x" or "/\\evil.example", which browsers treat as
  # another host: anything but a plain site path goes home instead. The
  # check comes first because Phoenix raises on such a path, which would
  # fail the request rather than send it home.
  defp redirect(conn, to) do
    to = if site_path?(to), do: to, else: Auth.path(:home)
    conn |> Phoenix.Controller.redirect(to: to) |> halt()
  end

  # What Phoenix's redirect refuses besides a leading "//": a backslash
  # (another host, to some browsers), and a tab or line break.
  @unsafe ["\\", "/%09", "/\t", "\n", "\r"]

  @doc """
  Whether `path` is a path on this site that `Phoenix.Controller.redirect/2`
  accepts: one leading slash, then none of a backslash, a tab or a line
  break.
  """
  def site_path?("/" <> rest = path),
    do: not String.starts_with?(rest, "/") and not String.contains?(path, @unsafe)

  def site_path?(_), do: false
end
