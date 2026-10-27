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

  The second factor's page calls `verify_second_factor/2` with the
  submitted code; enrollment's page, after the backend confirms it,
  `complete_step(conn, :second_factor_enroll)`.

  Run `Macaw.Plug.ClientIp` before these, so a session records, and the
  throttle counts, the client's address, not a proxy's. Run `fetch_flash`
  before `require_role/2`, or its refusal goes home without saying why.

  **Remembering a browser.** `log_in(conn, user, remember: true)` (a
  "remember me" box) also sets a signed cookie holding the session's token
  (`remember_cookie/0`, `config :macaw_auth, remember_cookie:`), which
  `fetch_current_user/2` reads when the session has none, after the
  browser closed. It lives for the backend's idle limit, set again each
  time the backend records the session's use, is `http_only`
  and `same_site: "Lax"`, and is `secure` exactly when the request is
  https; no setting turns that off. It dies with its session: a revoked
  or expired session's token no longer resolves, and `log_out/1` deletes
  it. Behind a TLS-terminating proxy, make the request's scheme the
  client's (`Plug.RewriteOn` with `:x_forwarded_proto`), or the cookie goes
  out without `secure`. The session cookie is the host's (its endpoint's
  `Plug.Session` options); set `secure: true` there for an https site, as
  this cookie does by itself.

  **LiveView sockets.** `log_in/3` puts the session's `live_socket_id`
  (`Macaw.Auth.live_socket_id/1`) in the session, so Phoenix names the
  session's LiveView sockets by it. With `config :macaw_auth, endpoint:
  MyAppWeb.Endpoint`, every revocation (`Macaw.Auth.revoke/2`, `log_out/1`)
  broadcasts `"disconnect"` on it and Phoenix drops those sockets; without
  `:endpoint` the hooks' own guard (`Macaw.Auth.Live`) takes the pages away.

  Redirects are `Phoenix.Controller.redirect/2`'s, behind this module's own
  check that the target is a path on this site (`site_path?/1`). A
  remembered path came from a request, and Phoenix raises on one that
  isn't safe, so anything else goes home instead: it neither leaves the
  site nor fails the request.
  """

  import Plug.Conn

  alias Macaw.Auth

  @token_key "macaw_auth_token"
  @remember_cookie "_macaw_auth_remember"
  @return_key "macaw_auth_return_to"

  @doc """
  Assigns the signed-in user, session and pending step, or nils.

  The token is the session's; only when the session has none is it read
  from the remember cookie, and then, if it resolves, put back into the
  session (renewed, with the session's `live_socket_id`) and the cookie
  re-issued for another idle limit. A refused token is deleted from the
  session, and a refused remembered one from the cookie too.

  When the backend records the session's use on this request (its touch,
  at most its interval), a remember cookie the browser sent for this
  session is set again too, for a fresh idle limit: a browser kept open
  past the idle limit keeps its cookie as long as its session lives. A
  browser that sent none never gets one here.
  """
  def fetch_current_user(conn, _opts) do
    {conn, token, source} = token(conn)
    now = DateTime.utc_now()

    case {Auth.fetch(token, touch: true, now: now), source} do
      {{:ok, user, session}, :session} ->
        conn
        |> refresh_remember_cookie(token, touched?(session, now))
        |> signed_in(user, session)

      {{:ok, user, session}, :cookie} ->
        conn
        |> configure_session(renew: true)
        |> put_session(@token_key, token)
        |> put_session(:live_socket_id, Auth.live_socket_id(session.id))
        |> put_remember_cookie(token)
        |> signed_in(user, session)

      {{:error, _}, :cookie} ->
        conn |> delete_remember_cookie() |> signed_out()

      {{:error, _}, _none_or_session} ->
        conn |> delete_session(@token_key) |> signed_out()
    end
  end

  defp token(conn) do
    case get_session(conn, @token_key) do
      nil ->
        conn = fetch_cookies(conn, signed: [remember_cookie()])

        case conn.cookies[remember_cookie()] do
          token when is_binary(token) -> {conn, token, :cookie}
          _ -> {conn, nil, :none}
        end

      token ->
        {conn, token, :session}
    end
  end

  # The backend touched the session on this request: its last use is the
  # clock this request gave it (every backend honors `:now`).
  defp touched?(%{last_used_at: %DateTime{} = used}, now), do: DateTime.compare(used, now) == :eq
  defp touched?(_session, _now), do: false

  # Only a browser that opted in, and only for this session's own token.
  defp refresh_remember_cookie(conn, token, true = _touched) do
    conn = fetch_cookies(conn, signed: [remember_cookie()])

    if conn.cookies[remember_cookie()] == token,
      do: put_remember_cookie(conn, token),
      else: conn
  end

  defp refresh_remember_cookie(conn, _token, false), do: conn

  defp signed_in(conn, user, session) do
    conn
    |> assign(:current_user, user)
    |> assign(:current_session, session)
    |> assign(:pending_step, Auth.pending_step(user, session))
  end

  defp signed_out(conn) do
    conn
    |> assign(:current_user, nil)
    |> assign(:current_session, nil)
    |> assign(:pending_step, nil)
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
  old session is renewed (no fixation), the token stored with the
  session's `live_socket_id` (`Macaw.Auth.live_socket_id/1`), and the
  browser sent to the step the session owes, else where it was going,
  else home.

  `remember: true` also sets the remember cookie (`remember_cookie/0`):
  signed, holding the token, for the backend's idle limit
  (`Macaw.Auth.session_idle_seconds/1`), `http_only`, `same_site: "Lax"`,
  and `secure` exactly when the request is https. Without it, a remember
  cookie the browser sent is deleted. Other `opts` go to
  `Macaw.Auth.create_session/2`.
  """
  def log_in(conn, user, opts \\ []) do
    {remember, opts} = Keyword.pop(opts, :remember, false)

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
    |> put_session(:live_socket_id, Auth.live_socket_id(session.id))
    |> then(&if(return_to, do: put_session(&1, @return_key, return_to), else: &1))
    |> remember(remember, token)
    |> signed_in(user, session)
    |> continue()
  end

  defp remember(conn, true, token), do: put_remember_cookie(conn, token)
  defp remember(conn, false, _token), do: forget(conn)

  # Deletes the remember cookie only when the browser sent one.
  defp forget(conn) do
    conn = fetch_cookies(conn)

    if Map.has_key?(conn.req_cookies, remember_cookie()),
      do: delete_remember_cookie(conn),
      else: conn
  end

  defp put_remember_cookie(conn, token) do
    put_resp_cookie(conn, remember_cookie(), token,
      sign: true,
      max_age: Auth.session_idle_seconds(),
      http_only: true,
      same_site: "Lax",
      secure: conn.scheme == :https
    )
  end

  defp delete_remember_cookie(conn) do
    delete_resp_cookie(conn, remember_cookie(),
      sign: true,
      http_only: true,
      same_site: "Lax",
      secure: conn.scheme == :https
    )
  end

  @doc """
  The remember cookie's name: `config :macaw_auth, remember_cookie:`,
  default `"_macaw_auth_remember"`.
  """
  @spec remember_cookie() :: String.t()
  def remember_cookie, do: Application.get_env(:macaw_auth, :remember_cookie, @remember_cookie)

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

  @doc """
  Checks a second-factor code for the current session, passing the
  client's address for the backend's throttle. On success the
  `:second_factor` step is complete and the browser goes on, to the next
  step or where it was going: `{:ok, conn}` (redirected, halted). On a
  refusal the conn stays for the app's page to render the reason:
  `{:error, reason, conn}` (`:invalid_code`, `:throttled`, or the
  session's own refusal), and with no current session
  `{:error, :invalid, conn}`.

      def create(conn, %{"code" => code}) do
        case Macaw.Auth.Plug.verify_second_factor(conn, code) do
          {:ok, conn} -> conn
          {:error, reason, conn} -> render(conn, :new, error: reason)
        end
      end
  """
  @spec verify_second_factor(Plug.Conn.t(), term()) ::
          {:ok, Plug.Conn.t()} | {:error, atom(), Plug.Conn.t()}
  def verify_second_factor(conn, code) do
    case conn.assigns[:current_session] do
      nil ->
        {:error, :invalid, conn}

      session ->
        case Auth.verify_second_factor(session.id, code, remote_ip: client_ip(conn)) do
          :ok -> {:ok, complete_step(conn, :second_factor)}
          {:error, reason} -> {:error, reason, conn}
        end
    end
  end

  @doc """
  Revokes the session (telling its open pages, and with `:endpoint`
  disconnecting its LiveView sockets), renews the session, deletes the
  remember cookie, and goes to sign in.
  """
  def log_out(conn) do
    if session = conn.assigns[:current_session], do: Auth.revoke(session.id)

    conn
    |> configure_session(renew: true)
    |> clear_session()
    |> forget()
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
