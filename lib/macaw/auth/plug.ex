defmodule Macaw.Auth.Plug do
  @moduledoc """
  The request side of `Macaw.Auth`: plain Plug, no Phoenix needed.

      import Macaw.Auth.Plug

      pipeline :browser do
        plug :fetch_session
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

  Run `Macaw.Plug.ClientIp` before these, so a session records the client's
  address, not a proxy's.
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
  Refuses (`403`) a user with none of `roles`. What a role allows is the
  app's to decide; this only checks membership.
  """
  def require_role(conn, roles) when is_list(roles) do
    user = conn.assigns[:current_user]

    if user && Enum.any?(user.roles, &(&1 in roles)),
      do: conn,
      else: conn |> send_resp(403, "Forbidden\n") |> halt()
  end

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
            remote_ip: conn.remote_ip |> :inet.ntoa() |> to_string(),
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
  # another host: anything but a plain site path goes home instead.
  defp redirect(conn, to) do
    to = if site_path?(to), do: to, else: Auth.path(:home)
    conn |> put_resp_header("location", to) |> send_resp(302, "") |> halt()
  end

  @doc false
  def site_path?("/" <> rest), do: not String.starts_with?(rest, ["/", "\\"])
  def site_path?(_), do: false
end
