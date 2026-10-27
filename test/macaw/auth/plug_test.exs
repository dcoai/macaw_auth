defmodule Macaw.Auth.PlugTest do
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias Macaw.Auth
  alias Macaw.Auth.Plug, as: AuthPlug
  alias Macaw.Auth.Test.MemoryBackend, as: Mem

  setup do
    Application.put_env(:macaw_auth, :backend, Mem)

    Application.put_env(:macaw_auth, :paths, %{
      sign_in: "/login",
      home: "/home",
      second_factor: "/login/totp"
    })

    on_exit(fn -> Application.delete_env(:macaw_auth, :paths) end)
    Mem.reset!()
    :ok
  end

  @secret_key_base String.duplicate("macaw_auth test secret key base ", 2)

  defp request(path, session \\ %{}, method \\ :get) do
    conn(method, path) |> with_secret() |> init_test_session(session) |> fetch()
  end

  defp with_secret(conn), do: %{conn | secret_key_base: @secret_key_base}

  defp fetch(conn), do: AuthPlug.fetch_current_user(conn, [])

  # A later request from the browser that got `previous`: its cookies, a
  # fresh session (the browser closed, say).
  defp next_request(previous, path, session \\ %{}) do
    conn(:get, path)
    |> with_secret()
    |> recycle_cookies(previous)
    |> init_test_session(session)
    |> fetch()
  end

  @remember "_macaw_auth_remember"

  defp signed_in(user, path) do
    {:ok, token, _} = Auth.create_session(user)
    request(path, %{AuthPlug.token_key() => token})
  end

  defp location(conn), do: conn |> get_resp_header("location") |> List.first()

  test "a signed-out visitor is sent to sign in, remembering where a GET was going" do
    conn = request("/reports?year=2026") |> AuthPlug.require_authenticated([])
    assert conn.halted and conn.status == 302
    assert location(conn) == "/login"
    assert get_session(conn, "macaw_auth_return_to") == "/reports?year=2026"
  end

  test "a POST is not remembered" do
    conn = request("/reports", %{}, :post) |> AuthPlug.require_authenticated([])
    assert get_session(conn, "macaw_auth_return_to") == nil
  end

  test "a signed-in user passes, with user, session and no pending step" do
    {user, _} = Mem.user!(%{})
    conn = signed_in(user, "/reports") |> AuthPlug.require_authenticated([])
    refute conn.halted
    assert conn.assigns.current_user.id == user.id
    assert conn.assigns.pending_step == nil
  end

  test "a session owing a second factor reaches only that step and sign-out" do
    {user, _} = Mem.user!(%{second_factor: :enrolled})
    {:ok, token, _} = Auth.create_session(user)
    session = %{AuthPlug.token_key() => token}

    conn = request("/reports", session) |> AuthPlug.require_authenticated([])
    assert location(conn) == "/login/totp"

    for path <- ["/login/totp", "/logout"] do
      refute (request(path, session) |> AuthPlug.require_authenticated([])).halted
    end
  end

  test "require_role checks membership only, else home with an error flash" do
    {admin, _} = Mem.user!(%{roles: ["admin"]})
    {viewer, _} = Mem.user!(%{roles: ["viewer"]})

    refute (signed_in(admin, "/admin") |> AuthPlug.require_role(["admin", "owner"])).halted

    conn =
      signed_in(viewer, "/admin")
      |> Phoenix.Controller.fetch_flash([])
      |> AuthPlug.require_role(["admin"])

    assert conn.halted and conn.status == 302
    assert location(conn) == "/home"
    assert Phoenix.Flash.get(conn.assigns.flash, :error) == "You are not allowed to do that."
  end

  test "require_role without fetch_flash still goes home, without a message" do
    {viewer, _} = Mem.user!(%{roles: ["viewer"]})
    conn = signed_in(viewer, "/admin") |> AuthPlug.require_role(["admin"])
    assert conn.halted and location(conn) == "/home"
    refute Map.has_key?(conn.assigns, :flash)

    signed_out = request("/admin") |> AuthPlug.require_role(["admin"])
    assert signed_out.halted and location(signed_out) == "/home"
  end

  test "authenticate passes the client's address to the backend" do
    {_user, creds} = Mem.user!(%{})
    conn = %{request("/login") | remote_ip: {203, 0, 113, 7}}
    assert {:ok, _} = AuthPlug.authenticate(conn, creds)
  end

  test "log_in renews the session, stores the token, and returns where the visitor was going" do
    {user, _} = Mem.user!(%{})
    conn = request("/login", %{"macaw_auth_return_to" => "/reports"}) |> AuthPlug.log_in(user)

    assert location(conn) == "/reports"
    assert conn.private[:plug_session_info] == :renew
    assert {:ok, _, _} = Auth.fetch(get_session(conn, AuthPlug.token_key()))
  end

  test "log_in sends a session that owes a step to the step" do
    {user, _} = Mem.user!(%{second_factor: :enrolled})
    conn = request("/login") |> AuthPlug.log_in(user)
    assert location(conn) == "/login/totp"
  end

  test "complete_step clears the step and continues" do
    {user, _} = Mem.user!(%{second_factor: :enrolled})
    {:ok, token, _} = Auth.create_session(user)

    conn =
      request("/login/totp", %{AuthPlug.token_key() => token})
      |> AuthPlug.complete_step(:second_factor)

    assert location(conn) == "/home"
    assert conn.assigns.pending_step == nil
  end

  test "complete_step of a session revoked meanwhile logs out" do
    {user, _} = Mem.user!(%{must_change_password: true})
    {:ok, token, session} = Auth.create_session(user)
    conn = request("/password", %{AuthPlug.token_key() => token})
    :ok = Auth.revoke(session.id)

    conn = AuthPlug.complete_step(conn, :password_change)
    assert conn.halted
    assert location(conn) == "/login"
    assert get_session(conn, AuthPlug.token_key()) == nil
  end

  describe "log_in for a user the backend no longer has" do
    test "goes back to sign in with a flash, setting no session or cookie" do
      {user, _} = Mem.user!(%{})
      :ok = Mem.delete!(user)

      conn =
        request("/login", %{"macaw_auth_return_to" => "/reports"})
        |> Phoenix.Controller.fetch_flash([])
        |> AuthPlug.log_in(user, remember: true)

      assert conn.halted
      assert conn.status == 302
      assert location(conn) == "/login"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) == "You could not be signed in."
      assert get_session(conn, AuthPlug.token_key()) == nil
      assert get_session(conn, :live_socket_id) == nil
      refute Map.has_key?(conn.resp_cookies, @remember)
      assert Auth.list_sessions(user.id) == []
    end

    test "without fetch_flash, the same, without a message" do
      {user, _} = Mem.user!(%{})
      :ok = Mem.delete!(user)

      conn = request("/login") |> AuthPlug.log_in(user)
      assert conn.halted
      assert location(conn) == "/login"
      refute Map.has_key?(conn.assigns, :flash)
      assert get_session(conn, AuthPlug.token_key()) == nil
    end
  end

  test "verify_second_factor with a valid code completes the step and goes where it was going" do
    {user, creds} = Mem.user!(%{})
    next_code = Mem.enroll_second_factor!(user)
    {:ok, user} = Auth.authenticate(creds)
    {:ok, token, _} = Auth.create_session(user)

    session = %{AuthPlug.token_key() => token, "macaw_auth_return_to" => "/reports"}
    conn = request("/login/totp", session)
    assert conn.assigns.pending_step == :second_factor

    assert {:ok, conn} = AuthPlug.verify_second_factor(conn, next_code.())
    assert location(conn) == "/reports"
    assert conn.assigns.pending_step == nil
    {:ok, user, session} = Auth.fetch(token)
    assert Auth.pending_step(user, session) == nil
  end

  test "verify_second_factor with a wrong code stays, with the reason" do
    {user, creds} = Mem.user!(%{})
    _next_code = Mem.enroll_second_factor!(user)
    {:ok, user} = Auth.authenticate(creds)
    {:ok, token, _} = Auth.create_session(user)

    conn = request("/login/totp", %{AuthPlug.token_key() => token})
    assert {:error, :invalid_code, conn} = AuthPlug.verify_second_factor(conn, "not a code")
    refute conn.halted
    assert conn.assigns.pending_step == :second_factor

    assert {:error, :invalid, _} = AuthPlug.verify_second_factor(request("/login/totp"), "1")
  end

  test "log_out revokes the session and tells its open pages" do
    {user, _} = Mem.user!(%{})
    {:ok, token, session} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)

    conn = request("/logout", %{AuthPlug.token_key() => token}) |> AuthPlug.log_out()

    assert location(conn) == "/login"
    assert Auth.fetch(token) == {:error, :invalid}
    assert_receive {:sessions_revoked, [id]}
    assert id == session.id
  end

  describe "the remember cookie" do
    test "log_in with remember: true sets a signed cookie for the idle limit, http only, Lax" do
      {user, _} = Mem.user!(%{})
      conn = request("/login") |> AuthPlug.log_in(user, remember: true)

      cookie = conn.resp_cookies[@remember]
      assert cookie.max_age == Mem.idle_seconds()
      assert cookie.http_only == true
      assert cookie.same_site == "Lax"
      assert cookie.secure == false
      # Signed with the secret key base, holding the session's token.
      token = get_session(conn, AuthPlug.token_key())

      assert {:ok, ^token} =
               Plug.Crypto.verify(@secret_key_base, @remember <> "_cookie", cookie.value)
    end

    test "the cookie is secure exactly when the request is https" do
      {user, _} = Mem.user!(%{})

      conn =
        %{conn(:get, "/login") | scheme: :https}
        |> with_secret()
        |> init_test_session(%{})
        |> fetch()
        |> AuthPlug.log_in(user, remember: true)

      assert conn.resp_cookies[@remember].secure == true
    end

    test "without remember: true no live cookie is set, and an old one is deleted" do
      {user, _} = Mem.user!(%{})
      remembered = request("/login") |> AuthPlug.log_in(user, remember: true)

      conn =
        conn(:get, "/login")
        |> with_secret()
        |> recycle_cookies(remembered)
        |> init_test_session(%{})
        |> fetch()
        |> AuthPlug.log_in(user)

      assert conn.resp_cookies[@remember].max_age == 0
      plain = request("/login") |> AuthPlug.log_in(user)
      refute match?(%{max_age: age} when age > 0, plain.resp_cookies[@remember])
    end

    test "a session with no token is restored from the cookie, its token put back" do
      {user, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(user, remember: true)
      token = get_session(signed_in, AuthPlug.token_key())
      session = signed_in.assigns.current_session

      conn = next_request(signed_in, "/reports")

      assert conn.assigns.current_user.id == user.id
      assert conn.assigns.current_session.id == session.id
      assert get_session(conn, AuthPlug.token_key()) == token
      assert get_session(conn, :live_socket_id) == "macaw_auth_sessions:#{session.id}"
    end

    test "a touch of a remembered session sets the cookie again, for a fresh idle limit" do
      {user, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(user, remember: true)
      token = get_session(signed_in, AuthPlug.token_key())
      :ok = Mem.age_session!(signed_in.assigns.current_session.id, 400)

      conn = next_request(signed_in, "/reports", %{AuthPlug.token_key() => token})

      assert conn.assigns.current_user.id == user.id
      cookie = conn.resp_cookies[@remember]
      assert cookie.max_age == Mem.idle_seconds()
      assert cookie.http_only == true and cookie.same_site == "Lax" and cookie.secure == false

      assert {:ok, ^token} =
               Plug.Crypto.verify(@secret_key_base, @remember <> "_cookie", cookie.value)
    end

    test "a request that records no use leaves the cookie alone" do
      {user, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(user, remember: true)
      token = get_session(signed_in, AuthPlug.token_key())

      conn = next_request(signed_in, "/reports", %{AuthPlug.token_key() => token})

      assert conn.assigns.current_user.id == user.id
      refute Map.has_key?(conn.resp_cookies, @remember)
    end

    test "a touch never sets a cookie for a browser that didn't opt in" do
      {user, _} = Mem.user!(%{})
      {:ok, token, session} = Auth.create_session(user)
      :ok = Mem.age_session!(session.id, 400)

      conn = request("/reports", %{AuthPlug.token_key() => token})

      assert conn.assigns.current_user.id == user.id
      refute Map.has_key?(conn.resp_cookies, @remember)
    end

    test "a touch doesn't refresh a cookie holding another session's token" do
      {remembered, _} = Mem.user!(%{})
      {other, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(remembered, remember: true)
      {:ok, other_token, other_session} = Auth.create_session(other)
      :ok = Mem.age_session!(other_session.id, 400)

      conn = next_request(signed_in, "/reports", %{AuthPlug.token_key() => other_token})

      assert conn.assigns.current_user.id == other.id
      refute Map.has_key?(conn.resp_cookies, @remember)
    end

    test "the cookie is read only when the session has no token" do
      {remembered, _} = Mem.user!(%{})
      {other, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(remembered, remember: true)
      {:ok, other_token, _} = Auth.create_session(other)

      conn = next_request(signed_in, "/reports", %{AuthPlug.token_key() => other_token})
      assert conn.assigns.current_user.id == other.id
    end

    test "a revoked session's cookie is dead, and deleted" do
      {user, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(user, remember: true)
      :ok = Auth.revoke(signed_in.assigns.current_session.id)

      conn = next_request(signed_in, "/reports")
      assert conn.assigns.current_user == nil
      assert get_session(conn, AuthPlug.token_key()) == nil
      assert conn.resp_cookies[@remember].max_age == 0
    end

    test "a cookie not signed with the key is ignored" do
      {user, _} = Mem.user!(%{})
      {:ok, token, _} = Auth.create_session(user)

      conn =
        conn(:get, "/reports")
        |> with_secret()
        |> put_req_cookie(@remember, Base.url_encode64(token))
        |> init_test_session(%{})
        |> fetch()

      assert conn.assigns.current_user == nil
    end

    test "log_out deletes the cookie" do
      {user, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(user, remember: true)

      conn = next_request(signed_in, "/logout") |> AuthPlug.log_out()
      assert conn.resp_cookies[@remember].max_age == 0
      assert Auth.fetch(get_session(signed_in, AuthPlug.token_key())) == {:error, :invalid}
    end

    test "the cookie's name is configurable" do
      Application.put_env(:macaw_auth, :remember_cookie, "_my_app_remember")
      on_exit(fn -> Application.delete_env(:macaw_auth, :remember_cookie) end)
      {user, _} = Mem.user!(%{})

      signed_in = request("/login") |> AuthPlug.log_in(user, remember: true)
      assert AuthPlug.remember_cookie() == "_my_app_remember"
      assert Map.has_key?(signed_in.resp_cookies, "_my_app_remember")
      refute Map.has_key?(signed_in.resp_cookies, @remember)
      assert next_request(signed_in, "/reports").assigns.current_user.id == user.id
    end

    test "the default name" do
      assert AuthPlug.remember_cookie() == "_macaw_auth_remember"
    end
  end

  test "log_in puts the session's live_socket_id" do
    {user, _} = Mem.user!(%{})
    conn = request("/login") |> AuthPlug.log_in(user)
    id = conn.assigns.current_session.id
    assert get_session(conn, :live_socket_id) == "macaw_auth_sessions:#{id}"
    assert get_session(conn, "live_socket_id") == "macaw_auth_sessions:#{id}"
  end

  # Phoenix's redirect raises on each of these; the guard in front of it
  # sends them home, so a crafted path neither leaves the site nor fails
  # the request.
  test "a remembered path that would leave the site goes home instead, without raising" do
    {user, _} = Mem.user!(%{})

    for evil <- [
          "//evil.example/x",
          "/\\evil.example",
          "https://evil.example",
          "/a\\b",
          "/%09/evil.example",
          "/x\r\nSet-Cookie: a=b"
        ] do
      conn = request("/login", %{"macaw_auth_return_to" => evil}) |> AuthPlug.log_in(user)
      assert conn.status == 302
      assert location(conn) == "/home", "#{inspect(evil)} was followed"
    end
  end

  test "site_path? agrees with Phoenix's own check" do
    for path <- ["/", "/a", "/a?b=c", "//x", "/\\x", "/a\\b", "/%09x", "/\tx", "/a\nb", "x", ""] do
      assert AuthPlug.site_path?(path) == (Phoenix.URL.classify_local_path(path) == :ok),
             inspect(path)
    end
  end

  test "redirect_if_signed_in" do
    {user, _} = Mem.user!(%{})
    assert location(signed_in(user, "/login") |> AuthPlug.redirect_if_signed_in([])) == "/home"
    refute (request("/login") |> AuthPlug.redirect_if_signed_in([])).halted
  end

  test "the viewer is identity and roles only" do
    {user, _} = Mem.user!(%{roles: ["admin"]})
    conn = signed_in(user, "/")

    assert Auth.viewer(conn) == %{
             id: user.id,
             username: user.username,
             roles: ["admin"],
             source: "local"
           }

    assert Auth.viewer(request("/")) == nil
  end
end
