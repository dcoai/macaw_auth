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

  defp with_public_url(url) do
    on_exit(fn -> Application.delete_env(:macaw_auth, :public_url) end)
    Application.put_env(:macaw_auth, :public_url, url)
  end

  @tag verifies: "plug-require-signed-out"
  test "a signed-out visitor is sent to sign in, remembering where a GET was going" do
    conn = request("/reports?year=2026") |> AuthPlug.require_authenticated([])
    assert conn.halted and conn.status == 302
    assert location(conn) == "/login"
    assert get_session(conn, "macaw_auth_return_to") == "/reports?year=2026"
  end

  @tag verifies: "plug-return-get-only"
  test "a GET is remembered with its query; a POST is not" do
    get = request("/reports?year=2026") |> AuthPlug.require_authenticated([])
    assert get_session(get, "macaw_auth_return_to") == "/reports?year=2026"

    post = request("/reports", %{}, :post) |> AuthPlug.require_authenticated([])
    assert get_session(post, "macaw_auth_return_to") == nil
  end

  @tag verifies: "plug-require-signed-in"
  test "a signed-in user passes, with user, session and no pending step" do
    {user, _} = Mem.user!(%{})
    conn = signed_in(user, "/reports") |> AuthPlug.require_authenticated([])
    refute conn.halted
    assert conn.assigns.current_user.id == user.id
    assert conn.assigns.pending_step == nil
  end

  @tag verifies: "plug-require-step"
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

  @tag verifies: "plug-require-role"
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

  @tag verifies: "plug-require-role-no-flash"
  test "require_role without fetch_flash still goes home, without a message" do
    {viewer, _} = Mem.user!(%{roles: ["viewer"]})
    conn = signed_in(viewer, "/admin") |> AuthPlug.require_role(["admin"])
    assert conn.halted and location(conn) == "/home"
    refute Map.has_key?(conn.assigns, :flash)
  end

  @tag verifies: "plug-require-role-signed-out"
  test "require_role alone sends a signed-out GET to sign in, remembering where it was going" do
    conn =
      request("/admin?tab=users")
      |> Phoenix.Controller.fetch_flash([])
      |> AuthPlug.require_role(["admin"])

    assert conn.halted and conn.status == 302
    assert location(conn) == "/login"
    assert get_session(conn, "macaw_auth_return_to") == "/admin?tab=users"
    assert Phoenix.Flash.get(conn.assigns.flash, :error) == nil
  end

  @tag verifies: "plug-require-role-signed-out-post"
  test "require_role sends a signed-out POST to sign in without remembering it" do
    conn = request("/admin", %{}, :post) |> AuthPlug.require_role(["admin"])
    assert conn.halted and conn.status == 302
    assert location(conn) == "/login"
    assert get_session(conn, "macaw_auth_return_to") == nil
  end

  @tag verifies: "plug-require-role-signed-in"
  test "require_role still sends a signed-in user without the role home, remembering nothing" do
    {viewer, _} = Mem.user!(%{roles: ["viewer"]})

    conn =
      signed_in(viewer, "/admin")
      |> Phoenix.Controller.fetch_flash([])
      |> AuthPlug.require_role(["admin"])

    assert conn.halted and conn.status == 302
    assert location(conn) == "/home"
    assert Phoenix.Flash.get(conn.assigns.flash, :error) == "You are not allowed to do that."
    assert get_session(conn, "macaw_auth_return_to") == nil
  end

  @tag verifies: "plug-log-in"
  test "log_in renews the session, stores the token, and returns where the visitor was going" do
    {user, _} = Mem.user!(%{})
    conn = request("/login", %{"macaw_auth_return_to" => "/reports"}) |> AuthPlug.log_in(user)

    assert location(conn) == "/reports"
    assert conn.private[:plug_session_info] == :renew
    assert {:ok, _, _} = Auth.fetch(get_session(conn, AuthPlug.token_key()))
  end

  @tag verifies: "plug-log-in-step"
  test "log_in sends a session that owes a step to the step" do
    {user, _} = Mem.user!(%{second_factor: :enrolled})
    conn = request("/login") |> AuthPlug.log_in(user)
    assert location(conn) == "/login/totp"
  end

  @tag verifies: "plug-complete-step"
  test "complete_step clears the step and continues" do
    {user, _} = Mem.user!(%{second_factor: :enrolled})
    {:ok, token, _} = Auth.create_session(user)

    conn =
      request("/login/totp", %{AuthPlug.token_key() => token})
      |> AuthPlug.complete_step(:second_factor)

    assert location(conn) == "/home"
    assert conn.assigns.pending_step == nil
  end

  @tag verifies: "plug-complete-step-revoked"
  test "complete_step of a session revoked meanwhile logs out" do
    {user, _} = Mem.user!(%{must_change_password: true})
    {:ok, token, session} = Auth.create_session(user)
    conn = request("/password", %{AuthPlug.token_key() => token})
    :ok = Auth.revoke(session.id)

    conn = AuthPlug.complete_step(conn, :password_change)
    assert conn.halted
    assert conn.status == 302
    assert location(conn) == "/login"
    assert get_session(conn, AuthPlug.token_key()) == nil
  end

  @tag verifies: "plug-log-in-refused"
  test "log_in for a user the backend no longer has goes back to sign in, setting no session or cookie" do
    for flash? <- [true, false] do
      {user, _} = Mem.user!(%{})
      :ok = Mem.delete!(user)
      conn = request("/login", %{"macaw_auth_return_to" => "/reports"})
      conn = if flash?, do: Phoenix.Controller.fetch_flash(conn, []), else: conn

      conn = AuthPlug.log_in(conn, user, remember: true)

      assert conn.halted
      assert conn.status == 302
      assert location(conn) == "/login"

      if flash?,
        do:
          assert(Phoenix.Flash.get(conn.assigns.flash, :error) == "You could not be signed in."),
        else: refute(Map.has_key?(conn.assigns, :flash))

      assert get_session(conn, AuthPlug.token_key()) == nil
      assert get_session(conn, "live_socket_id") == nil
      refute Map.has_key?(conn.resp_cookies, @remember)
      assert Auth.list_sessions(user.id) == []
    end
  end

  @tag verifies: "plug-verify-ok"
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

  @tag verifies: "plug-verify-refused"
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

  @tag verifies: "plug-log-out"
  test "log_out revokes the session and tells its open pages" do
    {user, _} = Mem.user!(%{})
    {:ok, token, session} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)

    conn = request("/logout", %{AuthPlug.token_key() => token}) |> AuthPlug.log_out()

    assert conn.status == 302 and location(conn) == "/login"
    assert Auth.fetch(token) == {:error, :invalid}
    assert_receive {:sessions_revoked, [id]}
    assert id == session.id
  end

  describe "enrollment by ticket" do
    # A browser that signed in as a user owing enrollment: its conn after
    # log_in, and the next request, carrying that session.
    defp ticketed(opts \\ []) do
      {user, creds} = Mem.user!(%{second_factor: :required})

      conn =
        request("/login", %{"macaw_auth_return_to" => "/reports"})
        |> AuthPlug.log_in(user, opts)

      {user, creds, conn, request("/second-factor/enroll", get_session(conn))}
    end

    @tag verifies: "plug-log-in-ticket"
    test "log_in of a user owing enrollment gives a ticket, no session, and goes to enroll" do
      {user, _creds, conn, _next} = ticketed()

      assert conn.halted
      assert location(conn) == "/second-factor/enroll"
      assert conn.private[:plug_session_info] == :renew
      assert is_binary(get_session(conn, "macaw_auth_enrollment_ticket"))
      assert get_session(conn, "macaw_auth_return_to") == "/reports"
      assert get_session(conn, AuthPlug.token_key()) == nil
      assert get_session(conn, "live_socket_id") == nil
      assert {conn.assigns.current_user, conn.assigns.current_session} == {nil, nil}
      assert Auth.list_sessions(user.id) == []

      # An older session's remember cookie doesn't outlive this sign-in.
      {other, _} = Mem.user!(%{})
      remembered = request("/login") |> AuthPlug.log_in(other, remember: true)

      again =
        conn(:post, "/login")
        |> with_secret()
        |> recycle_cookies(remembered)
        |> init_test_session(%{})
        |> AuthPlug.log_in(user)

      assert again.resp_cookies[@remember].max_age == 0
    end

    @tag verifies: "plug-enrollment"
    test "enrollment/1 shows the session's ticket; with none, or a refused one, :invalid_ticket" do
      {_user, _creds, _conn, next} = ticketed()
      assert {:ok, %{secret: secret, uri: "otpauth://totp/" <> _}} = AuthPlug.enrollment(next)
      assert is_binary(secret)

      assert AuthPlug.enrollment(request("/second-factor/enroll")) == {:error, :invalid_ticket}

      tampered = request("/second-factor/enroll", %{"macaw_auth_enrollment_ticket" => "x"})
      assert AuthPlug.enrollment(tampered) == {:error, :invalid_ticket}
    end

    @tag verifies: "plug-enroll-ok"
    test "enroll_second_factor/2 with a valid code starts the session only then, unredirected" do
      {user, _creds, _conn, next} = ticketed(remember: true)
      {:ok, %{secret: secret}} = AuthPlug.enrollment(next)
      assert Auth.list_sessions(user.id) == []

      assert {:ok, codes, conn} =
               AuthPlug.enroll_second_factor(next, NimbleTOTP.verification_code(secret))

      assert is_list(codes)
      refute conn.halted
      assert conn.private[:plug_session_info] == :renew
      assert get_session(conn, "macaw_auth_enrollment_ticket") == nil
      assert get_session(conn, "macaw_auth_return_to") == "/reports"
      token = get_session(conn, AuthPlug.token_key())

      assert {:ok, %Auth.User{second_factor: :enrolled}, %{second_factor_passed: true} = session} =
               Auth.fetch(token)

      assert get_session(conn, "live_socket_id") == Auth.live_socket_id(session.id)
      assert conn.assigns.current_user.second_factor == :enrolled
      assert conn.assigns.pending_step == nil
      # Remembered as sign-in asked.
      assert conn.resp_cookies[@remember].max_age == Mem.idle_seconds()

      # The page's next step goes where the browser was going.
      assert conn |> AuthPlug.continue() |> location() == "/reports"
    end

    @tag verifies: "plug-enroll-refused"
    test "enroll_second_factor/2 refused: a wrong code keeps the ticket, a refused ticket is dropped" do
      {user, _creds, _conn, next} = ticketed()

      assert {:error, :invalid_code, conn} = AuthPlug.enroll_second_factor(next, "000000")
      refute conn.halted
      assert is_binary(get_session(conn, "macaw_auth_enrollment_ticket"))

      tampered = request("/second-factor/enroll", %{"macaw_auth_enrollment_ticket" => "x"})
      assert {:error, :invalid_ticket, conn} = AuthPlug.enroll_second_factor(tampered, "000000")
      assert get_session(conn, "macaw_auth_enrollment_ticket") == nil

      none = request("/second-factor/enroll")
      assert {:error, :invalid_ticket, ^none} = AuthPlug.enroll_second_factor(none, "000000")
      assert Auth.list_sessions(user.id) == []
    end
  end

  describe "the remember cookie" do
    @tag verifies: "plug-remember-cookie"
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

    @tag verifies: "plug-remember-secure"
    test "the cookie is secure exactly when the request is https" do
      {user, _} = Mem.user!(%{})

      conn =
        %{conn(:get, "/login") | scheme: :https}
        |> with_secret()
        |> init_test_session(%{})
        |> fetch()
        |> AuthPlug.log_in(user, remember: true)

      assert conn.resp_cookies[@remember].secure == true

      plain = request("/login") |> AuthPlug.log_in(user, remember: true)
      assert plain.scheme == :http
      assert Application.get_env(:macaw_auth, :public_url) == nil
      assert plain.resp_cookies[@remember].secure == false
    end

    @tag verifies: "plug-remember-secure-declared"
    test "a declared https public URL adds secure to a plain request; nothing removes it" do
      {user, _} = Mem.user!(%{})
      with_public_url("https://app.example.com")

      # Plain http, as a TLS-terminating proxy forwards it.
      remembered = request("/login") |> AuthPlug.log_in(user, remember: true)
      assert remembered.scheme == :http
      assert remembered.resp_cookies[@remember].secure == true

      # Deleting it carries the same flag.
      forgotten =
        conn(:get, "/login")
        |> with_secret()
        |> recycle_cookies(remembered)
        |> init_test_session(%{})
        |> fetch()
        |> AuthPlug.log_in(user)

      assert forgotten.resp_cookies[@remember].max_age == 0
      assert forgotten.resp_cookies[@remember].secure == true

      # An http public URL adds nothing, and takes nothing from https.
      with_public_url("http://app.example.com")
      plain = request("/login") |> AuthPlug.log_in(user, remember: true)
      assert plain.resp_cookies[@remember].secure == false

      https =
        %{conn(:get, "/login") | scheme: :https}
        |> with_secret()
        |> init_test_session(%{})
        |> fetch()
        |> AuthPlug.log_in(user, remember: true)

      assert https.resp_cookies[@remember].secure == true
    end

    @tag verifies: "plug-public-url-checked"
    test "the public URL is an http or https URL with a host, else ArgumentError naming it" do
      assert AuthPlug.public_scheme() == nil
      with_public_url("https://app.example.com")
      assert AuthPlug.public_scheme() == :https
      with_public_url("http://app.example.com")
      assert AuthPlug.public_scheme() == :http

      for bad <- ["ftp://app.example.com", "https://", "app.example.com", :https] do
        with_public_url(bad)

        assert_raise ArgumentError,
                     "config :macaw_auth, public_url: must be an http or https URL with a host, " <>
                       "got #{inspect(bad)}",
                     &AuthPlug.public_scheme/0
      end
    end

    @tag verifies: "plug-remember-off"
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

    @tag verifies: "plug-remember-restore"
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

    @tag verifies: "plug-remember-touch"
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

    @tag verifies: "plug-remember-no-touch"
    test "no touch, no cookie sent, or another session's cookie: the cookie is left alone" do
      # No touch: the session isn't aged, so the request records no use.
      {user, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(user, remember: true)
      token = get_session(signed_in, AuthPlug.token_key())

      conn = next_request(signed_in, "/reports", %{AuthPlug.token_key() => token})

      assert conn.assigns.current_user.id == user.id
      refute Map.has_key?(conn.resp_cookies, @remember)

      # A touch, but the browser never opted in.
      {plain, _} = Mem.user!(%{})
      {:ok, plain_token, plain_session} = Auth.create_session(plain)
      :ok = Mem.age_session!(plain_session.id, 400)

      conn = request("/reports", %{AuthPlug.token_key() => plain_token})

      assert conn.assigns.current_user.id == plain.id
      refute Map.has_key?(conn.resp_cookies, @remember)

      # A touch, but the browser's cookie holds another session's token.
      {other, _} = Mem.user!(%{})
      {:ok, other_token, other_session} = Auth.create_session(other)
      :ok = Mem.age_session!(other_session.id, 400)

      conn = next_request(signed_in, "/reports", %{AuthPlug.token_key() => other_token})

      assert conn.assigns.current_user.id == other.id
      refute Map.has_key?(conn.resp_cookies, @remember)
    end

    @tag verifies: "plug-remember-session-first"
    test "the cookie is read only when the session has no token" do
      {remembered, _} = Mem.user!(%{})
      {other, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(remembered, remember: true)
      {:ok, other_token, _} = Auth.create_session(other)

      conn = next_request(signed_in, "/reports", %{AuthPlug.token_key() => other_token})
      assert conn.assigns.current_user.id == other.id
    end

    @tag verifies: "plug-remember-revoked"
    test "a revoked session's cookie is dead, and deleted" do
      {user, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(user, remember: true)
      :ok = Auth.revoke(signed_in.assigns.current_session.id)

      conn = next_request(signed_in, "/reports")
      assert conn.assigns.current_user == nil
      assert get_session(conn, AuthPlug.token_key()) == nil
      assert conn.resp_cookies[@remember].max_age == 0
    end

    @tag verifies: "plug-remember-unsigned"
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

    @tag verifies: "plug-log-out-cookie"
    test "log_out deletes the cookie" do
      {user, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(user, remember: true)

      conn = next_request(signed_in, "/logout") |> AuthPlug.log_out()
      assert conn.resp_cookies[@remember].max_age == 0
      assert Auth.fetch(get_session(signed_in, AuthPlug.token_key())) == {:error, :invalid}
    end

    @tag verifies: "plug-remember-name"
    test "the cookie's name is configurable, by default _macaw_auth_remember" do
      assert AuthPlug.remember_cookie() == "_macaw_auth_remember"
      Application.put_env(:macaw_auth, :remember_cookie, "_my_app_remember")
      on_exit(fn -> Application.delete_env(:macaw_auth, :remember_cookie) end)
      {user, _} = Mem.user!(%{})

      signed_in = request("/login") |> AuthPlug.log_in(user, remember: true)
      assert AuthPlug.remember_cookie() == "_my_app_remember"
      assert Map.has_key?(signed_in.resp_cookies, "_my_app_remember")
      refute Map.has_key?(signed_in.resp_cookies, @remember)
      assert next_request(signed_in, "/reports").assigns.current_user.id == user.id
    end
  end

  @tag verifies: "plug-live-socket-id"
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
  @tag verifies: "plug-open-redirect"
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

  @tag verifies: "plug-site-path-phoenix"
  test "site_path? agrees with Phoenix's own check" do
    for path <- ["/", "/a", "/a?b=c", "//x", "/\\x", "/a\\b", "/%09x", "/\tx", "/a\nb", "x", ""] do
      assert AuthPlug.site_path?(path) == (Phoenix.URL.classify_local_path(path) == :ok),
             inspect(path)
    end
  end

  @tag verifies: "plug-redirect-signed-in"
  test "redirect_if_signed_in" do
    {user, _} = Mem.user!(%{})
    assert location(signed_in(user, "/login") |> AuthPlug.redirect_if_signed_in([])) == "/home"
    refute (request("/login") |> AuthPlug.redirect_if_signed_in([])).halted
  end

  @tag verifies: "viewer"
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

  describe "authorize" do
    setup do
      on_exit(fn -> Application.delete_env(:macaw_auth, :authorizer) end)
    end

    @tag verifies: "plug-authorize-closed"
    test "closed by default: with no authorizer, even an admin is refused" do
      Application.delete_env(:macaw_auth, :authorizer)
      {admin, _} = Mem.user!(%{roles: ["admin"]})

      conn =
        signed_in(admin, "/admin")
        |> Phoenix.Controller.fetch_flash([])
        |> AuthPlug.authorize(:manage)

      assert conn.halted and conn.status == 302
      assert location(conn) == "/home"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) == "You are not allowed to do that."
    end

    @tag verifies: "plug-authorize"
    test "the authorizer's true passes and its false refuses, as require_role refuses" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      {admin, _} = Mem.user!(%{roles: ["admin"]})
      {viewer, _} = Mem.user!(%{roles: ["viewer"]})

      refute (signed_in(admin, "/admin") |> AuthPlug.authorize(:manage)).halted

      conn =
        signed_in(viewer, "/admin")
        |> Phoenix.Controller.fetch_flash([])
        |> AuthPlug.authorize(:manage)

      assert conn.halted and conn.status == 302
      assert location(conn) == "/home"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) == "You are not allowed to do that."

      without_flash = signed_in(viewer, "/admin") |> AuthPlug.authorize(:manage)
      assert without_flash.halted and location(without_flash) == "/home"
      refute Map.has_key?(without_flash.assigns, :flash)
    end

    @tag verifies: "plug-authorize-resource"
    test "the resource is the option's function of the conn, else nil" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      {owner, _} = Mem.user!(%{})
      {other, _} = Mem.user!(%{})
      opts = {:edit, resource: &Macaw.Auth.Test.Authorizer.post/1}

      refute (signed_in(owner, "/posts?owner=#{owner.id}") |> AuthPlug.authorize(opts)).halted
      assert (signed_in(other, "/posts?owner=#{owner.id}") |> AuthPlug.authorize(opts)).halted
      # Without `resource:` the authorizer is asked about nil, and refuses an edit.
      assert (signed_in(owner, "/posts") |> AuthPlug.authorize(:edit)).halted
    end

    @tag verifies: "plug-authorize-signed-out"
    test "a signed-out visitor is sent to sign in, remembering where a GET was going" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      conn = request("/admin?tab=users") |> AuthPlug.authorize(:manage)
      assert conn.halted and location(conn) == "/login"
      assert get_session(conn, "macaw_auth_return_to") == "/admin?tab=users"
    end

    @tag verifies: "plug-authorize-raises"
    test "an authorizer that raises crashes the request" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      {user, _} = Mem.user!(%{})
      conn = signed_in(user, "/boom")

      assert_raise RuntimeError, "the authorizer failed", fn ->
        AuthPlug.authorize(conn, :explode)
      end
    end
  end

  @tag verifies: "plug-token-key"
  test "the token is read from the session key token_key/0 names" do
    assert AuthPlug.token_key() == "macaw_auth_token"
    {user, _} = Mem.user!(%{})
    {:ok, token, _} = Auth.create_session(user)

    assert request("/", %{"macaw_auth_token" => token}).assigns.current_user.id == user.id
    assert request("/", %{"token" => token}).assigns.current_user == nil
  end

  @tag verifies: "plug-fetch"
  test "a live token assigns its user and session; a revoked one three nils, and loses the token" do
    {user, _} = Mem.user!(%{})
    {:ok, token, session} = Auth.create_session(user)

    conn = request("/", %{AuthPlug.token_key() => token})
    assert conn.assigns.current_user.id == user.id
    assert conn.assigns.current_session.id == session.id
    assert conn.assigns.pending_step == nil

    :ok = Auth.revoke(session.id)
    conn = request("/", %{AuthPlug.token_key() => token})

    assert {conn.assigns.current_user, conn.assigns.current_session, conn.assigns.pending_step} ==
             {nil, nil, nil}

    assert get_session(conn, AuthPlug.token_key()) == nil
  end

  # A resource function that must never be called.
  def unasked_resource(_conn), do: raise("the resource was asked")

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 02" do
    @tag verifies: "auth-plug"
    test "the pipeline: the session first, the client's address from ClientIp, the flash for refusals" do
      # Without fetch_session, the token has nowhere to be read from.
      assert_raise ArgumentError, fn -> conn(:get, "/") |> fetch() end

      # Behind a trusted proxy, ClientIp makes the session record the client's address.
      {user, _} = Mem.user!(%{roles: ["viewer"]})

      conn =
        %{conn(:get, "/login") | remote_ip: {10, 0, 0, 1}}
        |> put_req_header("x-forwarded-for", "198.51.100.9")
        |> with_secret()
        |> init_test_session(%{})
        |> Phoenix.Controller.fetch_flash([])
        |> Macaw.Plug.ClientIp.call(Macaw.Plug.ClientIp.init(trusted_proxies: ["10.0.0.0/8"]))
        |> fetch()
        |> AuthPlug.log_in(user)

      assert conn.assigns.current_session.remote_ip == "198.51.100.9"

      # With fetch_flash first, a refusal says why; without it, it goes home silently.
      token = get_session(conn, AuthPlug.token_key())
      session = %{AuthPlug.token_key() => token}

      said =
        request("/admin", session)
        |> Phoenix.Controller.fetch_flash([])
        |> AuthPlug.require_role(["admin"])

      assert Phoenix.Flash.get(said.assigns.flash, :error) == "You are not allowed to do that."

      silent = request("/admin", session) |> AuthPlug.require_role(["admin"])
      assert silent.halted and location(silent) == "/home"
      refute Map.has_key?(silent.assigns, :flash)
    end

    @tag verifies: "auth-plug-keys"
    test "the library's session keys are the token, the return path and the socket id, and its one cookie the remember cookie" do
      # A signed-out GET: only the return path.
      remembered = request("/reports") |> AuthPlug.require_authenticated([])
      assert get_session(remembered) == %{"macaw_auth_return_to" => "/reports"}

      # Signed in: the token and the socket id (the return path was used and dropped).
      {user, _} = Mem.user!(%{})

      conn =
        request("/login", %{"macaw_auth_return_to" => "/reports", "other" => 1})
        |> AuthPlug.log_in(user, remember: true)

      id = conn.assigns.current_session.id

      assert get_session(conn) == %{
               "macaw_auth_token" => get_session(conn, AuthPlug.token_key()),
               "live_socket_id" => "macaw_auth_sessions:#{id}"
             }

      assert Map.keys(conn.resp_cookies) == ["_macaw_auth_remember"]

      # A remembered session restored: the token and the socket id again.
      restored = next_request(conn, "/reports")

      assert get_session(restored) == %{
               "macaw_auth_token" => get_session(conn, AuthPlug.token_key()),
               "live_socket_id" => "macaw_auth_sessions:#{id}"
             }
    end

    @tag verifies: "auth-plug-fetch"
    test "a request touches its session, and a token refused for any reason is dropped" do
      {user, _} = Mem.user!(%{})
      {:ok, token, session} = Auth.create_session(user)
      :ok = Mem.age_session!(session.id, 400)

      # touch: true: the request records the session's use.
      conn = request("/", %{AuthPlug.token_key() => token})
      assert DateTime.diff(DateTime.utc_now(), conn.assigns.current_session.last_used_at) < 5

      # Expired, disabled, garbage: three nils, and the token leaves the session.
      {idle, _} = Mem.user!(%{})
      {:ok, idle_token, idle_session} = Auth.create_session(idle)
      :ok = Mem.age_session!(idle_session.id, Mem.idle_seconds() + 1)

      {disabled, _} = Mem.user!(%{})
      {:ok, disabled_token, _} = Auth.create_session(disabled)
      :ok = Mem.disable!(disabled)

      for refused <- [idle_token, disabled_token, :crypto.strong_rand_bytes(32)] do
        conn = request("/", %{AuthPlug.token_key() => refused})

        assert {conn.assigns.current_user, conn.assigns.current_session,
                conn.assigns.pending_step} == {nil, nil, nil}

        assert get_session(conn, AuthPlug.token_key()) == nil
      end
    end

    @tag verifies: "auth-plug-require-authenticated"
    test "a session owing a step passes only at exactly the step's page or sign-out" do
      {user, _} = Mem.user!(%{second_factor: :enrolled})
      {:ok, token, _} = Auth.create_session(user)
      session = %{AuthPlug.token_key() => token}

      for path <- ["/login/totp/", "/login/totp/x", "/logout/now", "/", "/login"] do
        conn = request(path, session) |> AuthPlug.require_authenticated([])
        assert conn.halted and conn.status == 302, path
        assert location(conn) == "/login/totp"
      end

      # The query string is not the path: the step's page with one passes.
      refute (request("/login/totp?retry=1", session)
              |> AuthPlug.require_authenticated([])).halted

      # Signed out: halted to sign in.
      conn = request("/login/totp") |> AuthPlug.require_authenticated([])
      assert conn.halted and location(conn) == "/login"
    end

    @tag verifies: "auth-plug-return"
    test "the return path is the GET's path, with ? only for a query, and is checked only when used" do
      plain = request("/reports") |> AuthPlug.require_authenticated([])
      assert get_session(plain, "macaw_auth_return_to") == "/reports"

      for method <- [:put, :patch, :delete] do
        conn = request("/reports", %{}, method) |> AuthPlug.require_authenticated([])
        assert get_session(conn, "macaw_auth_return_to") == nil
      end

      # Remembered as it came, then refused when used.
      evil = request("/\\evil.example") |> AuthPlug.require_authenticated([])

      assert get_session(evil, "macaw_auth_return_to") == "/\\evil.example"

      {user, _} = Mem.user!(%{})

      conn =
        request("/login", %{"macaw_auth_return_to" => get_session(evil, "macaw_auth_return_to")})
        |> AuthPlug.log_in(user)

      assert location(conn) == "/home"
    end

    @tag verifies: "auth-plug-require-role"
    test "any one of the roles admits, by exact membership; a refusal is a redirect, not a 403" do
      {owner, _} = Mem.user!(%{roles: ["viewer", "owner"]})
      refute (signed_in(owner, "/admin") |> AuthPlug.require_role(["admin", "owner"])).halted

      for roles <- [["Admin"], ["admins"], []] do
        {user, _} = Mem.user!(%{roles: roles})
        conn = signed_in(user, "/admin") |> AuthPlug.require_role(["admin"])
        assert conn.halted and conn.status == 302, inspect(roles)
        assert location(conn) == "/home"
      end

      {viewer, _} = Mem.user!(%{roles: ["viewer"]})

      conn =
        signed_in(viewer, "/admin")
        |> Phoenix.Controller.fetch_flash([])
        |> AuthPlug.require_role([])

      assert conn.status == 302 and location(conn) == "/home"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) == "You are not allowed to do that."

      # Signed out, it is not a refusal: to sign in, as require_authenticated sends it.
      for method <- [:get, :post] do
        conn =
          request("/admin?tab=users", %{}, method)
          |> Phoenix.Controller.fetch_flash([])
          |> AuthPlug.require_role(["admin"])

        assert conn.halted and conn.status == 302 and location(conn) == "/login"
        assert Phoenix.Flash.get(conn.assigns.flash, :error) == nil

        assert get_session(conn, "macaw_auth_return_to") ==
                 if(method == :get, do: "/admin?tab=users")
      end
    end

    @tag verifies: "auth-plug-authorize"
    test "authorize's options, its resource only when signed in, and a step it leaves alone" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      on_exit(fn -> Application.delete_env(:macaw_auth, :authorizer) end)
      {admin, _} = Mem.user!(%{roles: ["admin"]})

      # Only :resource is an option.
      assert_raise ArgumentError, fn ->
        signed_in(admin, "/admin") |> AuthPlug.authorize({:manage, owner: 1})
      end

      # The resource function isn't called for a signed-out request.
      conn =
        request("/admin")
        |> AuthPlug.authorize({:manage, resource: &__MODULE__.unasked_resource/1})

      assert conn.halted and location(conn) == "/login"

      # Allowed: the conn as it came.
      conn = signed_in(admin, "/admin")
      assert AuthPlug.authorize(conn, :manage) == conn

      # A session owing a step is neither checked nor sent to it here.
      {owing, _} = Mem.user!(%{roles: ["admin"], second_factor: :enrolled})
      conn = signed_in(owing, "/admin")
      assert conn.assigns.pending_step == :second_factor
      assert AuthPlug.authorize(conn, :manage) == conn
    end

    @tag verifies: "auth-plug-redirect-signed-in"
    test "redirect_if_signed_in: signed in, 302 home, halted; signed out, the conn as it came" do
      {user, _} = Mem.user!(%{})
      conn = signed_in(user, "/login") |> AuthPlug.redirect_if_signed_in([])
      assert conn.halted and conn.status == 302 and location(conn) == "/home"

      signed_out = request("/login")
      assert AuthPlug.redirect_if_signed_in(signed_out, []) == signed_out
    end

    @tag verifies: "auth-plug-log-in"
    test "log_in records the client and user agent, clears the session but the return path; refused, it touches nothing" do
      {user, _} = Mem.user!(%{})

      conn =
        %{conn(:get, "/login") | remote_ip: {203, 0, 113, 7}}
        |> put_req_header("user-agent", "Browser/1.0")
        |> with_secret()
        |> init_test_session(%{"macaw_auth_return_to" => "/reports", "other" => 1})
        |> fetch()
        |> AuthPlug.log_in(user)

      session = conn.assigns.current_session
      assert {session.remote_ip, session.user_agent} == {"203.0.113.7", "Browser/1.0"}
      assert get_session(conn, "other") == nil
      assert conn.assigns.current_user.id == user.id
      assert conn.assigns.pending_step == nil
      assert conn.halted
      assert conn.status == 302 and location(conn) == "/reports"

      # Options other than :remember go to create_session/2, over the conn's.
      conn =
        request("/login") |> AuthPlug.log_in(user, user_agent: "given", remote_ip: "192.0.2.5")

      session = conn.assigns.current_session
      assert {session.remote_ip, session.user_agent} == {"192.0.2.5", "given"}

      # Refused: the session neither renewed nor cleared, the browser's cookie kept,
      # the assigns as they were.
      remembered = request("/login") |> AuthPlug.log_in(user, remember: true)
      {gone, _} = Mem.user!(%{})
      :ok = Mem.delete!(gone)
      token = get_session(remembered, AuthPlug.token_key())

      before =
        next_request(remembered, "/login", %{
          AuthPlug.token_key() => token,
          "macaw_auth_return_to" => "/reports"
        })

      for remember <- [true, false] do
        conn = AuthPlug.log_in(before, gone, remember: remember)
        assert conn.private[:plug_session_info] == before.private[:plug_session_info]
        assert get_session(conn) == get_session(before)
        assert get_session(conn, "macaw_auth_return_to") == "/reports"
        refute Map.has_key?(conn.resp_cookies, @remember)
        assert conn.assigns.current_user.id == before.assigns.current_user.id
        assert conn.assigns.current_session == before.assigns.current_session
        assert conn.assigns.pending_step == before.assigns.pending_step
      end
    end

    @tag verifies: "auth-plug-log-in"
    test "log_out renews and clears the session, and with no session or cookie still goes to sign in" do
      {user, _} = Mem.user!(%{})
      {:ok, token, _} = Auth.create_session(user)

      conn =
        request("/logout", %{AuthPlug.token_key() => token, "other" => 1}) |> AuthPlug.log_out()

      assert conn.private[:plug_session_info] == :renew
      assert get_session(conn) == %{}
      assert conn.halted
      assert conn.status == 302 and location(conn) == "/login"
      # No remember cookie was sent, so none is deleted.
      refute Map.has_key?(conn.resp_cookies, @remember)

      signed_out = request("/logout") |> AuthPlug.log_out()
      assert signed_out.halted
      assert location(signed_out) == "/login"
    end

    @tag verifies: "auth-plug-continue"
    test "continue: the owed step, else the return path (then forgotten), else home" do
      {owing, _} = Mem.user!(%{second_factor: :enrolled})
      {:ok, token, _} = Auth.create_session(owing)

      conn =
        request("/login", %{AuthPlug.token_key() => token, "macaw_auth_return_to" => "/reports"})
        |> AuthPlug.continue()

      assert conn.halted
      assert conn.status == 302 and location(conn) == "/login/totp"

      {user, _} = Mem.user!(%{})
      {:ok, token, _} = Auth.create_session(user)

      conn =
        request("/login", %{AuthPlug.token_key() => token, "macaw_auth_return_to" => "/reports"})
        |> AuthPlug.continue()

      assert conn.halted
      assert location(conn) == "/reports"
      assert get_session(conn, "macaw_auth_return_to") == nil

      conn = request("/login", %{AuthPlug.token_key() => token}) |> AuthPlug.continue()
      assert conn.halted
      assert location(conn) == "/home"
    end

    @tag verifies: "auth-plug-complete-step"
    test "complete_step re-reads the session and goes on; a session that no longer resolves is logged out" do
      {user, _} = Mem.user!(%{must_change_password: true})
      {:ok, token, _} = Auth.create_session(user)
      session = %{AuthPlug.token_key() => token, "macaw_auth_return_to" => "/reports"}

      conn = request("/password", session)
      assert conn.assigns.pending_step == :password_change
      conn = AuthPlug.complete_step(conn, :password_change)
      assert conn.assigns.current_session.completed_steps == [:password_change]
      assert conn.assigns.pending_step == nil
      assert conn.halted
      assert location(conn) == "/reports"

      # The step is recorded, but the session no longer resolves (its user disabled).
      {disabled, _} = Mem.user!(%{must_change_password: true})
      {:ok, token, _} = Auth.create_session(disabled)
      conn = request("/password", %{AuthPlug.token_key() => token})
      :ok = Mem.disable!(disabled)

      conn = AuthPlug.complete_step(conn, :password_change)
      assert conn.halted
      assert location(conn) == "/login"
      assert get_session(conn, AuthPlug.token_key()) == nil
    end

    @tag verifies: "auth-plug-site-path"
    test "site_path? is one leading slash and none of the unsafe sequences; every redirect is a halted 302" do
      for path <- ["/", "/reports", "/a/b?c=d", "/a%20b"],
          do: assert(AuthPlug.site_path?(path), path)

      for path <- [
            "//evil.example",
            "/a\\b",
            "/%09evil",
            "/a/%09b",
            "/\tx",
            "/a\nb",
            "/a\rb",
            "https://evil.example",
            "x",
            ""
          ],
          do: refute(AuthPlug.site_path?(path), inspect(path))

      {user, _} = Mem.user!(%{})
      {:ok, token, _} = Auth.create_session(user)
      signed = %{AuthPlug.token_key() => token}

      for conn <- [
            request("/reports") |> AuthPlug.require_authenticated([]),
            request("/admin", signed) |> AuthPlug.require_role(["admin"]),
            request("/login", signed) |> AuthPlug.redirect_if_signed_in([]),
            request("/login", signed) |> AuthPlug.continue(),
            request("/logout", signed) |> AuthPlug.log_out()
          ] do
        assert conn.halted and conn.status == 302
        assert AuthPlug.site_path?(location(conn))
      end
    end

    @tag verifies: "auth-plug-remember"
    test "remembered, a browser stays signed in after it closes; not remembered, it doesn't" do
      {user, _} = Mem.user!(%{})

      remembered = request("/login") |> AuthPlug.log_in(user, remember: true)
      assert next_request(remembered, "/reports").assigns.current_user.id == user.id

      forgotten = request("/login") |> AuthPlug.log_in(user)
      refute Map.has_key?(forgotten.resp_cookies, @remember)
      assert next_request(forgotten, "/reports").assigns.current_user == nil
    end

    @tag verifies: "auth-plug-remember-cookie"
    test "the cookie never holds the bare token, and an altered one is ignored as absent" do
      {user, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(user, remember: true)
      token = get_session(signed_in, AuthPlug.token_key())
      value = signed_in.resp_cookies[@remember].value

      refute value == token
      refute value =~ Base.url_encode64(token, padding: false)

      # Change a character inside the signature (not the last, whose low bits
      # are only padding): it no longer verifies.
      at = byte_size(value) - 5
      <<head::binary-size(^at), char, tail::binary>> = value
      altered = head <> if(char == ?A, do: "Q", else: "A") <> tail

      conn =
        conn(:get, "/reports")
        |> with_secret()
        |> put_req_cookie(@remember, altered)
        |> init_test_session(%{})
        |> fetch()

      assert conn.assigns.current_user == nil
      assert get_session(conn, AuthPlug.token_key()) == nil
    end

    @tag verifies: "auth-plug-remember-read"
    test "a restored session is renewed and its cookie set again; a refused one's cookie is deleted" do
      {user, _} = Mem.user!(%{})
      signed_in = request("/login") |> AuthPlug.log_in(user, remember: true)
      token = get_session(signed_in, AuthPlug.token_key())

      restored = next_request(signed_in, "/reports")
      assert restored.private[:plug_session_info] == :renew
      cookie = restored.resp_cookies[@remember]
      assert cookie.max_age == Mem.idle_seconds()

      assert {:ok, ^token} =
               Plug.Crypto.verify(@secret_key_base, @remember <> "_cookie", cookie.value)

      # Its user disabled: the cookie is dead, and deleted.
      :ok = Mem.disable!(user)
      refused = next_request(signed_in, "/reports")
      assert refused.assigns.current_user == nil
      assert refused.resp_cookies[@remember].max_age == 0

      # No cookie at all: signed out, nothing set.
      none = request("/reports")
      assert none.assigns.current_user == nil
      assert none.resp_cookies == %{}
    end

    @tag verifies: "auth-plug-secure"
    test "the library sets no cookie but its own, secure by the scheme or the declared public URL" do
      {user, _} = Mem.user!(%{})

      for {url, scheme, secure} <- [
            {nil, :https, true},
            {nil, :http, false},
            {"https://app.example.com", :http, true},
            {"http://app.example.com", :http, false},
            {"http://app.example.com", :https, true}
          ] do
        if url, do: with_public_url(url), else: Application.delete_env(:macaw_auth, :public_url)

        conn =
          %{conn(:get, "/login") | scheme: scheme}
          |> with_secret()
          |> init_test_session(%{})
          |> fetch()
          |> AuthPlug.log_in(user, remember: true)

        assert Map.keys(conn.resp_cookies) == [@remember]
        assert conn.resp_cookies[@remember].secure == secure
      end
    end
  end
end
