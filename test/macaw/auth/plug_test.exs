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

  defp request(path, session \\ %{}, method \\ :get) do
    conn(method, path) |> init_test_session(session) |> AuthPlug.fetch_current_user([])
  end

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

  test "require_role checks membership only, 403 otherwise" do
    {admin, _} = Mem.user!(%{roles: ["admin"]})
    {viewer, _} = Mem.user!(%{roles: ["viewer"]})

    refute (signed_in(admin, "/admin") |> AuthPlug.require_role(["admin", "owner"])).halted
    conn = signed_in(viewer, "/admin") |> AuthPlug.require_role(["admin"])
    assert conn.halted and conn.status == 403
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

  test "a remembered path that would leave the site goes home instead" do
    {user, _} = Mem.user!(%{})

    for evil <- ["//evil.example/x", "/\\evil.example", "https://evil.example"] do
      conn = request("/login", %{"macaw_auth_return_to" => evil}) |> AuthPlug.log_in(user)
      assert location(conn) == "/home", "#{evil} was followed"
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
