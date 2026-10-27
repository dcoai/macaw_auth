defmodule Macaw.Auth.LiveTest do
  use ExUnit.Case, async: false

  alias Macaw.Auth
  alias Macaw.Auth.Live
  alias Macaw.Auth.Test.MemoryBackend, as: Mem

  setup do
    Application.put_env(:macaw_auth, :backend, Mem)
    Mem.reset!()
    :ok
  end

  defp socket, do: %Phoenix.LiveView.Socket{assigns: %{__changed__: %{}, flash: %{}}}
  defp session(token), do: %{Macaw.Auth.Plug.token_key() => token}

  defp mounted(hook, token) do
    {:cont, socket} = Live.on_mount(hook, %{}, session(token), socket())
    socket
  end

  test "a signed-in session mounts with its user" do
    {user, _} = Mem.user!(%{})
    {:ok, token, _} = Auth.create_session(user)
    assert {:cont, socket} = Live.on_mount(:require_authenticated, %{}, session(token), socket())
    assert socket.assigns.current_user.id == user.id
  end

  test "a signed-out visitor is redirected to sign in" do
    assert {:halt, socket} = Live.on_mount(:require_authenticated, %{}, %{}, socket())
    assert socket.redirected == {:redirect, %{to: "/login", status: 302}}
  end

  test "a missing role is redirected home; a session owing a step to the step" do
    {viewer, _} = Mem.user!(%{roles: ["viewer"]})
    {:ok, token, _} = Auth.create_session(viewer)
    assert {:halt, s} = Live.on_mount({:require_role, ["admin"]}, %{}, session(token), socket())
    assert {:redirect, %{to: "/"}} = s.redirected

    {enrolled, _} = Mem.user!(%{second_factor: :enrolled})
    {:ok, token, _} = Auth.create_session(enrolled)
    assert {:halt, s} = Live.on_mount(:require_authenticated, %{}, session(token), socket())
    assert {:redirect, %{to: "/login/second-factor"}} = s.redirected
  end

  test "an open page leaves at once when its session is revoked, and not for another" do
    {user, _} = Mem.user!(%{})
    {:ok, token, session} = Auth.create_session(user)
    {:cont, s} = Live.on_mount(:mount_current_user, %{}, session(token), socket())

    assert {:halt, other} = Live.handle_guard({:sessions_revoked, [:someone_else]}, s)
    assert other.redirected == nil

    assert {:halt, gone} = Live.handle_guard({:sessions_revoked, [session.id]}, s)
    assert {:redirect, %{to: "/login"}} = gone.redirected
  end

  test "the re-check refreshes the user and leaves when the session is gone" do
    {user, _} = Mem.user!(%{})
    {:ok, token, session} = Auth.create_session(user)
    s = mounted(:require_authenticated, token)

    assert {:halt, kept} = Live.handle_guard(:macaw_auth_recheck, s)
    assert kept.assigns.current_user.id == user.id
    assert kept.redirected == nil

    :ok = Auth.revoke(session.id)
    assert {:halt, gone} = Live.handle_guard(:macaw_auth_recheck, s)
    assert {:redirect, %{to: "/login"}} = gone.redirected
  end

  test "the re-check sends a page whose role was removed home" do
    {admin, _} = Mem.user!(%{roles: ["admin"]})
    {:ok, token, _} = Auth.create_session(admin)
    s = mounted({:require_role, ["admin"]}, token)

    :ok = Mem.update_user!(admin, roles: ["viewer"])
    assert {:halt, gone} = Live.handle_guard(:macaw_auth_recheck, s)
    assert {:redirect, %{to: "/"}} = gone.redirected
  end

  test "the re-check sends a page whose session now owes a step to that step" do
    {user, _} = Mem.user!(%{})
    {:ok, token, _} = Auth.create_session(user)
    s = mounted(:require_authenticated, token)

    :ok = Mem.update_user!(user, must_change_password: true)
    assert {:halt, gone} = Live.handle_guard(:macaw_auth_recheck, s)
    assert {:redirect, %{to: "/password"}} = gone.redirected
  end

  test "other messages pass through" do
    assert {:cont, _} = Live.handle_guard(:something_else, socket())
  end

  describe "{:authorize, action}" do
    setup do
      on_exit(fn -> Application.delete_env(:macaw_auth, :authorizer) end)
    end

    defp authorize_mount(hook, params, token),
      do: Live.on_mount(hook, params, session(token), socket())

    test "closed by default: with no authorizer, even an admin is sent home" do
      Application.delete_env(:macaw_auth, :authorizer)
      {admin, _} = Mem.user!(%{roles: ["admin"]})
      {:ok, token, _} = Auth.create_session(admin)
      assert {:halt, s} = authorize_mount({:authorize, :manage}, %{}, token)
      assert {:redirect, %{to: "/"}} = s.redirected
    end

    test "the authorizer's true mounts the page and its false sends it home" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      {admin, _} = Mem.user!(%{roles: ["admin"]})
      {viewer, _} = Mem.user!(%{roles: ["viewer"]})
      {:ok, admin_token, _} = Auth.create_session(admin)
      {:ok, viewer_token, _} = Auth.create_session(viewer)

      assert {:cont, s} = authorize_mount({:authorize, :manage}, %{}, admin_token)
      assert s.assigns.current_user.id == admin.id

      assert {:halt, s} = authorize_mount({:authorize, :manage}, %{}, viewer_token)
      assert {:redirect, %{to: "/"}} = s.redirected
    end

    test "the resource is the option's function of the params and socket" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      {owner, _} = Mem.user!(%{})
      {other, _} = Mem.user!(%{})
      {:ok, owner_token, _} = Auth.create_session(owner)
      {:ok, other_token, _} = Auth.create_session(other)
      hook = {:authorize, :edit, resource: &Macaw.Auth.Test.Authorizer.post/2}
      params = %{"owner" => to_string(owner.id)}

      assert {:cont, _} = authorize_mount(hook, params, owner_token)
      assert {:halt, s} = authorize_mount(hook, params, other_token)
      assert {:redirect, %{to: "/"}} = s.redirected
      # Without `resource:` the authorizer is asked about nil, and refuses an edit.
      assert {:halt, _} = authorize_mount({:authorize, :edit}, params, owner_token)
    end

    test "a signed-out visitor is sent to sign in, and a session owing a step to the step" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      assert {:halt, s} = Live.on_mount({:authorize, :manage}, %{}, %{}, socket())
      assert {:redirect, %{to: "/login"}} = s.redirected

      {admin, _} = Mem.user!(%{roles: ["admin"], must_change_password: true})
      {:ok, token, _} = Auth.create_session(admin)
      assert {:halt, s} = authorize_mount({:authorize, :manage}, %{}, token)
      assert {:redirect, %{to: "/password"}} = s.redirected
    end

    test "the re-check asks the authorizer again, with the refreshed user" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      {admin, _} = Mem.user!(%{roles: ["admin"]})
      {:ok, token, _} = Auth.create_session(admin)
      s = mounted({:authorize, :manage}, token)

      assert {:halt, kept} = Live.handle_guard(:macaw_auth_recheck, s)
      assert kept.redirected == nil

      :ok = Mem.update_user!(admin, roles: ["viewer"])
      assert {:halt, gone} = Live.handle_guard(:macaw_auth_recheck, s)
      assert {:redirect, %{to: "/"}} = gone.redirected
    end

    test "the re-check keeps the resource the page mounted with" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      {owner, _} = Mem.user!(%{})
      {:ok, token, _} = Auth.create_session(owner)
      hook = {:authorize, :edit, resource: &Macaw.Auth.Test.Authorizer.post/2}

      {:cont, s} =
        Live.on_mount(hook, %{"owner" => to_string(owner.id)}, session(token), socket())

      assert {:halt, kept} = Live.handle_guard(:macaw_auth_recheck, s)
      assert kept.redirected == nil
    end

    test "an authorizer that raises crashes the mount" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      {user, _} = Mem.user!(%{})
      {:ok, token, _} = Auth.create_session(user)

      assert_raise RuntimeError, "the authorizer failed", fn ->
        authorize_mount({:authorize, :explode}, %{}, token)
      end
    end
  end
end
