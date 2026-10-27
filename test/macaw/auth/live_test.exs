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

  @tag verifies: "live-mount-user"
  test ":mount_current_user assigns the user and session of a live token, and nil without one" do
    {user, _} = Mem.user!(%{})
    {:ok, token, user_session} = Auth.create_session(user)

    assert {:cont, s} = Live.on_mount(:mount_current_user, %{}, session(token), socket())
    assert s.assigns.current_user.id == user.id
    assert s.assigns.current_session.id == user_session.id

    assert {:cont, s} = Live.on_mount(:mount_current_user, %{}, %{}, socket())
    assert s.assigns.current_user == nil
    assert s.assigns.current_session == nil
  end

  @tag verifies: "live-require-authenticated"
  test "a signed-in session mounts with its user" do
    {user, _} = Mem.user!(%{})
    {:ok, token, user_session} = Auth.create_session(user)
    assert {:cont, socket} = Live.on_mount(:require_authenticated, %{}, session(token), socket())
    assert socket.assigns.current_user.id == user.id
    assert socket.assigns.current_session.id == user_session.id
  end

  @tag verifies: "live-require-signed-out"
  test "a signed-out visitor is redirected to sign in" do
    assert {:halt, socket} = Live.on_mount(:require_authenticated, %{}, %{}, socket())
    assert socket.redirected == {:redirect, %{to: "/login", status: 302}}
  end

  @tag verifies: "live-require-role"
  test "a missing role is redirected home; a held one mounts" do
    {viewer, _} = Mem.user!(%{roles: ["viewer"]})
    {:ok, token, _} = Auth.create_session(viewer)
    assert {:halt, s} = Live.on_mount({:require_role, ["admin"]}, %{}, session(token), socket())
    assert {:redirect, %{to: "/"}} = s.redirected

    {admin, _} = Mem.user!(%{roles: ["admin"]})
    {:ok, token, _} = Auth.create_session(admin)
    assert {:cont, s} = Live.on_mount({:require_role, ["admin"]}, %{}, session(token), socket())
    assert s.assigns.current_user.id == admin.id
  end

  @tag verifies: "live-require-step"
  test "a session owing a step is redirected to the step" do
    {enrolled, _} = Mem.user!(%{second_factor: :enrolled})
    {:ok, token, _} = Auth.create_session(enrolled)
    assert {:halt, s} = Live.on_mount(:require_authenticated, %{}, session(token), socket())
    assert {:redirect, %{to: "/login/second-factor"}} = s.redirected
  end

  @tag verifies: "live-revoked"
  test "an open page leaves at once when its session is revoked, and not for another" do
    {user, _} = Mem.user!(%{})
    {:ok, token, session} = Auth.create_session(user)
    {:cont, s} = Live.on_mount(:mount_current_user, %{}, session(token), socket())

    assert {:halt, other} = Live.handle_guard({:sessions_revoked, [:someone_else]}, s)
    assert other.redirected == nil

    assert {:halt, gone} = Live.handle_guard({:sessions_revoked, [session.id]}, s)
    assert {:redirect, %{to: "/login"}} = gone.redirected
  end

  @tag verifies: "live-recheck"
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

  @tag verifies: "live-recheck-role"
  test "the re-check sends a page whose role was removed home" do
    {admin, _} = Mem.user!(%{roles: ["admin"]})
    {:ok, token, _} = Auth.create_session(admin)
    s = mounted({:require_role, ["admin"]}, token)

    :ok = Mem.update_user!(admin, roles: ["viewer"])
    assert {:halt, gone} = Live.handle_guard(:macaw_auth_recheck, s)
    assert {:redirect, %{to: "/"}} = gone.redirected
  end

  @tag verifies: "live-recheck-step"
  test "the re-check sends a page whose session now owes a step to that step" do
    {user, _} = Mem.user!(%{})
    {:ok, token, _} = Auth.create_session(user)
    s = mounted(:require_authenticated, token)

    :ok = Mem.update_user!(user, must_change_password: true)
    assert {:halt, gone} = Live.handle_guard(:macaw_auth_recheck, s)
    assert {:redirect, %{to: "/password"}} = gone.redirected
  end

  @tag verifies: "live-recheck-no-touch"
  test "a page's re-checks never move its session's last use" do
    {user, _} = Mem.user!(%{})
    {:ok, token, user_session} = Auth.create_session(user)
    s = mounted(:require_authenticated, token)
    # Long enough unused that a touching look-up would record the use.
    :ok = Mem.age_session!(user_session.id, 1_000)
    {:ok, _, before} = Auth.fetch_by_id(user_session.id, touch: false)

    assert {:halt, kept} = Live.handle_guard(:macaw_auth_recheck, s)
    assert {:halt, _} = Live.handle_guard(:macaw_auth_recheck, kept)

    {:ok, _, later} = Auth.fetch_by_id(user_session.id, touch: false)
    assert later.last_used_at == before.last_used_at
  end

  @tag verifies: "live-other-messages"
  test "other messages pass through" do
    s = socket()
    assert Live.handle_guard(:something_else, s) == {:cont, s}
  end

  describe "{:authorize, action}" do
    setup do
      on_exit(fn -> Application.delete_env(:macaw_auth, :authorizer) end)
    end

    defp authorize_mount(hook, params, token),
      do: Live.on_mount(hook, params, session(token), socket())

    @tag verifies: "live-authorize-closed"
    test "closed by default: with no authorizer, even an admin is sent home" do
      Application.delete_env(:macaw_auth, :authorizer)
      {admin, _} = Mem.user!(%{roles: ["admin"]})
      {:ok, token, _} = Auth.create_session(admin)
      assert {:halt, s} = authorize_mount({:authorize, :manage}, %{}, token)
      assert {:redirect, %{to: "/"}} = s.redirected
    end

    @tag verifies: "live-authorize"
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

    @tag verifies: "live-authorize-resource"
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

    @tag verifies: "live-authorize-order"
    test "a signed-out visitor is sent to sign in, and a session owing a step to the step" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      assert {:halt, s} = Live.on_mount({:authorize, :manage}, %{}, %{}, socket())
      assert {:redirect, %{to: "/login"}} = s.redirected

      {admin, _} = Mem.user!(%{roles: ["admin"], must_change_password: true})
      {:ok, token, _} = Auth.create_session(admin)
      assert {:halt, s} = authorize_mount({:authorize, :manage}, %{}, token)
      assert {:redirect, %{to: "/password"}} = s.redirected
    end

    @tag verifies: "live-recheck-authorize"
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

    @tag verifies: "live-recheck-authorize-resource"
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

    @tag verifies: "live-authorize-raises"
    test "an authorizer that raises crashes the mount" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      {user, _} = Mem.user!(%{})
      {:ok, token, _} = Auth.create_session(user)

      assert_raise RuntimeError, "the authorizer failed", fn ->
        authorize_mount({:authorize, :explode}, %{}, token)
      end
    end
  end

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 03" do
    setup do
      on_exit(fn ->
        Application.delete_env(:macaw_auth, :authorizer)
        Application.delete_env(:macaw_auth, :revalidate_ms)
        Application.delete_env(:macaw_auth, :endpoint)
      end)
    end

    # A socket as a connected page's: a transport process and a lifecycle to hook.
    defp connected_socket,
      do: %{
        socket()
        | transport_pid: self(),
          private: %{lifecycle: %Phoenix.LiveView.Lifecycle{}}
      }

    defp guard_hooks(socket),
      do: for(%{id: id} <- socket.private.lifecycle.handle_info, do: id)

    @tag verifies: "auth-live"
    test "no mount, by any hook, moves the session's last use; the token is read at token_key/0" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      {admin, _} = Mem.user!(%{roles: ["admin"]})
      {:ok, token, user_session} = Auth.create_session(admin)
      :ok = Mem.age_session!(user_session.id, 1_000)
      {:ok, _, before} = Auth.fetch_by_id(user_session.id, touch: false)

      for hook <- [
            :mount_current_user,
            :require_authenticated,
            {:require_role, ["admin"]},
            {:authorize, :manage}
          ] do
        assert {:cont, s} =
                 Live.on_mount(hook, %{}, %{Macaw.Auth.Plug.token_key() => token}, socket())

        assert s.assigns.current_user.id == admin.id
      end

      {:ok, _, later} = Auth.fetch_by_id(user_session.id, touch: false)
      assert later.last_used_at == before.last_used_at

      # Under any other key, the token isn't the session's.
      assert {:halt, _} =
               Live.on_mount(:require_authenticated, %{}, %{"token" => token}, socket())
    end

    @tag verifies: "auth-live-mount-user"
    test ":mount_current_user never redirects or guards: a refused token or an owed step still continues" do
      {user, _} = Mem.user!(%{})
      {:ok, token, user_session} = Auth.create_session(user)
      :ok = Auth.revoke(user_session.id)

      assert {:cont, s} = Live.on_mount(:mount_current_user, %{}, session(token), socket())
      assert {s.assigns.current_user, s.assigns.current_session} == {nil, nil}
      assert s.redirected == nil

      {enrolled, _} = Mem.user!(%{second_factor: :enrolled})
      {:ok, token, _} = Auth.create_session(enrolled)
      s = %{connected_socket() | assigns: %{__changed__: %{}, flash: %{}}}

      assert {:cont, s} = Live.on_mount(:mount_current_user, %{}, session(token), s)
      assert s.assigns.current_user.id == enrolled.id
      assert s.redirected == nil
      refute Map.has_key?(s.assigns, :pending_step)
      assert guard_hooks(s) == []
      refute_received :macaw_auth_recheck
    end

    def tracked_resource(params, _socket) do
      send(self(), {:resource_asked, params})
      Macaw.Auth.Test.Authorizer.post(params, nil)
    end

    @tag verifies: "auth-live-guarded"
    test "the guards' order, full-page redirects without a flash, and the authorize hook's options" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      hook = {:authorize, :edit, resource: &__MODULE__.tracked_resource/2}

      # A redirect is a full page load, 302 on the static render.
      assert {:halt, s} = Live.on_mount(hook, %{"owner" => "1"}, %{}, socket())
      assert s.redirected == {:redirect, %{to: "/login", status: 302}}

      # The resource function is asked only of a session that passed 1 and 2.
      {owing, _} = Mem.user!(%{must_change_password: true})
      {:ok, token, _} = Auth.create_session(owing)
      params = %{"owner" => to_string(owing.id)}
      assert {:halt, s} = Live.on_mount(hook, params, session(token), socket())
      assert s.redirected == {:redirect, %{to: "/password", status: 302}}
      refute_received {:resource_asked, _}

      # Step before role: an owed step wins over a missing role.
      assert {:halt, s} =
               Live.on_mount({:require_role, ["admin"]}, %{}, session(token), socket())

      assert s.redirected == {:redirect, %{to: "/password", status: 302}}

      # Admitted: asked once, of the params; continue assigns user and session.
      {owner, _} = Mem.user!(%{})
      {:ok, token, owner_session} = Auth.create_session(owner)
      params = %{"owner" => to_string(owner.id)}
      assert {:cont, s} = Live.on_mount(hook, params, session(token), socket())
      assert_received {:resource_asked, ^params}
      refute_received {:resource_asked, _}
      assert s.assigns.current_session.id == owner_session.id

      # A refusal goes home without a flash, as a missing role does.
      {other, _} = Mem.user!(%{})
      {:ok, token, _} = Auth.create_session(other)
      assert {:halt, s} = Live.on_mount(hook, params, session(token), socket())
      assert s.redirected == {:redirect, %{to: "/", status: 302}}
      assert s.assigns.flash == %{}

      assert {:halt, s} =
               Live.on_mount({:require_role, ["admin"]}, %{}, session(token), socket())

      assert s.assigns.flash == %{}

      # Only :resource is an option.
      assert_raise ArgumentError, fn ->
        Live.on_mount({:authorize, :edit, scope: :all}, params, session(token), socket())
      end
    end

    @tag verifies: "auth-live-guard"
    test "a connected mount subscribes, schedules the re-check and hooks handle_info; a static one doesn't" do
      Application.put_env(:macaw_auth, :revalidate_ms, 10)
      {user, _} = Mem.user!(%{})
      {:ok, token, _} = Auth.create_session(user)
      {:ok, _, other} = Auth.create_session(user)

      assert {:cont, static} =
               Live.on_mount(:require_authenticated, %{}, session(token), socket())

      refute Map.has_key?(static.private, :lifecycle)
      :ok = Auth.revoke(other.id)
      refute_receive {:sessions_revoked, _}
      refute_received :macaw_auth_recheck

      {:ok, _, another} = Auth.create_session(user)

      assert {:cont, live} =
               Live.on_mount(:require_authenticated, %{}, session(token), connected_socket())

      assert guard_hooks(live) == [:macaw_auth_guard]
      assert_receive :macaw_auth_recheck
      :ok = Auth.revoke(another.id)
      assert_receive {:sessions_revoked, [id]}
      assert id == another.id

      # Without :revalidate_ms, the re-check waits a minute, not moments.
      Application.delete_env(:macaw_auth, :revalidate_ms)
      {:cont, _} = Live.on_mount(:require_authenticated, %{}, session(token), connected_socket())
      refute_receive :macaw_auth_recheck, 200
    end

    @tag verifies: "auth-live-revoked"
    test "a revocation reaches a connected page with no endpoint configured; the page's handle_info never sees it" do
      Application.delete_env(:macaw_auth, :endpoint)
      Application.put_env(:macaw_auth, :revalidate_ms, 60_000)
      {user, _} = Mem.user!(%{})
      {:ok, token, own} = Auth.create_session(user)
      {:ok, _, other} = Auth.create_session(user)

      {:cont, s} = Live.on_mount(:require_authenticated, %{}, session(token), connected_socket())

      :ok = Auth.revoke(other.id)
      assert_receive {:sessions_revoked, ids}
      assert ids == [other.id]
      assert {:halt, stays} = Live.handle_guard({:sessions_revoked, ids}, s)
      assert stays.redirected == nil
      assert stays.assigns.current_session.id == own.id

      :ok = Auth.revoke(own.id)
      assert_receive {:sessions_revoked, ids}
      assert {:halt, gone} = Live.handle_guard({:sessions_revoked, ids}, s)
      assert {:redirect, %{to: "/login"}} = gone.redirected
    end

    @tag verifies: "auth-live-recheck"
    test "the re-check keeps the mount's guard, reassigns the user, schedules the next, and stops on a redirect" do
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      Application.put_env(:macaw_auth, :revalidate_ms, 0)
      {user, _} = Mem.user!(%{roles: ["admin"]})
      {:ok, token, user_session} = Auth.create_session(user)

      assert mounted(:require_authenticated, token).private.macaw_auth_guard == :any

      assert mounted({:require_role, ["admin"]}, token).private.macaw_auth_guard ==
               {:roles, ["admin"]}

      hook = {:authorize, :edit, resource: &__MODULE__.tracked_resource/2}
      params = %{"owner" => to_string(user.id)}
      {:cont, s} = Live.on_mount(hook, params, session(token), socket())
      assert s.private.macaw_auth_guard == {:authorize, :edit, %{owner_id: user.id}}
      assert_received {:resource_asked, _}

      # Kept: the resource function isn't asked again, the refreshed user is
      # assigned, and the next re-check is scheduled.
      :ok = Mem.update_user!(user, display_name: "Renamed")
      assert {:halt, kept} = Live.handle_guard(:macaw_auth_recheck, s)
      refute_received {:resource_asked, _}
      assert kept.assigns.current_user.display_name == "Renamed"
      assert kept.assigns.current_session.id == user_session.id
      assert_receive :macaw_auth_recheck

      # Expired: gone to sign in, and no re-check follows.
      :ok = Mem.age_session!(user_session.id, 4_000)
      assert {:halt, gone} = Live.handle_guard(:macaw_auth_recheck, kept)
      assert {:redirect, %{to: "/login"}} = gone.redirected
      refute_receive :macaw_auth_recheck

      # A disabled user's page is gone too.
      {other, _} = Mem.user!(%{})
      {:ok, token, _} = Auth.create_session(other)
      s = mounted(:require_authenticated, token)
      :ok = Mem.disable!(other)
      assert {:halt, gone} = Live.handle_guard(:macaw_auth_recheck, s)
      assert {:redirect, %{to: "/login"}} = gone.redirected
    end

    @tag verifies: "auth-live-other"
    test "any message but the guard's continues untouched to the page" do
      s = socket()

      for message <- [
            {:sessions_revoked_elsewhere, [1]},
            "text",
            {:macaw_auth_recheck, :later},
            42
          ],
          do: assert(Live.handle_guard(message, s) == {:cont, s})
    end
  end
end
