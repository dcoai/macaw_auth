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
    {:cont, s} = Live.on_mount(:mount_current_user, %{}, session(token), socket())

    assert {:halt, kept} = Live.handle_guard(:macaw_auth_recheck, s)
    assert kept.assigns.current_user.id == user.id

    :ok = Auth.revoke(session.id)
    assert {:halt, gone} = Live.handle_guard(:macaw_auth_recheck, s)
    assert {:redirect, %{to: "/login"}} = gone.redirected
  end

  test "other messages pass through" do
    assert {:cont, _} = Live.handle_guard(:something_else, socket())
  end
end
