defmodule Macaw.Auth.AnnounceTest do
  use ExUnit.Case, async: false

  alias Macaw.Auth
  alias Macaw.Auth.Test.FakeEndpoint
  alias Macaw.Auth.Test.MemoryBackend, as: Mem

  setup do
    Application.put_env(:macaw_auth, :backend, Mem)
    Mem.reset!()
    :ok
  end

  # A page of another user: forwards what it hears to the test.
  defp page_of(user_id) do
    test = self()

    pid =
      spawn_link(fn ->
        :ok = Auth.subscribe(user_id)
        send(test, :subscribed)

        receive do
          message -> send(test, {:other_page, message})
        end
      end)

    assert_receive :subscribed
    pid
  end

  @tag verifies: "announce-revoked"
  test "announcing revoked sessions reaches the user's subscribers only; announcing none is silent" do
    :ok = Auth.subscribe("announce-user")
    page_of("announce-other-user")

    :ok = Auth.announce_revoked("announce-user", [:a, :b])
    assert_receive {:sessions_revoked, [:a, :b]}

    :ok = Auth.announce_revoked("announce-user", [])
    refute_receive {:sessions_revoked, _}
    refute_received {:other_page, _}
  end

  @tag verifies: "revoke-announces"
  test "revoke/2 tells the user's subscriber the session it ended, and nobody when it ended none" do
    {user, _} = Mem.user!(%{})
    {:ok, _, session} = Auth.create_session(user)
    :ok = Auth.subscribe(user.id)

    :ok = Auth.revoke(session.id)
    assert_receive {:sessions_revoked, [id]}
    assert id == session.id

    :ok = Auth.revoke({:user, user.id})
    refute_receive {:sessions_revoked, _}
  end

  @tag verifies: "revoke-disconnects-sockets"
  test "with an endpoint, each ended session's sockets are disconnected; without one, nothing is broadcast" do
    FakeEndpoint.listen()
    Application.put_env(:macaw_auth, :endpoint, FakeEndpoint)
    on_exit(fn -> Application.delete_env(:macaw_auth, :endpoint) end)

    {user, _} = Mem.user!(%{})
    {:ok, _, kept} = Auth.create_session(user)
    {:ok, _, gone1} = Auth.create_session(user)
    {:ok, _, gone2} = Auth.create_session(user)

    :ok = Auth.revoke({:user, user.id}, except: kept.id)

    for s <- [gone1, gone2] do
      topic = "macaw_auth_sessions:#{s.id}"
      assert_receive {:endpoint_broadcast, ^topic, "disconnect", %{}}
    end

    kept_topic = Auth.live_socket_id(kept.id)
    refute_receive {:endpoint_broadcast, ^kept_topic, _, _}

    :ok = Auth.announce_revoked("announce-user", [:a, :b])

    for id <- [:a, :b] do
      topic = Auth.live_socket_id(id)
      assert_receive {:endpoint_broadcast, ^topic, "disconnect", %{}}
    end

    :ok = Auth.announce_revoked("announce-user", [])
    refute_receive {:endpoint_broadcast, _, _, _}

    Application.delete_env(:macaw_auth, :endpoint)
    {:ok, _, other} = Auth.create_session(user)
    :ok = Auth.revoke(other.id)
    :ok = Auth.announce_revoked("announce-user", [:a])
    refute_receive {:endpoint_broadcast, _, _, _}
  end

  @tag verifies: "live-socket-id"
  test "a session's live_socket_id" do
    assert Auth.live_socket_id(42) == "macaw_auth_sessions:42"
  end
end
