defmodule Macaw.Auth.AnnounceTest do
  use ExUnit.Case, async: false

  alias Macaw.Auth

  test "announcing revoked sessions reaches subscribers; announcing none is silent" do
    :ok = Auth.subscribe("announce-user")

    :ok = Auth.announce_revoked("announce-user", [:a, :b])
    assert_receive {:sessions_revoked, [:a, :b]}

    :ok = Auth.announce_revoked("announce-user", [])
    refute_receive {:sessions_revoked, _}
  end

  describe "with an endpoint configured" do
    alias Macaw.Auth.Test.FakeEndpoint
    alias Macaw.Auth.Test.MemoryBackend, as: Mem

    setup do
      FakeEndpoint.listen()
      Application.put_env(:macaw_auth, :endpoint, FakeEndpoint)
      on_exit(fn -> Application.delete_env(:macaw_auth, :endpoint) end)
      :ok
    end

    test "announcing revoked sessions also disconnects each one's LiveView sockets" do
      :ok = Auth.announce_revoked("announce-user", [:a, :b])

      for id <- [:a, :b] do
        topic = Auth.live_socket_id(id)
        assert_receive {:endpoint_broadcast, ^topic, "disconnect", %{}}
      end

      :ok = Auth.announce_revoked("announce-user", [])
      refute_receive {:endpoint_broadcast, _, _, _}
    end

    test "revoke/2 disconnects the sockets of every session it ended" do
      Application.put_env(:macaw_auth, :backend, Mem)
      Mem.reset!()
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
    end
  end

  test "without an endpoint, announcing broadcasts nothing beyond the subscribers" do
    Macaw.Auth.Test.FakeEndpoint.listen()
    Application.delete_env(:macaw_auth, :endpoint)
    :ok = Auth.announce_revoked("announce-user", [:a])
    refute_receive {:endpoint_broadcast, _, _, _}
  end

  test "a session's live_socket_id" do
    assert Auth.live_socket_id(42) == "macaw_auth_sessions:42"
  end

  test "only the named user's pages hear it" do
    :ok = Auth.subscribe("someone")
    :ok = Auth.announce_revoked("someone-else", [:x])
    refute_receive {:sessions_revoked, _}
  end
end
