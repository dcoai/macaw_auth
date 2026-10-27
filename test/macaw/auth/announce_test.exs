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

  test "only the named user's pages hear it" do
    :ok = Auth.subscribe("someone")
    :ok = Auth.announce_revoked("someone-else", [:x])
    refute_receive {:sessions_revoked, _}
  end
end
