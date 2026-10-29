defmodule Macaw.Auth.Native.Source.Ldap.GroupAccountTest do
  @moduledoc """
  A direct-bind source reading its groups as a service account
  (`groups.bind_dn`, `groups.bind_password`), its flow run against
  `Macaw.Auth.Test.FakeLdap`, a directory that lets only the service
  account read the groups. The fixture directory's own check is in
  `Macaw.Auth.Native.Source.LdapTest` (tagged `:ldap`).
  """

  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Macaw.Auth.Native.Source.Ldap
  alias Macaw.Auth.Test.FakeLdap

  @base "dc=example,dc=test"
  @alice "uid=alice,cn=users,#{@base}"
  @svc "cn=svc,#{@base}"
  @svc_password "svc-groups-secret"

  @directory %{
    binds: %{@alice => "alice-password", @svc => @svc_password},
    entries: %{@alice => %{"uid" => ["alice"], "cn" => ["Alice Admin"]}},
    groups: [
      %{dn: "cn=macaw,cn=groups,#{@base}", cn: "macaw", members: ["alice"]},
      %{dn: "cn=macaw-admin,cn=groups,#{@base}", cn: "macaw-admin", members: ["alice"]}
    ],
    group_readers: [@svc]
  }

  defp source(port, groups \\ %{}) do
    {:ok, source} =
      Ldap.parse(
        %{
          type: :ldap,
          name: "nas",
          host: "127.0.0.1",
          port: port,
          ssl: false,
          allow_plaintext: true,
          user_dn_template: "uid={username},cn=users,#{@base}",
          groups: Map.merge(%{base_dn: "cn=groups,#{@base}", member_attr: "memberUid"}, groups),
          required_group: "macaw",
          role_mapping: %{"macaw-admin" => "admin"}
        },
        env: %{"LDAP_GROUPS_PW" => @svc_password}
      )

    source
  end

  defp account(password \\ {:env, "LDAP_GROUPS_PW"}),
    do: %{bind_dn: @svc, bind_password: password}

  @tag verifies: "ldap-group-account"
  test "a direct bind with a groups account reads the groups as it, after the user's bind" do
    port = FakeLdap.start(@directory)

    assert {:ok, %{username: "alice", roles: ["admin"], extra: extra}} =
             Ldap.authenticate(source(port, account()), "alice", "alice-password", [])

    assert Enum.sort(extra["groups"]) == [
             "cn=macaw,cn=groups,#{@base}",
             "cn=macaw-admin,cn=groups,#{@base}"
           ]

    # The user binds first, then the service account, which the group search runs as.
    assert_received {:fake_ldap, :bind, @alice, "alice-password"}
    assert_received {:fake_ldap, :bind, @svc, @svc_password}
    assert_received {:fake_ldap, :group_search, @svc}

    # A wrong user password never reaches the service bind.
    assert {:error, :invalid_credentials} =
             Ldap.authenticate(source(port, account()), "alice", "wrong", [])

    assert_received {:fake_ldap, :bind, @alice, "wrong"}
    refute_received {:fake_ldap, :bind, @svc, _}
  end

  @tag verifies: "ldap-group-account-absent"
  test "without a groups account, the user's own bind reads the groups, as before" do
    restricted = FakeLdap.start(@directory)

    # The directory shows the user no groups: not in the required group.
    assert {:error, :not_in_group} =
             Ldap.authenticate(source(restricted), "alice", "alice-password", [])

    assert_received {:fake_ldap, :group_search, @alice}
    refute_received {:fake_ldap, :bind, @svc, _}

    open = FakeLdap.start(%{@directory | group_readers: :anyone})

    assert {:ok, %{roles: ["admin"]}} =
             Ldap.authenticate(source(open), "alice", "alice-password", [])

    assert_received {:fake_ldap, :group_search, @alice}
    refute_received {:fake_ldap, :bind, @svc, _}
  end

  @tag verifies: "ldap-group-account-secret"
  test "a refused service bind is :group_search_failed, and its password is in no answer or log" do
    port = FakeLdap.start(@directory)
    wrong = "svc-wrong-groups-secret"

    log =
      capture_log(fn ->
        assert {:error, :group_search_failed} =
                 Ldap.authenticate(source(port, account(wrong)), "alice", "alice-password", [])
      end)

    assert_received {:fake_ldap, :bind, @svc, ^wrong}
    refute_received {:fake_ldap, :group_search, _}

    log =
      log <>
        capture_log(fn ->
          assert {:ok, answer} =
                   Ldap.authenticate(source(port, account()), "alice", "alice-password", [])

          refute inspect(answer) =~ @svc_password
          refute inspect(source(port, account())) =~ @svc_password

          steps = Ldap.diagnose(source(port, account(wrong)), "alice", "alice-password")
          refute inspect(steps) =~ wrong
        end)

    assert log =~
             "LDAP source nas: the group search failed: the service bind was refused, or the directory refused the search (127.0.0.1:#{port})"

    refute log =~ wrong
    refute log =~ @svc_password
    refute log =~ "alice-password"
  end

  @tag verifies: "ldap-group-account-diagnose"
  test "diagnose binds for the groups as a step of its own, naming the account" do
    port = FakeLdap.start(@directory)
    steps = Ldap.diagnose(source(port, account()), "alice", "alice-password")

    assert Enum.map(steps, &elem(&1, 0)) == [
             "connect",
             "TLS",
             "find the user's DN",
             "bind as the user",
             "read attributes",
             "username",
             "bind for the groups",
             "groups",
             "required group",
             "roles"
           ]

    assert Enum.all?(steps, &(elem(&1, 1) == :ok))
    assert {"bind for the groups", :ok, "bound as #{@svc}"} = Enum.at(steps, 6)
    assert {"groups", :ok, groups} = Enum.at(steps, 7)
    assert groups =~ "macaw-admin"
    assert {"roles", :ok, "admin"} = List.last(steps)
    refute inspect(steps) =~ @svc_password
    refute inspect(steps) =~ "alice-password"

    capture_log(fn ->
      assert {"bind for the groups", :error, "the group search failed: the service bind" <> _} =
               List.last(Ldap.diagnose(source(port, account("nope")), "alice", "alice-password"))
    end)

    # Without the account the steps are as before: the groups, read as the user.
    plain = Ldap.diagnose(source(port), "alice", "alice-password")
    refute List.keymember?(plain, "bind for the groups", 0)
    assert {"required group", :error, _} = List.last(plain)
  end
end
