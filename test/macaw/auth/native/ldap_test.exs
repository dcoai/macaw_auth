defmodule Macaw.Auth.Native.Source.LdapTest do
  @moduledoc """
  Directory sign-in against the OpenLDAP fixture directory (macaw's
  ci/tools/ldap image; users under cn=users, posixGroup groups with
  memberUid under cn=groups, alice also in the groupOfNames `staff`).
  Runs when MACAW_AUTH_LDAP_HOST names it (CI's `ldap` service):

      docker run -d --rm --name macaw-auth-ldap -p 127.0.0.1:3391:389 \\
        -p 127.0.0.1:3638:636 macaw-ldap-test
      MACAW_AUTH_LDAP_HOST=localhost MACAW_AUTH_LDAP_PORT=3391 \\
        MACAW_AUTH_LDAPS_PORT=3638 mix test --include ldap
  """

  use Macaw.Auth.DataCase, async: false

  import ExUnit.CaptureLog

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Config, UserRecord}
  alias Macaw.Auth.Native.Source.Ldap
  alias Macaw.Auth.User

  @moduletag :ldap

  @ca Path.expand("../../../fixtures/ldap/ca.pem", __DIR__)
  @base "dc=example,dc=test"

  defp host, do: System.fetch_env!("MACAW_AUTH_LDAP_HOST")
  defp port, do: String.to_integer(System.get_env("MACAW_AUTH_LDAP_PORT", "389"))
  defp ldaps_port, do: String.to_integer(System.get_env("MACAW_AUTH_LDAPS_PORT", "636"))

  # As the owner's NAS: direct bind over StartTLS with the test CA.
  defp nas(overrides \\ %{}) do
    %{
      type: :ldap,
      name: "nas",
      host: host(),
      port: port(),
      ssl: false,
      starttls: true,
      cacertfile: @ca,
      user_dn_template: "uid={username},cn=users,#{@base}",
      groups: %{base_dn: "cn=groups,#{@base}", member_attr: "memberUid"},
      required_group: "macaw",
      role_mapping: %{"macaw-admin" => "admin"},
      default_role: "viewer"
    }
    |> Map.merge(overrides)
    |> source()
  end

  defp search(overrides \\ %{}) do
    nas(
      Map.merge(
        %{
          user_dn_template: nil,
          search: %{
            base_dn: @base,
            bind_dn: "cn=svc,#{@base}",
            bind_password: "svc-test-password"
          }
        },
        overrides
      )
    )
  end

  defp source(map) do
    config = map |> Map.reject(fn {_k, v} -> v == nil end)
    {:ok, source} = Ldap.parse(config, [])
    source
  end

  defp auth(source, username, password), do: Ldap.authenticate(source, username, password, [])

  test "direct bind, as on the NAS: groups give the roles, required_group admits" do
    assert {:ok, alice} = auth(nas(), "alice", "alice-password")
    assert %{username: "alice", roles: ["admin"], display_name: "Alice Admin"} = alice
    assert alice.extra["email"] == "alice@example.test"
    assert alice.extra["dn"] == "uid=alice,cn=users,#{@base}"
    assert alice.extra["external_id"] =~ ~r/^[0-9a-f-]{36}$/

    assert {:ok, %{roles: ["viewer"]}} = auth(nas(), "bob", "bob-password")
    assert {:error, :not_in_group} = auth(nas(), "carol", "carol-password")
    assert {:error, :invalid_credentials} = auth(nas(), "alice", "wrong")
    assert {:error, :empty_password} = auth(nas(), "alice", "")
    assert {:error, :invalid_credentials} = auth(nas(), "nobody", "x")
    assert {:error, :no_role} = auth(nas(%{default_role: nil}), "bob", "bob-password")
    assert {:error, :invalid_username} = auth(nas(), "Bad User", "bad-password")
  end

  test "every mapped role of every group, in the mapping's terms" do
    mapping = %{"macaw-admin" => ["admin", "operator"], "macaw" => "viewer"}
    assert {:ok, %{roles: roles}} = auth(nas(%{role_mapping: mapping}), "alice", "alice-password")
    assert Enum.sort(roles) == ["admin", "operator", "viewer"]
  end

  test "a username can't change the DN or widen a search" do
    assert {:error, :invalid_credentials} = auth(nas(), "alice,cn=users", "alice-password")
    assert {:error, :invalid_credentials} = auth(nas(), "alice;x", "alice-password")
    assert {:error, :user_not_found} = auth(search(), "*", "alice-password")
    assert {:error, :user_not_found} = auth(search(), "a*)(uid=*", "alice-password")
    assert {:error, :user_not_found} = auth(search(), "alice)(|(uid=*", "alice-password")
  end

  test "search mode, anonymous search, ambiguity and memberOf" do
    assert {:ok, %{roles: ["admin"]}} = auth(search(), "alice", "alice-password")
    assert {:error, :invalid_credentials} = auth(search(), "alice", "wrong")
    assert {:error, :ambiguous_user} = auth(search(), "dave", "dave-password")

    anonymous = search(%{search: %{base_dn: "cn=users,#{@base}"}, allow_anonymous_search: true})
    assert {:ok, %{roles: ["viewer"]}} = auth(anonymous, "bob", "bob-password")

    member_of =
      nas(%{
        groups: %{from: :member_of},
        required_group: "staff",
        role_mapping: %{"staff" => "admin"}
      })

    assert {:ok, %{roles: ["admin"]}} = auth(member_of, "alice", "alice-password")
    assert {:error, :not_in_group} = auth(member_of, "bob", "bob-password")

    capture_log(fn ->
      bad =
        search(%{search: %{base_dn: @base, bind_dn: "cn=svc,#{@base}", bind_password: "wrong"}})

      assert {:error, :search_failed} = auth(bad, "alice", "alice-password")
    end)
  end

  test "LDAPS and StartTLS verify the certificate and the hostname" do
    ldaps = nas(%{ssl: true, starttls: false, port: ldaps_port()})
    assert {:ok, _} = auth(ldaps, "bob", "bob-password")

    capture_log(fn ->
      # The test certificate names `ldap` and `localhost`, not the address.
      {:ok, {a, b, c, d}} = :inet.getaddr(String.to_charlist(host()), :inet)
      by_ip = nas(%{ssl: true, starttls: false, port: ldaps_port(), host: "#{a}.#{b}.#{c}.#{d}"})
      assert {:error, :tls_failed} = auth(by_ip, "bob", "bob-password")

      untrusted = nas(%{cacertfile: nil})
      assert {:error, :tls_failed} = auth(untrusted, "bob", "bob-password")

      assert {:error, :connect_failed} = auth(nas(%{port: 1}), "bob", "bob-password")
    end)

    assert {:ok, _} = auth(nas(%{cacertfile: nil, verify_peer: false}), "bob", "bob-password")
  end

  test "plaintext: refused unless allowed" do
    assert {:error, "sources[nas].ssl: is false" <> _} =
             Ldap.parse(
               %{
                 type: :ldap,
                 name: "nas",
                 host: host(),
                 port: port(),
                 ssl: false,
                 user_dn_template: "uid={username}"
               },
               []
             )

    # A source made without the configuration's check still won't bind in the clear.
    refused = %{nas() | starttls: false}
    assert {:error, :plaintext_refused} = auth(refused, "bob", "bob-password")
    refute Ldap.knows?(refused, :plaintext_refused)

    allowed = nas(%{starttls: false, allow_plaintext: true})
    assert {:ok, %{username: "bob"}} = auth(allowed, "bob", "bob-password")
  end

  describe "through the chain" do
    defp chain(sources), do: Config.put(%{Config.get() | sources: sources})

    defp local, do: hd(Config.get().sources)

    defp sign_in(username, password),
      do: Native.authenticate(%{username: username, password: password})

    test "a directory user is provisioned, and their roles follow the directory" do
      chain([local(), nas()])

      assert {:ok, %User{username: "alice", source: "nas", roles: ["admin"]} = alice} =
               sign_in("alice", "alice-password")

      assert %UserRecord{hashed_password: nil, source: "nas"} = Repo.get!(UserRecord, alice.id)
      assert {:ok, %User{id: id}} = sign_in("Alice", "alice-password")
      assert id == alice.id

      Repo.update_all(UserRecord, set: [roles: ["viewer"]])
      assert {:ok, %User{roles: ["admin"]}} = sign_in("alice", "alice-password")

      assert sign_in("alice", "wrong") == {:error, :invalid_credentials}
      assert sign_in("carol", "carol-password") == {:error, :invalid_credentials}
    end

    test "the directory's owner never becomes the local owner" do
      local_user!("owner", "local owner password")

      for sources <- [[local(), nas()], [nas(), local()]] do
        chain(sources)
        assert sign_in("owner", "owner-password") == {:error, :invalid_credentials}
        assert {:ok, %User{source: "local"}} = sign_in("owner", "local owner password")
      end

      assert Repo.aggregate(UserRecord, :count) == 1
    end

    test "an unreachable directory never locks a local user out" do
      local_user!("root", "local admin password")

      capture_log(fn ->
        chain([nas(%{port: 1}), local()])
        assert {:ok, %User{username: "root"}} = sign_in("root", "local admin password")
        assert sign_in("alice", "alice-password") == {:error, :invalid_credentials}
      end)
    end

    test "search mode: a wrong password at a found entry is final" do
      local_user!("bob", "local bob password")
      chain([search(), local()])
      assert sign_in("bob", "local bob password") == {:error, :invalid_credentials}
    end
  end

  test "diagnose says how each step went, without the password" do
    steps = Ldap.diagnose(nas(), "alice", "alice-password")

    assert Enum.map(steps, &elem(&1, 0)) == [
             "connect",
             "TLS",
             "find the user's DN",
             "bind as the user",
             "read attributes",
             "username",
             "groups",
             "required group",
             "roles"
           ]

    assert Enum.all?(steps, &(elem(&1, 1) == :ok))
    assert {"TLS", :ok, "StartTLS, certificate and hostname verified"} = Enum.at(steps, 1)
    assert {"roles", :ok, "admin"} = List.last(steps)
    refute inspect(steps) =~ "alice-password"

    assert [_, _, _, {"bind as the user", :error, "the directory refused" <> _}] =
             Ldap.diagnose(nas(), "alice", "nope")

    assert {"required group", :error, "the user is not in the required group"} =
             List.last(Ldap.diagnose(nas(), "carol", "carol-password"))

    assert {"find the user's DN", :ok, "searched " <> detail} =
             Enum.at(Ldap.diagnose(search(), "alice", "alice-password"), 2)

    assert detail =~ "(uid=alice) as cn=svc,#{@base}"

    capture_log(fn ->
      assert [{"connect", :ok, _}, {"TLS", :error, "TLS failed" <> _}] =
               Ldap.diagnose(nas(%{cacertfile: nil}), "alice", "alice-password")

      assert [{"connect", :error, _}] = Ldap.diagnose(nas(%{port: 1}), "alice", "alice-password")
    end)
  end
end
