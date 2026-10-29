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

  @tag verifies: "ldap-direct-bind"
  test "direct bind, as on the NAS: groups give the roles, required_group admits" do
    assert {:ok, alice} = auth(nas(), "alice", "alice-password")
    assert %{username: "alice", roles: ["admin"], display_name: "Alice Admin"} = alice
    assert alice.extra["email"] == "alice@example.test"
    assert alice.extra["dn"] == "uid=alice,cn=users,#{@base}"
    assert alice.external_id =~ ~r/^[0-9a-f-]{36}$/
    refute Map.has_key?(alice.extra, "external_id")

    assert {:ok, %{roles: ["viewer"]}} = auth(nas(), "bob", "bob-password")
    assert {:error, :not_in_group} = auth(nas(), "carol", "carol-password")
    assert {:error, :invalid_credentials} = auth(nas(), "alice", "wrong")
    assert {:error, :empty_password} = auth(nas(), "alice", "")
    assert {:error, :invalid_credentials} = auth(nas(), "nobody", "x")
    assert {:error, :no_role} = auth(nas(%{default_role: nil}), "bob", "bob-password")
    assert {:error, :invalid_username} = auth(nas(), "Bad User", "bad-password")
  end

  @tag verifies: "ldap-roles"
  test "every mapped role of every group, in the mapping's terms" do
    mapping = %{"macaw-admin" => ["admin", "operator"], "macaw" => "viewer"}
    assert {:ok, %{roles: roles}} = auth(nas(%{role_mapping: mapping}), "alice", "alice-password")
    assert Enum.sort(roles) == ["admin", "operator", "viewer"]
  end

  @tag verifies: "ldap-injection"
  test "a username can't change the DN or widen a search" do
    assert {:error, :invalid_credentials} = auth(nas(), "alice,cn=users", "alice-password")
    assert {:error, :invalid_credentials} = auth(nas(), "alice;x", "alice-password")
    assert {:error, :user_not_found} = auth(search(), "*", "alice-password")
    assert {:error, :user_not_found} = auth(search(), "a*)(uid=*", "alice-password")
    assert {:error, :user_not_found} = auth(search(), "alice)(|(uid=*", "alice-password")
  end

  @tag verifies: "ldap-search"
  test "search mode, anonymous search, ambiguity and a refused service bind" do
    assert {:ok, %{roles: ["admin"]}} = auth(search(), "alice", "alice-password")
    assert {:error, :invalid_credentials} = auth(search(), "alice", "wrong")
    assert {:error, :ambiguous_user} = auth(search(), "dave", "dave-password")

    anonymous = search(%{search: %{base_dn: "cn=users,#{@base}"}, allow_anonymous_search: true})
    assert {:ok, %{roles: ["viewer"]}} = auth(anonymous, "bob", "bob-password")

    capture_log(fn ->
      bad =
        search(%{search: %{base_dn: @base, bind_dn: "cn=svc,#{@base}", bind_password: "wrong"}})

      assert {:error, :search_failed} = auth(bad, "alice", "alice-password")
    end)
  end

  @tag verifies: "ldap-group-account-fixture"
  test "direct bind with a groups account: the groups read as the service account" do
    account = fn password ->
      nas(%{
        groups: %{
          base_dn: "cn=groups,#{@base}",
          member_attr: "memberUid",
          bind_dn: "cn=svc,#{@base}",
          bind_password: password
        }
      })
    end

    assert {:ok, %{roles: ["admin"]}} =
             auth(account.("svc-test-password"), "alice", "alice-password")

    assert {:ok, %{roles: ["viewer"]}} =
             auth(account.("svc-test-password"), "bob", "bob-password")

    assert {:error, :invalid_credentials} = auth(account.("svc-test-password"), "alice", "wrong")

    # The service bind is made: a wrong password for it fails the group search.
    log =
      capture_log(fn ->
        assert {:error, :group_search_failed} =
                 auth(account.("svc-wrong-secret"), "alice", "alice-password")
      end)

    assert log =~ "LDAP source nas: the group search failed"
    refute log =~ "svc-wrong-secret"
  end

  @tag verifies: "ldap-member-of"
  test "groups from memberOf" do
    member_of =
      nas(%{
        groups: %{from: :member_of},
        required_group: "staff",
        role_mapping: %{"staff" => "admin"}
      })

    assert {:ok, %{roles: ["admin"]}} = auth(member_of, "alice", "alice-password")
    assert {:error, :not_in_group} = auth(member_of, "bob", "bob-password")
  end

  @tag verifies: "ldap-tls"
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

  @tag verifies: "ldap-plaintext"
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

    @tag verifies: "ldap-chain-provision"
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

    @tag verifies: "provision-no-takeover-ldap"
    test "the directory's owner never becomes the local owner" do
      local_user!("owner", "local owner password")

      for sources <- [[local(), nas()], [nas(), local()]] do
        chain(sources)
        assert sign_in("owner", "owner-password") == {:error, :invalid_credentials}
        assert {:ok, %User{source: "local"}} = sign_in("owner", "local owner password")
      end

      assert Repo.aggregate(UserRecord, :count) == 1
    end

    @tag verifies: "ldap-chain-unreachable"
    test "an unreachable directory never locks a local user out" do
      local_user!("root", "local admin password")

      capture_log(fn ->
        chain([nas(%{port: 1}), local()])
        assert {:ok, %User{username: "root"}} = sign_in("root", "local admin password")
        assert sign_in("alice", "alice-password") == {:error, :invalid_credentials}
      end)
    end

    @tag verifies: "ldap-chain-search-final"
    test "search mode: a wrong password at a found entry is final" do
      local_user!("bob", "local bob password")
      chain([search(), local()])
      assert sign_in("bob", "local bob password") == {:error, :invalid_credentials}
    end
  end

  @tag verifies: "ldap-diagnose"
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

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 07" do
    @tag verifies: "auth-ldap-connect"
    test "failures told apart, TLS verified, each failure logged by name and never a password" do
      # LDAPS to a port where nothing listens is unreachable, not a TLS failure.
      ldaps_down = nas(%{ssl: true, starttls: false, port: 1})

      log =
        capture_log(fn ->
          assert {:error, :connect_failed} = auth(ldaps_down, "bob", "bob-password")
          assert {:error, :connect_failed} = auth(nas(%{port: 1}), "bob", "bob-password")
          assert {:error, :tls_failed} = auth(nas(%{cacertfile: nil}), "bob", "bob-password")

          bad_service =
            search(%{
              search: %{
                base_dn: @base,
                bind_dn: "cn=svc,#{@base}",
                bind_password: "svc-wrong-secret"
              }
            })

          assert {:error, :search_failed} = auth(bad_service, "alice", "alice-password")
        end)

      assert log =~ "LDAP source nas: the directory could not be reached (#{host()}:1)"
      assert log =~ "LDAP source nas: TLS failed: the certificate did not verify"
      assert log =~ "(#{host()}:#{port()})"
      assert log =~ "LDAP source nas: the search failed"
      refute log =~ "svc-wrong-secret"
      refute log =~ "alice-password"
      refute log =~ "bob-password"

      # The chain and the hostname are verified, with SNI and depth 3, against
      # cacertfile or the system's CAs; verify_peer: false turns it off.
      options = Ldap.tls_options(nas())
      assert options[:verify] == :verify_peer
      assert options[:server_name_indication] == String.to_charlist(host())
      assert options[:depth] == 3
      assert options[:cacertfile] == String.to_charlist(@ca)
      assert [_ | _] = Ldap.tls_options(nas(%{cacertfile: nil}))[:cacerts]
      assert [_ | _] = options[:customize_hostname_check][:match_fun] |> List.wrap()
      assert Ldap.tls_options(nas(%{verify_peer: false})) == [verify: :verify_none]

      assert {"TLS", :ok, "StartTLS, certificate NOT verified (verify_peer: false)"} =
               Enum.at(
                 Ldap.diagnose(
                   nas(%{cacertfile: nil, verify_peer: false}),
                   "bob",
                   "bob-password"
                 ),
                 1
               )
    end

    @tag verifies: "auth-ldap-flow"
    test "no password, a trimmed username, the directory's spelling, the entry's attributes" do
      # Refused before connecting: even an unreachable directory says :empty_password.
      assert {:error, :empty_password} = auth(nas(%{port: 1}), "bob", nil)

      assert {:ok, %{username: "bob"}} = auth(nas(), "  bob  ", "bob-password")
      assert {:error, :user_not_found} = auth(nas(), "", "bob-password")
      assert {:error, :user_not_found} = auth(nas(), "   ", "bob-password")

      # A search base that doesn't exist is no entry.
      nowhere =
        search(%{
          search: %{
            base_dn: "ou=nowhere,#{@base}",
            bind_dn: "cn=svc,#{@base}",
            bind_password: "svc-test-password"
          }
        })

      assert {:error, :user_not_found} = auth(nowhere, "alice", "alice-password")

      # The username is the directory's spelling, not what was typed.
      assert {:ok, %{username: "alice"}} = auth(nas(), "ALICE", "alice-password")

      assert {:ok, alice} = auth(nas(), "alice", "alice-password")

      assert Enum.sort(alice.extra["groups"]) == [
               "cn=macaw,cn=groups,#{@base}",
               "cn=macaw-admin,cn=groups,#{@base}"
             ]

      # Without the id attribute on the entry, the external id is the DN.
      assert {:ok, %{external_id: "uid=alice,cn=users," <> _}} =
               auth(nas(%{id_attr: "employeeNumber"}), "alice", "alice-password")

      # A non-ASCII password goes as its UTF-8 bytes: refused as any wrong one.
      assert {:error, :invalid_credentials} = auth(nas(), "alice", "pässwörd-✓")

      # The connection is closed after, whatever the outcome: each connection
      # process the sign-in started ends.
      for {name, password, outcome} <- [
            {"bob", "bob-password", :ok},
            {"carol", "carol-password", :error},
            {"alice", "wrong", :error}
          ] do
        {:links, before} = Process.info(self(), :links)
        assert {^outcome, _} = auth(nas(), name, password)
        {:links, now} = Process.info(self(), :links)
        assert [_ | _] = connections = now -- before

        for pid <- connections do
          ref = Process.monitor(pid)
          assert_receive {:DOWN, ^ref, :process, ^pid, _}, 1000
        end
      end
    end

    @tag verifies: "auth-ldap-groups"
    test "groups by memberOf, by member DN, by memberUid as spelled; matched by DN or CN; roles once" do
      # memberOf, the required group named by its DN in another case.
      member_of =
        nas(%{
          groups: %{from: :member_of},
          required_group: "CN=STAFF,CN=GROUPS,DC=EXAMPLE,DC=TEST",
          role_mapping: %{"Staff" => "admin"}
        })

      assert {:ok, %{roles: ["admin"], extra: %{"groups" => ["cn=staff,cn=groups," <> _]}}} =
               auth(member_of, "alice", "alice-password")

      # groupOfNames: member holds the user's DN.
      by_member =
        nas(%{
          groups: %{base_dn: "cn=groups,#{@base}", member_attr: "member"},
          required_group: "staff",
          role_mapping: %{"staff" => "admin"}
        })

      assert {:ok, %{roles: ["admin"]}} = auth(by_member, "alice", "alice-password")
      assert {:error, :not_in_group} = auth(by_member, "bob", "bob-password")

      # posixGroup: memberUid holds the uid as the directory spells it, not as typed.
      assert {:ok, %{roles: ["admin"]}} = auth(nas(), "ALICE", "alice-password")

      # Every role every matching group maps to, each once; else the default.
      once = %{"macaw" => ["viewer", "admin"], "macaw-admin" => "admin"}
      assert {:ok, %{roles: roles}} = auth(nas(%{role_mapping: once}), "alice", "alice-password")
      assert Enum.sort(roles) == ["admin", "viewer"]

      unmapped = nas(%{role_mapping: %{"nothing" => "x"}, default_role: ["guest", "viewer"]})
      assert {:ok, %{roles: ["guest", "viewer"]}} = auth(unmapped, "bob", "bob-password")
    end

    @tag verifies: "auth-ldap-check"
    test "diagnose names each transport and search, and the task prints a line a step" do
      ldaps = nas(%{ssl: true, starttls: false, port: ldaps_port()})

      assert {"TLS", :ok, "LDAPS, certificate and hostname verified"} =
               Enum.at(Ldap.diagnose(ldaps, "bob", "bob-password"), 1)

      plain = nas(%{starttls: false, allow_plaintext: true})

      assert {"TLS", :ok, "plain LDAP: passwords are sent unencrypted (allow_plaintext: true)"} =
               Enum.at(Ldap.diagnose(plain, "bob", "bob-password"), 1)

      anonymous = search(%{search: %{base_dn: "cn=users,#{@base}"}, allow_anonymous_search: true})

      assert {"find the user's DN", :ok,
              "searched cn=users,#{@base} for (uid=bob) anonymously: DN uid=bob,cn=users," <> _} =
               Enum.at(Ldap.diagnose(anonymous, "bob", "bob-password"), 2)

      steps = Ldap.diagnose(nas(), "alice", "alice-password")
      assert {"connect", :ok, "#{host()}:#{port()} is reachable"} == hd(steps)
      assert {"username", :ok, "alice"} = Enum.at(steps, 5)
      assert {"required group", :ok, "member of macaw"} = Enum.at(steps, 7)

      # The task, against the configured source, the password from its variable.
      previous = Application.get_env(:macaw_auth, Macaw.Auth.Native)
      password = System.get_env("MACAW_AUTH_CHECK_PASSWORD")
      Mix.shell(Mix.Shell.Process)

      on_exit(fn ->
        Mix.shell(Mix.Shell.IO)
        Application.put_env(:macaw_auth, Macaw.Auth.Native, previous)

        if password,
          do: System.put_env("MACAW_AUTH_CHECK_PASSWORD", password),
          else: System.delete_env("MACAW_AUTH_CHECK_PASSWORD")
      end)

      Application.put_env(:macaw_auth, Macaw.Auth.Native,
        repo: Repo,
        sources: [
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
            role_mapping: %{"macaw-admin" => "admin"}
          }
        ]
      )

      assert {0, lines} = check_task(["nas", "alice"], "alice-password")
      assert length(lines) == 9
      assert "ok     connect: " <> _ = hd(lines)
      assert "ok     roles: admin" == List.last(lines)
      refute Enum.join(lines) =~ "alice-password"

      assert {1, lines} = check_task(["nas", "alice"], "nope")

      assert "FAILED bind as the user: the directory refused the password for that DN" ==
               List.last(lines)
    end
  end

  # Runs mix macaw_auth.ldap.check as Mix would: `{exit status, printed lines}`.
  defp check_task(argv, password) do
    System.put_env("MACAW_AUTH_CHECK_PASSWORD", password)
    Process.flag(:trap_exit, true)
    running = Task.async(fn -> Mix.Tasks.MacawAuth.Ldap.Check.run(argv) end)

    status =
      case Task.yield(running, 10_000) do
        {:ok, _} -> 0
        {:exit, {:shutdown, status}} -> status
      end

    {status, shell_lines()}
  end

  defp shell_lines do
    receive do
      {:mix_shell, :info, [line]} -> [line | shell_lines()]
    after
      0 -> []
    end
  end
end
