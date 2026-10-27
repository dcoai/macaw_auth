defmodule Macaw.Auth.Native.Source.Ldap.OfflineTest do
  @moduledoc """
  What an LDAP source does without a directory: its configuration, whether
  it knows a user after a refusal, the explanations, group matching, and
  the check task's refusals. The flow itself runs against the fixture
  directory (`Macaw.Auth.Native.Source.LdapTest`, tagged `:ldap`).
  """

  # Not async: the check task reads the application environment and an
  # environment variable.
  use ExUnit.Case, async: false

  alias Macaw.Auth.Native.Source
  alias Macaw.Auth.Native.Source.Ldap
  alias Mix.Tasks.MacawAuth.Ldap.Check

  @ca Path.expand("../../../fixtures/ldap/ca.pem", __DIR__)
  @password_var "MACAW_AUTH_CHECK_PASSWORD"

  @nas %{
    type: :ldap,
    name: "nas",
    host: "ldap",
    port: 389,
    ssl: false,
    starttls: true,
    user_dn_template: "uid={username},cn=users,dc=example,dc=test"
  }

  @no_template Map.delete(@nas, :user_dn_template)

  defp parse(overrides), do: @nas |> Map.merge(overrides) |> Ldap.parse([])

  defp error(overrides) do
    {:error, message} = parse(overrides)
    message
  end

  defp search(search, overrides \\ %{}),
    do: @no_template |> Map.merge(overrides) |> Map.put(:search, search) |> Ldap.parse([])

  @tag verifies: "ldap-config-finding"
  test "an LDAP source can't be configured without exactly one way to find the user" do
    assert error(%{user_dn_template: nil}) ==
             "sources[nas].user_dn_template: or search is required"

    assert error(%{search: %{base_dn: "dc=x"}}) ==
             "sources[nas].search: can't be set with user_dn_template: choose one"

    assert error(%{user_dn_template: "uid=x,cn=users"}) ==
             "sources[nas].user_dn_template: must contain {username}"

    assert search(%{base_dn: "dc=x", filter: "(uid=x"}) ==
             {:error, "sources[nas].search.filter: must be an LDAP filter containing {username}"}

    assert search(%{base_dn: "dc=x"}) ==
             {:error,
              "sources[nas].search.bind_dn: and bind_password are required (or allow_anonymous_search: true)"}

    assert {:ok, %Ldap{search: %{base_dn: "dc=x", bind_dn: nil}, bind_password: nil}} =
             search(%{base_dn: "dc=x"}, %{allow_anonymous_search: true})
  end

  @tag verifies: "ldap-member-match"
  test "a group matches by its DN or its CN, ignoring case" do
    groups = [%{dn: "cn=Admins,dc=x", cn: "Admins"}]

    assert Ldap.member?(groups, "admins")
    assert Ldap.member?(groups, "CN=ADMINS,DC=X")
    refute Ldap.member?(groups, "staff")
  end

  describe "mix macaw_auth.ldap.check" do
    setup do
      previous = Application.get_env(:macaw_auth, Macaw.Auth.Native)
      password = System.get_env(@password_var)

      Application.put_env(:macaw_auth, Macaw.Auth.Native,
        repo: Macaw.Auth.Test.Repo,
        sources: [%{type: :password}, @nas, %{@nas | name: "corp"}]
      )

      on_exit(fn ->
        Application.put_env(:macaw_auth, Macaw.Auth.Native, previous)

        if password,
          do: System.put_env(@password_var, password),
          else: System.delete_env(@password_var)
      end)

      :ok
    end

    @tag verifies: "ldap-check-task"
    test "refuses without the password variable, an unknown source, or a username" do
      System.delete_env(@password_var)

      assert_raise Mix.Error,
                   "set MACAW_AUTH_CHECK_PASSWORD to the user's password (it is never read from argv)",
                   fn -> Check.run(["nas", "alice"]) end

      System.put_env(@password_var, "alice-password")

      assert_raise Mix.Error, ~s(no LDAP source "local"; configured: nas, corp), fn ->
        Check.run(["local", "alice"])
      end

      assert_raise Mix.Error, "usage: mix macaw_auth.ldap.check SOURCE USERNAME", fn ->
        Check.run(["nas"])
      end
    end

    @tag verifies: "auth-ldap-check"
    test "reads the configuration as the backend does, naming a fault" do
      System.put_env(@password_var, "alice-password")

      Application.put_env(:macaw_auth, Macaw.Auth.Native,
        repo: Macaw.Auth.Test.Repo,
        sources: [Map.put(@nas, :port, 0)]
      )

      assert_raise Mix.Error,
                   "config :macaw_auth, Macaw.Auth.Native: sources[nas].port: must be in 1..65535",
                   fn -> Check.run(["nas", "alice"]) end

      # It starts :ssl and :eldap itself, and a password among the
      # arguments is only ever a third argument: the usage, never a sign-in.
      assert Enum.all?(
               [:ssl, :eldap],
               &List.keymember?(Application.started_applications(), &1, 0)
             )

      assert_raise Mix.Error, "usage: mix macaw_auth.ldap.check SOURCE USERNAME", fn ->
        Check.run(["nas", "alice", "alice-password"])
      end

      # An empty password is the single step that refuses it, before any connection.
      assert Ldap.diagnose(source!(%{port: 1}), "alice", "") ==
               [{"password", :error, Ldap.explain(:empty_password)}]

      assert Ldap.diagnose(source!(%{port: 1}), "alice", nil) ==
               [{"password", :error, Ldap.explain(:empty_password)}]
    end
  end

  defp source!(overrides) do
    {:ok, source} = parse(overrides)
    source
  end

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 07" do
    @tag verifies: "auth-ldap"
    test "a sign-in source over OTP's :eldap, with no LDAP library" do
      # A sign-in source: every callback of Macaw.Auth.Native.Source.
      Code.ensure_loaded!(Ldap)

      for {fun, arity} <- Source.behaviour_info(:callbacks),
          do: assert(function_exported?(Ldap, fun, arity), "#{fun}/#{arity}")

      assert :eldap in Application.spec(:macaw_auth, :applications)

      for {app, _, _} <- Application.loaded_applications(),
          app != :eldap,
          do: refute(app |> Atom.to_string() |> String.contains?("ldap"), inspect(app))

      # The example source, with the fixture's CA for its certificate file.
      example = %{
        type: :ldap,
        name: "nas",
        host: "nas.example.test",
        port: 389,
        ssl: false,
        starttls: true,
        cacertfile: @ca,
        user_dn_template: "uid={username},cn=users,dc=example,dc=test",
        groups: %{base_dn: "cn=groups,dc=example,dc=test", member_attr: "memberUid"},
        required_group: "macaw",
        role_mapping: %{"macaw-admin" => "admin"},
        default_role: "viewer"
      }

      assert {:ok, %Ldap{name: "nas", required_group: "macaw", default_role: ["viewer"]}} =
               Ldap.parse(example, [])
    end

    @tag verifies: "auth-ldap-config"
    test "the connection keys, their defaults and checks, by source and key" do
      # Ldap.parse/2 is Config.parse/2.
      assert Ldap.parse(@nas, []) == Ldap.Config.parse(@nas, [])

      minimal = %{type: :ldap, name: "nas", host: "ldap", user_dn_template: "uid={username}"}

      assert {:ok,
              %Ldap{
                port: 636,
                ssl: true,
                starttls: false,
                allow_plaintext: false,
                verify_peer: true,
                cacertfile: nil,
                timeout_ms: 5000
              }} = Ldap.parse(minimal, [])

      assert error(%{host: nil}) == "sources[nas].host: is required"
      assert error(%{host: ""}) == "sources[nas].host: must be a non-empty string"

      for port <- [0, 65_536],
          do: assert(error(%{port: port}) == "sources[nas].port: must be in 1..65535")

      assert error(%{port: "389"}) == "sources[nas].port: must be an integer"
      assert {:ok, %Ldap{port: 65_535}} = parse(%{port: 65_535})

      for key <- [:ssl, :starttls, :allow_plaintext, :verify_peer],
          do: assert(error(%{key => "yes"}) == "sources[nas].#{key}: must be true or false")

      assert error(%{cacertfile: "/nonexistent.pem"}) ==
               "sources[nas].cacertfile: /nonexistent.pem is not a readable file"

      assert error(%{cacertfile: Path.dirname(@ca)}) =~ "is not a readable file"
      assert {:ok, %Ldap{cacertfile: @ca}} = parse(%{cacertfile: @ca})

      for timeout <- [0, 600_001],
          do:
            assert(
              error(%{timeout_ms: timeout}) == "sources[nas].timeout_ms: must be in 1..600000"
            )

      assert {:ok, %Ldap{timeout_ms: 600_000}} = parse(%{timeout_ms: 600_000})

      # The known keys are exactly these, plus type and name (required).
      assert error(%{hostname: "x"}) == "sources[nas].hostname: is not a known setting"
      assert error(%{"bind_dn" => "x"}) == "sources[nas].bind_dn: is not a known setting"

      assert {:error, "sources: a source of type ldap needs a name"} =
               Ldap.parse(Map.delete(@nas, :name), [])

      every =
        Map.merge(@nas, %{
          allow_plaintext: false,
          verify_peer: true,
          cacertfile: @ca,
          timeout_ms: 100,
          id_attr: "uid",
          username_attr: "uid",
          email_attr: "mail",
          display_name_attr: "cn",
          groups: %{from: :member_of},
          required_group: "staff",
          role_mapping: %{"staff" => "viewer"},
          default_role: "viewer"
        })

      assert {:ok, %Ldap{}} = Ldap.parse(every, [])

      assert {:ok, %Ldap{search: %{base_dn: "dc=x"}}} =
               search(%{base_dn: "dc=x"}, %{allow_anonymous_search: true})
    end

    @tag verifies: "auth-ldap-transport"
    test "ssl and starttls together, or neither unencrypted, are refused; the guard holds at connect" do
      assert error(%{ssl: true, starttls: true}) ==
               "sources[nas].starttls: can't be used with ssl: true"

      assert error(%{ssl: false, starttls: false}) ==
               "sources[nas].ssl: is false: set starttls: true, or allow_plaintext: true to send passwords unencrypted"

      assert {:ok, %Ldap{ssl: false, starttls: false, allow_plaintext: true}} =
               parse(%{starttls: false, allow_plaintext: true})

      assert {:ok, %Ldap{ssl: true, starttls: false}} = parse(%{ssl: true, starttls: false})

      # A struct made without the check never connects: refused before any
      # connection, even to a port where nothing listens.
      refused = %{source!(%{port: 1}) | starttls: false}
      assert Ldap.authenticate(refused, "bob", "bob-password", []) == {:error, :plaintext_refused}
    end

    @tag verifies: "auth-ldap-finding"
    test "a template or a search, and the service account set together" do
      assert {:ok,
              %Ldap{user_dn_template: "uid={username},cn=users,dc=example,dc=test", search: nil}} =
               Ldap.parse(@nas, [])

      assert {:ok, %Ldap{search: search, bind_password: "pw", user_dn_template: nil}} =
               search(%{base_dn: "dc=x", bind_dn: "cn=svc", bind_password: "pw"})

      assert search == %{base_dn: "dc=x", filter: "(uid={username})", bind_dn: "cn=svc"}

      assert {:ok, %Ldap{search: %{filter: "(&(objectClass=person)(mail={username}))"}}} =
               search(%{
                 base_dn: "dc=x",
                 filter: "(&(objectClass=person)(mail={username}))",
                 bind_dn: "cn=svc",
                 bind_password: "pw"
               })

      for half <- [%{bind_dn: "cn=svc"}, %{bind_password: "pw"}] do
        assert search(Map.put(half, :base_dn, "dc=x")) ==
                 {:error, "sources[nas].search.bind_dn: and bind_password must be set together"}
      end

      assert search(%{bind_dn: "cn=svc", bind_password: "pw"}) ==
               {:error, "sources[nas].search.base_dn: is required"}

      # bind_password is a secret: a reference resolved when the configuration is read.
      assert {:ok, %Ldap{bind_password: "from env"}} =
               @no_template
               |> Map.put(:search, %{
                 base_dn: "dc=x",
                 bind_dn: "cn=svc",
                 bind_password: {:env, "PW"}
               })
               |> Ldap.parse(env: %{"PW" => "from env"})

      # allow_anonymous_search is a top-level key, false by default, checked.
      assert search(%{base_dn: "dc=x"}, %{allow_anonymous_search: "yes"}) ==
               {:error, "sources[nas].allow_anonymous_search: must be true or false"}
    end

    @tag verifies: "auth-ldap-attributes"
    test "the four attributes, their defaults, each an attribute name" do
      assert {:ok,
              %Ldap{
                id_attr: "entryUUID",
                username_attr: "uid",
                email_attr: "mail",
                display_name_attr: "cn"
              }} = parse(%{})

      assert {:ok, %Ldap{id_attr: "objectGUID", username_attr: "sAMAccountName"}} =
               parse(%{id_attr: "objectGUID", username_attr: "sAMAccountName"})

      for key <- [:id_attr, :username_attr, :email_attr, :display_name_attr], bad <- ["", 1] do
        assert error(%{key => bad}) == "sources[nas].#{key}: must be an attribute name"
      end
    end

    @tag verifies: "auth-ldap-groups-config"
    test "no groups, memberOf, or a search by one of three member attributes" do
      assert {:ok, %Ldap{groups: nil}} = parse(%{})

      for from <- [:member_of, "member_of"] do
        assert {:ok, %Ldap{groups: %{from: :member_of}}} = parse(%{groups: %{from: from}})
      end

      assert {:ok, %Ldap{groups: %{from: :search, base_dn: "cn=g", member_attr: "member"}}} =
               parse(%{groups: %{base_dn: "cn=g"}})

      for attr <- ~w(member uniqueMember memberUid) do
        assert {:ok, %Ldap{groups: %{member_attr: ^attr}}} =
                 parse(%{groups: %{"base_dn" => "cn=g", "member_attr" => attr}})
      end

      assert error(%{groups: %{base_dn: "cn=g", member_attr: "owner"}}) ==
               "sources[nas].groups.member_attr: must be member, uniqueMember or memberUid"

      for bad <- [%{}, %{from: :other}, %{base_dn: ""}, "member_of"] do
        assert error(%{groups: bad}) ==
                 "sources[nas].groups: must be %{from: :member_of} or %{base_dn: …, member_attr: …}"
      end
    end

    @tag verifies: "auth-ldap-access"
    test "a required group, the mapping as a list of roles, a default, all roles as strings" do
      assert {:ok, %Ldap{required_group: "cn=macaw,cn=groups,dc=x"}} =
               parse(%{required_group: "cn=macaw,cn=groups,dc=x"})

      assert {:ok, %Ldap{required_group: nil, role_mapping: [], default_role: nil}} = parse(%{})

      assert {:ok, %Ldap{role_mapping: mapping, default_role: ["viewer"]}} =
               parse(%{
                 role_mapping: %{"admins" => :admin, "ops" => [:ops, "viewer"]},
                 default_role: :viewer
               })

      assert Enum.sort(mapping) == [{"admins", ["admin"]}, {"ops", ["ops", "viewer"]}]

      assert {:ok, %Ldap{default_role: ["guest", "viewer"]}} =
               parse(%{default_role: ["guest", :viewer]})

      for bad <- [
            %{"g" => ""},
            %{"g" => []},
            %{"g" => 1},
            %{"g" => ["admin", 1]},
            %{"" => "admin"}
          ] do
        assert error(%{role_mapping: bad}) ==
                 "sources[nas].role_mapping: must map group names to a role or a list of roles"
      end

      for bad <- ["", [], [""], 1, true] do
        assert error(%{default_role: bad}) ==
                 "sources[nas].default_role: must be a role or a list of roles"
      end
    end

    @tag verifies: "auth-ldap-secret"
    test "the service password is resolved when read, and no error message contains it" do
      secret = %{base_dn: "dc=x", bind_dn: "cn=svc", bind_password: "hunter2-secret"}

      assert {:ok, %Ldap{bind_password: "hunter2-secret"}} = search(secret)

      for fault <- [
            %{groups: %{base_dn: "cn=g", member_attr: "owner"}},
            %{default_role: ""},
            %{port: 0},
            %{shade: 1}
          ] do
        assert {:error, message} = search(secret, fault)
        refute message =~ "hunter2"
      end

      path =
        Path.join(
          System.tmp_dir!(),
          "macaw_auth_ldap_secret_#{System.unique_integer([:positive])}"
        )

      File.write!(path, "from-a-file\n")
      on_exit(fn -> File.rm(path) end)

      assert {:ok, %Ldap{bind_password: "from-a-file"}} =
               search(%{secret | bind_password: {:file, path}})
    end

    @tag verifies: "auth-ldap-knows"
    test "which refusals pass the attempt on, and each reason's explanation" do
      direct = source!(%{})

      {:ok, by_search} =
        search(%{base_dn: "dc=x", bind_dn: "cn=svc", bind_password: "pw"})

      for reason <- [
            :empty_password,
            :user_not_found,
            :plaintext_refused,
            :connect_failed,
            :tls_failed,
            :search_failed
          ],
          source <- [direct, by_search],
          do: refute(Ldap.knows?(source, reason), inspect(reason))

      # A direct bind can't tell a wrong password from a missing entry; a search found it.
      refute Ldap.knows?(direct, :invalid_credentials)
      assert Ldap.knows?(by_search, :invalid_credentials)

      for reason <- [
            :ambiguous_user,
            :group_search_failed,
            :not_in_group,
            :no_role,
            :invalid_username
          ],
          source <- [direct, by_search],
          do: assert(Ldap.knows?(source, reason), inspect(reason))

      explanations = %{
        empty_password:
          "an empty password was refused before connecting (LDAP treats it as an anonymous bind)",
        invalid_credentials: "the directory refused the password for that DN",
        plaintext_refused:
          "neither ssl nor starttls is set, and allow_plaintext is false: passwords are not sent unencrypted",
        connect_failed: "the directory could not be reached",
        tls_failed:
          "TLS failed: the certificate did not verify (chain, cacertfile or hostname), or the server refused TLS",
        search_failed:
          "the search failed: the service bind was refused, or the directory refused the search",
        user_not_found: "no entry matched the username",
        ambiguous_user: "more than one entry matched the username",
        group_search_failed: "the group search failed",
        not_in_group: "the user is not in the required group",
        no_role: "no role_mapping matched the user's groups and there is no default_role",
        invalid_username:
          "the directory's username attribute is not a valid username (1–64 of a-z 0-9 . _ @ + -)"
      }

      for {reason, text} <- explanations, do: assert(Ldap.explain(reason) == text)
    end
  end
end
