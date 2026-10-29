defmodule Macaw.Auth.Native.ConfigTest do
  use ExUnit.Case, async: true

  alias Macaw.Auth.Native.Config
  alias Macaw.Auth.Native.Source.{Ldap, Password}

  @repo Macaw.Auth.Test.Repo
  @ca Path.expand("../../../fixtures/ldap/ca.pem", __DIR__)

  @nas %{
    type: :ldap,
    name: "nas",
    host: "ldap",
    port: 389,
    ssl: false,
    starttls: true,
    user_dn_template: "uid={username},cn=users,dc=example,dc=test"
  }

  defp parse(settings, opts \\ []), do: Config.parse(Keyword.merge([repo: @repo], settings), opts)

  defp ldap_error(overrides, opts \\ []) do
    {:error, message} = parse([sources: [Map.merge(@nas, overrides)]], opts)
    message
  end

  @tag verifies: "native-config-defaults"
  test "the defaults: a password source named local, bcrypt, and the session and TOTP settings" do
    assert {:ok,
            %Config{repo: @repo, hasher: Macaw.Auth.Native.Hasher.Bcrypt, sources: [source]} =
              config} = parse([])

    assert %Password{name: "local", repo: @repo} = source
    assert config.session_idle_days == 14
    assert config.totp_issuer == "Macaw"
    assert config.totp_required == false
    assert config.sealing_key == nil
  end

  @tag verifies: "ldap-config-defaults"
  test "an LDAP source is parsed with its defaults" do
    assert {:ok, %Config{sources: [%Password{}, %Ldap{} = nas]}} =
             parse(sources: [%{type: :password}, @nas])

    assert %Ldap{
             name: "nas",
             host: "ldap",
             port: 389,
             starttls: true,
             allow_plaintext: false,
             verify_peer: true,
             timeout_ms: 5000,
             id_attr: "entryUUID",
             username_attr: "uid",
             role_mapping: [],
             default_role: nil
           } = nas
  end

  @tag verifies: "ldap-config-strings"
  test "string keys and types, as a JSON file writes them" do
    source = %{
      "type" => "ldap",
      "name" => "corp",
      "host" => "ldap.example.test",
      "search" => %{
        "base_dn" => "dc=example,dc=test",
        "bind_dn" => "cn=svc",
        "bind_password" => "s"
      },
      "groups" => %{"base_dn" => "cn=groups,dc=example,dc=test", "member_attr" => "memberUid"},
      "role_mapping" => %{"admins" => ["admin", "operator"], "staff" => "viewer"},
      "default_role" => "guest"
    }

    assert {:ok, %Config{sources: [%Ldap{} = corp]}} = parse(sources: [source])

    assert corp.search == %{
             base_dn: "dc=example,dc=test",
             filter: "(uid={username})",
             bind_dn: "cn=svc"
           }

    assert corp.bind_password == "s"

    assert corp.groups == %{
             from: :search,
             base_dn: "cn=groups,dc=example,dc=test",
             member_attr: "memberUid",
             bind_dn: nil
           }

    assert Enum.sort(corp.role_mapping) == [
             {"admins", ["admin", "operator"]},
             {"staff", ["viewer"]}
           ]

    assert corp.default_role == ["guest"]
  end

  @tag verifies: "ldap-secret-hidden"
  test "the bind password never shows when the source is inspected" do
    {:ok, %Config{sources: [source]}} =
      parse(
        sources: [
          Map.merge(@nas, %{
            user_dn_template: nil,
            search: %{base_dn: "dc=x", bind_dn: "cn=svc", bind_password: "hunter2-secret"}
          })
          |> Map.delete(:user_dn_template)
        ]
      )

    refute inspect(source) =~ "hunter2"
  end

  @tag verifies: "source-settings"
  test "a source's unknown key, a bad name and a secret reference are checked, by name" do
    assert {:error, "sources[local].hasher: is not a known setting"} =
             parse(sources: [%{type: :password, hasher: :x}])

    assert ldap_error(%{name: "Bad Name"}) =~ ~s(sources["Bad Name"].name: must be)

    search = %{base_dn: "dc=x", bind_dn: "cn=svc", bind_password: {:env, "LDAP_PW"}}
    source = @nas |> Map.delete(:user_dn_template) |> Map.put(:search, search)

    assert {:ok, %Config{sources: [%Ldap{bind_password: "from env"}]}} =
             parse([sources: [source]], env: %{"LDAP_PW" => "from env"})

    assert {:error,
            "sources[nas].search.bind_password: the environment variable LDAP_PW is not set"} =
             parse([sources: [source]], env: %{})
  end

  test "plaintext is refused unless allowed, by name" do
    assert ldap_error(%{starttls: false}) =~
             "sources[nas].ssl: is false: set starttls: true, or allow_plaintext: true"

    assert {:ok, %Config{sources: [%Ldap{allow_plaintext: true}]}} =
             parse(sources: [Map.merge(@nas, %{starttls: false, allow_plaintext: true})])

    assert ldap_error(%{ssl: true}) == "sources[nas].starttls: can't be used with ssl: true"
  end

  test "every connection setting's fault is named" do
    assert ldap_error(%{host: nil}) == "sources[nas].host: is required"
    assert ldap_error(%{port: 0}) == "sources[nas].port: must be in 1..65535"
    assert ldap_error(%{verify_peer: "yes"}) == "sources[nas].verify_peer: must be true or false"
    assert ldap_error(%{hostname: "x"}) == "sources[nas].hostname: is not a known setting"
    assert ldap_error(%{"shade" => "x"}) =~ ~s(sources[nas].shade: is not a known setting)

    assert ldap_error(%{cacertfile: "/nonexistent.pem"}) =~
             "sources[nas].cacertfile: /nonexistent.pem"

    assert {:ok, _} = parse(sources: [Map.put(@nas, :cacertfile, @ca)])
  end

  @tag verifies: "ldap-config-finding"
  test "the ways of finding the user are checked, by name" do
    assert ldap_error(%{user_dn_template: "uid=x"}) ==
             "sources[nas].user_dn_template: must contain {username}"

    assert ldap_error(%{user_dn_template: nil}) ==
             "sources[nas].user_dn_template: or search is required"

    assert ldap_error(%{search: %{base_dn: "dc=x"}}) ==
             "sources[nas].search: can't be set with user_dn_template: choose one"

    no_template = Map.delete(@nas, :user_dn_template)

    assert {:error, "sources[nas].search.filter: must be an LDAP filter containing {username}"} =
             parse(sources: [Map.put(no_template, :search, %{base_dn: "dc=x", filter: "(uid=x"})])

    assert {:error, "sources[nas].search.bind_dn: and bind_password are required" <> _} =
             parse(sources: [Map.put(no_template, :search, %{base_dn: "dc=x"})])

    assert {:ok, %Config{sources: [%Ldap{search: %{bind_dn: nil}}]}} =
             parse(
               sources: [
                 Map.merge(no_template, %{
                   search: %{base_dn: "dc=x"},
                   allow_anonymous_search: true
                 })
               ]
             )
  end

  test "the groups and access settings' faults are named" do
    assert ldap_error(%{groups: %{base_dn: "cn=g", member_attr: "owner"}}) ==
             "sources[nas].groups.member_attr: must be member, uniqueMember or memberUid"

    assert ldap_error(%{role_mapping: %{"g" => 1}}) =~ "sources[nas].role_mapping: must map"
    assert ldap_error(%{default_role: ""}) =~ "sources[nas].default_role: must be a role"
  end

  @tag verifies: "native-config-faults"
  test "the configuration's own faults are named" do
    assert Config.parse([]) == {:error, "repo: is required (the host's Ecto.Repo)"}
    assert {:error, ":shade: is not a Macaw.Auth.Native setting"} = parse(shade: 1)
    assert {:error, "hasher: String is not a Macaw.Auth.Native.Hasher"} = parse(hasher: String)
    assert {:error, "sources: must be a non-empty list" <> _} = parse(sources: [])
    assert {:error, "sources: unknown type :oauth" <> _} = parse(sources: [%{type: :oauth}])

    assert {:error, "sources[local].name: is used by two sources"} =
             parse(sources: [%{type: :password}, %{"type" => "password"}])

    for bad <- [0, 3651, "14", 1.5, nil] do
      assert {:error, "session_idle_days: must be an integer in 1..3650, got " <> got} =
               parse(session_idle_days: bad)

      assert got == inspect(bad)
    end

    assert parse(totp_required: []) ==
             {:error, "totp_required: a list of roles must be non-empty role names (strings)"}

    assert parse(totp_required: "yes") ==
             {:error, ~s(totp_required: must be false, true or a list of roles, got "yes")}

    assert parse(totp_issuer: "a:b") == {:error, "totp_issuer: must not contain a colon"}

    assert parse(sealing_key: "too short a key") ==
             {:error, "sealing_key: must be at least 32 bytes"}

    assert {:error, "sealing_key: must be a binary of at least 32 bytes" <> _} =
             parse(sealing_key: 42)
  end

  @tag verifies: "native-config-sealing-hidden"
  test "the sealing key never shows when the configuration is inspected" do
    key = "a sealing key of forty-four bytes, all of it"
    assert {:ok, config} = parse(sealing_key: key)
    assert config.sealing_key == key

    refute inspect(config) =~ "sealing_key"
    refute inspect(config) =~ key
    refute inspect(config, limit: :infinity, printable_limit: :infinity) =~ "forty-four"
  end

  @tag verifies: "native-config-load"
  test "load! raises the fault, naming the configuration" do
    previous = Application.get_env(:macaw_auth, Macaw.Auth.Native)
    Application.put_env(:macaw_auth, Macaw.Auth.Native, repo: @repo, sources: [%{type: :ldap}])
    on_exit(fn -> Application.put_env(:macaw_auth, Macaw.Auth.Native, previous) end)

    assert_raise Config.Error,
                 "config :macaw_auth, Macaw.Auth.Native: sources: a source of type ldap needs a name",
                 fn -> Config.load!() end
  end

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 05 and 06" do
    @tag verifies: "auth-native-config"
    test "the keys: what each accepts, and source maps with string keys, made atoms only by lookup" do
      # repo: a module, an atom but nil, true or false.
      assert {:ok, %Config{repo: SomeRepo}} = Config.parse(repo: SomeRepo)
      assert Config.parse(repo: true) == {:error, "repo: must be a module, got true"}
      assert Config.parse(repo: "Repo") == {:error, ~s(repo: must be a module, got "Repo")}

      # hasher: either algorithm.
      assert {:ok, %Config{hasher: Macaw.Auth.Native.Hasher.Argon2}} =
               parse(hasher: Macaw.Auth.Native.Hasher.Argon2)

      # sources: in order, each a known type, a map.
      assert {:ok, %Config{sources: [%Ldap{name: "nas"}, %Password{name: "local"}]}} =
               parse(sources: [@nas, %{type: :password}])

      assert parse(sources: [:password]) ==
               {:error, "sources: each source must be a map, got :password"}

      # session_idle_days: the range's ends.
      assert {:ok, %Config{session_idle_days: 1}} = parse(session_idle_days: 1)
      assert {:ok, %Config{session_idle_days: 3650}} = parse(session_idle_days: 3650)

      # totp_issuer, totp_required and sealing_key: what each accepts.
      assert {:ok, %Config{totp_issuer: "My App"}} = parse(totp_issuer: "My App")
      assert {:error, "totp_issuer: must be a non-empty string" <> _} = parse(totp_issuer: "")
      assert {:ok, %Config{totp_required: true}} = parse(totp_required: true)
      assert {:ok, %Config{totp_required: ["admin"]}} = parse(totp_required: ["admin"])

      assert {:ok, %Config{sealing_key: {SomeKeys, :key, []}}} =
               parse(sealing_key: {SomeKeys, :key, []})

      # A source map with string keys and a string type, as a JSON file writes it.
      assert {:ok, %Config{sources: [%Password{name: "staff"}]}} =
               parse(sources: [%{"type" => "password", "name" => "staff"}])

      assert parse(sources: [%{type: :oauth}]) ==
               {:error, "sources: unknown type :oauth; one of :password, :ldap"}

      # An unknown string type or key is named as it is, never made an atom.
      type = "never_an_atom_#{System.unique_integer([:positive])}"
      key = "never_an_atom_#{System.unique_integer([:positive])}"

      assert parse(sources: [%{"type" => type}]) ==
               {:error, "sources: unknown type #{inspect(type)}; one of :password, :ldap"}

      assert parse(sources: [%{"type" => "password", key => 1}]) ==
               {:error, "sources[local].#{key}: is not a known setting"}

      assert_raise ArgumentError, fn -> String.to_existing_atom(type) end
      assert_raise ArgumentError, fn -> String.to_existing_atom(key) end
    end

    @tag verifies: "auth-source-settings"
    test "names, unknown keys and secrets are checked the same way for every source" do
      no_template = Map.delete(@nas, :user_dn_template)
      secret = fn value -> Map.put(no_template, :search, search_with(value)) end

      # A name: 1–32 of a-z 0-9 _ -, starting with a letter or digit.
      long = String.duplicate("a", 32)
      assert {:ok, %Config{sources: [%Password{name: ^long}]}} = parse(sources: [password(long)])

      for bad <- [String.duplicate("a", 33), "_x", "-x", "Upper", ""] do
        assert {:error, message} = parse(sources: [password(bad)])

        assert message ==
                 "sources[#{inspect(bad)}].name: must be 1–32 of a-z 0-9 _ -, " <>
                   "starting with a letter or digit"
      end

      assert {:ok, %Config{sources: [%Password{name: "local"}]}} =
               parse(sources: [%{type: :password}])

      assert parse(sources: [Map.delete(@nas, :name)]) ==
               {:error, "sources: a source of type ldap needs a name"}

      assert parse(sources: [@nas, password("nas")]) ==
               {:error, "sources[nas].name: is used by two sources"}

      # An unknown key, an atom or a string, names the source and the key.
      assert parse(sources: [Map.put(@nas, :hostname, "x")]) ==
               {:error, "sources[nas].hostname: is not a known setting"}

      assert parse(sources: [Map.put(@nas, "hostname", "x")]) ==
               {:error, "sources[nas].hostname: is not a known setting"}

      # A secret: a literal, {:env, VAR} or {:file, path} with a trailing newline trimmed.
      dir =
        Path.join(System.tmp_dir!(), "macaw_auth_settings_#{System.unique_integer([:positive])}")

      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf!(dir) end)
      file = Path.join(dir, "pw")
      File.write!(file, "from a file\n")
      empty = Path.join(dir, "empty")
      File.write!(empty, "")
      missing = Path.join(dir, "missing")

      assert {:ok, %Config{sources: [%Ldap{bind_password: "literal pw"}]}} =
               parse(sources: [secret.("literal pw")])

      assert {:ok, %Config{sources: [%Ldap{bind_password: "from env"}]}} =
               parse([sources: [secret.({:env, "PW"})]], env: %{"PW" => "from env"})

      assert {:ok, %Config{sources: [%Ldap{bind_password: "from a file"}]}} =
               parse(sources: [secret.({:file, file})])

      assert parse(sources: [secret.({:file, empty})]) ==
               {:error, "sources[nas].search.bind_password: #{empty} is empty"}

      assert parse(sources: [secret.({:file, missing})]) ==
               {:error,
                "sources[nas].search.bind_password: cannot read #{missing}: no such file or directory"}

      assert {:error, "sources[nas].search.bind_password: must be a string" <> _} =
               parse(sources: [secret.(42)])

      # No message holds a secret: a fault after a literal one was read, and a bad one.
      bad_groups = %{base_dn: "cn=g", member_attr: "owner"}

      assert {:error, message} =
               parse(sources: [Map.put(secret.("hunter2-secret"), :groups, bad_groups)])

      assert message ==
               "sources[nas].groups.member_attr: must be member, uniqueMember or memberUid"

      refute message =~ "hunter2"
      assert {:error, message} = parse(sources: [secret.({:literal, "hunter2-secret"})])
      refute message =~ "hunter2"
    end
  end

  defp password(name), do: %{type: :password, name: name}

  defp search_with(bind_password),
    do: %{base_dn: "dc=x", bind_dn: "cn=svc", bind_password: bind_password}
end
