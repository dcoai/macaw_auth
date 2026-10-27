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

  test "the defaults: a password source named local, bcrypt" do
    assert {:ok, %Config{repo: @repo, hasher: Macaw.Auth.Native.Hasher.Bcrypt, sources: [source]}} =
             parse([])

    assert %Password{name: "local", repo: @repo} = source
  end

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
             member_attr: "memberUid"
           }

    assert Enum.sort(corp.role_mapping) == [
             {"admins", ["admin", "operator"]},
             {"staff", ["viewer"]}
           ]

    assert corp.default_role == ["guest"]
  end

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

  test "secret references resolve, and a missing one is named without its value" do
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

  test "every fault is named" do
    assert ldap_error(%{host: nil}) == "sources[nas].host: is required"
    assert ldap_error(%{port: 0}) == "sources[nas].port: must be in 1..65535"
    assert ldap_error(%{verify_peer: "yes"}) == "sources[nas].verify_peer: must be true or false"
    assert ldap_error(%{hostname: "x"}) == "sources[nas].hostname: is not a known setting"
    assert ldap_error(%{"shade" => "x"}) =~ ~s(sources[nas].shade: is not a known setting)
    assert ldap_error(%{name: "Bad Name"}) =~ ~s(sources["Bad Name"].name: must be)

    assert ldap_error(%{cacertfile: "/nonexistent.pem"}) =~
             "sources[nas].cacertfile: /nonexistent.pem"

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

    assert ldap_error(%{groups: %{base_dn: "cn=g", member_attr: "owner"}}) ==
             "sources[nas].groups.member_attr: must be member, uniqueMember or memberUid"

    assert ldap_error(%{role_mapping: %{"g" => 1}}) =~ "sources[nas].role_mapping: must map"
    assert ldap_error(%{default_role: ""}) =~ "sources[nas].default_role: must be a role"
    assert {:ok, _} = parse(sources: [Map.put(@nas, :cacertfile, @ca)])
  end

  test "the configuration's own faults are named" do
    assert Config.parse([]) == {:error, "repo: is required (the host's Ecto.Repo)"}
    assert {:error, ":shade: is not a Macaw.Auth.Native setting"} = parse(shade: 1)
    assert {:error, "hasher: String is not a Macaw.Auth.Native.Hasher"} = parse(hasher: String)
    assert {:error, "sources: must be a non-empty list" <> _} = parse(sources: [])
    assert {:error, "sources: unknown type :oauth" <> _} = parse(sources: [%{type: :oauth}])

    assert {:error, "sources[local].name: is used by two sources"} =
             parse(sources: [%{type: :password}, %{"type" => "password"}])

    assert {:error, "sources[local].hasher: is not a known setting"} =
             parse(sources: [%{type: :password, hasher: :x}])
  end

  test "load! raises the fault, naming the configuration" do
    previous = Application.get_env(:macaw_auth, Macaw.Auth.Native)
    Application.put_env(:macaw_auth, Macaw.Auth.Native, repo: @repo, sources: [%{type: :ldap}])
    on_exit(fn -> Application.put_env(:macaw_auth, Macaw.Auth.Native, previous) end)

    assert_raise Config.Error,
                 "config :macaw_auth, Macaw.Auth.Native: sources: a source of type ldap needs a name",
                 fn -> Config.load!() end
  end
end
