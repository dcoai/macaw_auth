defmodule Macaw.Auth.ClosedDefaultsTest do
  # Spec 00 §5: every setting that grants trust or loosens a policy defaults
  # to granting nothing. Each item's detail is its own section's; this checks
  # the list as a whole, each item in its default state.
  use Macaw.Auth.DataCase, async: false

  import Plug.Test

  alias Macaw.Auth
  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Provision, UserCommands, UserRecord}
  alias Macaw.Auth.Native.Source.Ldap
  alias Macaw.Auth.User

  @secret_key_base String.duplicate("macaw_auth test secret key base ", 2)

  @nas %{
    type: :ldap,
    name: "nas",
    host: "ldap",
    port: 389,
    ssl: false,
    user_dn_template: "uid={username},cn=users,dc=example,dc=test"
  }

  @tag verifies: "auth-closed"
  test "each setting that grants trust or loosens a policy grants nothing until it is set" do
    # LDAP: no plaintext, a verified certificate, no anonymous search.
    assert {:error, plaintext} = Ldap.parse(@nas, [])
    assert plaintext =~ "allow_plaintext: true"

    assert {:ok, %Ldap{allow_plaintext: true}} =
             Ldap.parse(Map.put(@nas, :allow_plaintext, true), [])

    assert {:ok, %Ldap{allow_plaintext: false, verify_peer: true}} =
             Ldap.parse(Map.put(@nas, :starttls, true), [])

    assert {:error, anonymous} =
             @nas
             |> Map.merge(%{starttls: true, user_dn_template: nil, search: %{base_dn: "dc=x"}})
             |> Ldap.parse([])

    assert anonymous =~ "allow_anonymous_search: true"

    # A directory user never takes over another source's row.
    local = local_user!("owner", "a local password")

    assert Provision.directory_user(Repo, "nas", %{username: "owner", roles: []}) ==
             {:error, :username_taken}

    assert Repo.get!(UserRecord, local.id).source == "local"

    # No registration: the contract has no callback that makes a user, and
    # the first admin is made only while no user exists.
    callbacks = Macaw.Auth.Backend.behaviour_info(:callbacks)
    refute Enum.any?(callbacks, fn {name, _} -> name |> Atom.to_string() =~ ~r/user|regist/ end)
    assert Native.bootstrap_admin(%{username: "root", password: "pw", role: "admin"}) == :exists

    # A password among the command's words is refused.
    assert {:error, "a password is never read from the command line" <> _} =
             UserCommands.run(["add", "newbie", "--password", "hunter2"], "env pw",
               password_var: "THE_PASSWORD"
             )

    refute Native.get_user("newbie")

    # The release entry points have no prefix of their own.
    assert Application.get_env(:macaw_auth, Macaw.Auth.Native.Release) == nil

    # A role check passes only on membership.
    user = %User{id: 1, username: "ann", roles: ["viewer"]}

    refused =
      conn(:get, "/admin")
      |> Plug.Conn.assign(:current_user, user)
      |> Macaw.Auth.Plug.require_role(["admin"])

    assert refused.halted

    assert Macaw.Auth.Plug.require_role(Plug.Conn.assign(conn(:get, "/"), :current_user, user), [
             "viewer"
           ]).halted == false

    # No authorizer, nothing authorized.
    assert Application.get_env(:macaw_auth, :authorizer) == nil
    refute Auth.authorize(%User{id: 1, username: "root", roles: ["admin"]}, :manage, nil)

    # The remember cookie is set only when a sign-in asks for it, and is
    # secure under https whatever log_in is given.
    previous = Application.get_env(:macaw_auth, :backend)
    Application.put_env(:macaw_auth, :backend, Native)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:macaw_auth, :backend, previous),
        else: Application.delete_env(:macaw_auth, :backend)
    end)

    {:ok, owner} = Auth.authenticate(%{username: "owner", password: "a local password"})
    cookie = Macaw.Auth.Plug.remember_cookie()

    https = fn ->
      %{conn(:get, "/login") | scheme: :https, secret_key_base: @secret_key_base}
      |> init_test_session(%{})
      |> Macaw.Auth.Plug.fetch_current_user([])
    end

    refute Map.has_key?(Macaw.Auth.Plug.log_in(https.(), owner, []).resp_cookies, cookie)

    asked = Macaw.Auth.Plug.log_in(https.(), owner, remember: true, secure: false)
    assert asked.resp_cookies[cookie].secure == true
  end
end
