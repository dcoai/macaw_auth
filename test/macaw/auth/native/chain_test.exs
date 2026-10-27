defmodule Macaw.Auth.Native.ChainTest do
  use Macaw.Auth.DataCase, async: false

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Config, UserRecord}
  alias Macaw.Auth.Native.Source.Password
  alias Macaw.Auth.Test.FakeDirectory
  alias Macaw.Auth.User

  @hasher Macaw.Auth.Native.Hasher.Bcrypt

  defp chain(sources) do
    Config.put(%Config{repo: Repo, hasher: @hasher, sources: sources})
  end

  defp local, do: %Password{name: "local", repo: Repo, hasher: @hasher}

  defp dir(name, entries, opts \\ []) do
    struct!(
      FakeDirectory,
      Keyword.merge(
        [name: name, entries: entries, roles: %{"staff" => ["viewer"], "admins" => ["admin"]}],
        opts
      )
    )
  end

  defp sign_in(username, password),
    do: Native.authenticate(%{username: username, password: password})

  defp asked do
    receive do
      {:asked, name} -> [name | asked()]
    after
      0 -> []
    end
  end

  @tag verifies: "chain-order"
  test "sources are tried in order, and the first that knows the user decides" do
    chain([
      dir("first", %{"ann" => %{password: "first pw", groups: ["staff"]}}),
      dir("second", %{"ann" => %{password: "second pw"}, "ben" => %{password: "ben pw"}})
    ])

    assert {:ok, %User{source: "first"}} = sign_in("ann", "first pw")
    assert asked() == ["first"]

    # The first knows ann: her second-source password doesn't fall through.
    assert sign_in("ann", "second pw") == {:error, :invalid_credentials}
    assert asked() == ["first"]

    # The first doesn't know ben: the second decides.
    assert {:ok, %User{source: "second"}} = sign_in("ben", "ben pw")
    assert asked() == ["first", "second"]
  end

  @tag verifies: "chain-no-fallthrough"
  test "a wrong local password never falls through to a directory" do
    local_user!("cat", "local password")
    chain([local(), dir("dir", %{"cat" => %{password: "directory password"}})])

    assert sign_in("cat", "directory password") == {:error, :invalid_credentials}
    assert asked() == []
    assert {:ok, %User{source: "local"}} = sign_in("cat", "local password")
  end

  @tag verifies: "chain-unreachable"
  test "an unreachable directory passes to the next source" do
    local_user!("dan", "local password")
    chain([dir("down", %{}, reachable: false), local()])

    assert {:ok, %User{source: "local", username: "dan"}} = sign_in("dan", "local password")
    assert sign_in("dan", "wrong") == {:error, :invalid_credentials}
  end

  @tag verifies: "chain-none-knows"
  test "when no source knows the user, the refusal is the same" do
    chain([local(), dir("dir", %{})])
    assert sign_in("nobody", "x") == {:error, :invalid_credentials}
    assert asked() == ["dir"]
  end

  describe "just-in-time provisioning" do
    @tag verifies: "provision-first"
    test "a directory user's first sign-in makes their row, with no password" do
      chain([
        local(),
        dir("nas", %{"eve" => %{password: "pw", display_name: "Eve", groups: ["staff"]}})
      ])

      refute Repo.get_by(UserRecord, username: "eve")

      assert {:ok, %User{} = user} = sign_in("eve", "pw")
      assert %User{username: "eve", source: "nas", roles: ["viewer"], display_name: "Eve"} = user

      record = Repo.get_by!(UserRecord, username: "eve")
      assert record.id == user.id
      assert record.source == "nas"
      assert record.hashed_password == nil
      assert record.extra == %{"groups" => ["staff"]}

      # The same row the next time.
      assert {:ok, %User{id: id}} = sign_in("eve", "pw")
      assert id == user.id
      assert Repo.aggregate(UserRecord, :count) == 1
    end

    @tag verifies: "provision-refresh"
    test "roles are re-derived from the directory at every sign-in" do
      entries = %{"fay" => %{password: "pw", groups: ["staff", "admins"], display_name: "Fay"}}
      chain([dir("nas", entries)])
      assert {:ok, %User{roles: ["viewer", "admin"]}} = sign_in("fay", "pw")

      # Edited locally: the directory's word wins at the next sign-in.
      Repo.update_all(UserRecord, set: [roles: ["superuser"]])
      assert {:ok, %User{roles: ["viewer", "admin"]}} = sign_in("fay", "pw")

      # Removed from admins in the directory: the role goes.
      chain([dir("nas", put_in(entries["fay"].groups, ["staff"]))])
      assert {:ok, %User{roles: ["viewer"]}} = sign_in("fay", "pw")
      assert Repo.get_by!(UserRecord, username: "fay").roles == ["viewer"]
    end

    @tag verifies: "provision-no-takeover"
    test "a row another source owns is never taken over, whichever order the sources are in" do
      local = local_user!("owner", "local password")
      directory = dir("nas", %{"owner" => %{password: "directory password"}})

      for sources <- [[directory, local()], [local(), directory]] do
        chain(sources)
        assert sign_in("owner", "directory password") == {:error, :invalid_credentials}
        assert Repo.get!(UserRecord, local.id).source == "local"
        assert Repo.aggregate(UserRecord, :count) == 1
      end

      # Another directory's user is not taken over either.
      chain([dir("a", %{"gil" => %{password: "pw"}}), dir("b", %{"gil" => %{password: "pw"}})])
      assert {:ok, %User{source: "a"}} = sign_in("gil", "pw")

      chain([dir("b", %{"gil" => %{password: "pw"}})])
      assert sign_in("gil", "pw") == {:error, :invalid_credentials}
      assert Repo.get_by!(UserRecord, username: "gil").source == "a"
    end

    @tag verifies: "provision-disabled"
    test "a disabled directory user stays refused, and their row unchanged" do
      chain([dir("nas", %{"hal" => %{password: "pw", groups: ["staff"]}})])
      assert {:ok, _} = sign_in("hal", "pw")
      Repo.update_all(UserRecord, set: [disabled_at: DateTime.utc_now(), roles: []])

      assert sign_in("hal", "pw") == {:error, :disabled}
      assert Repo.get_by!(UserRecord, username: "hal").roles == []
    end

    @tag verifies: "provision-invalid-username"
    test "a directory username that isn't a valid one is refused" do
      chain([dir("nas", %{"Bad User" => %{password: "pw"}})])
      assert sign_in("Bad User", "pw") == {:error, :invalid_credentials}
      assert Repo.aggregate(UserRecord, :count) == 0
    end
  end

  @tag verifies: "native-telemetry"
  test "telemetry carries the reason and the source, never the password" do
    chain([local(), dir("nas", %{"ivy" => %{password: "pw"}})])
    ref = :telemetry_test.attach_event_handlers(self(), [[:macaw_auth, :native, :authenticate]])

    sign_in("ivy", "wrong")

    assert_received {[:macaw_auth, :native, :authenticate], ^ref, %{count: 1},
                     %{result: :error, reason: :invalid_credentials, source: "nas"} = meta}

    refute inspect(meta) =~ "wrong"

    sign_in("ivy", "pw")
    assert_received {_, ^ref, _, %{result: :ok, source: "nas", user_id: id}} when is_binary(id)
  end

  # As two first sign-ins at once: the look-up misses the row the other
  # sign-in just made, once (`:misses` times), then sees it.
  defmodule RacingRepo do
    alias Macaw.Auth.Test.Repo

    def get_by(queryable, clauses) do
      case Process.get(:misses, 0) do
        0 ->
          Repo.get_by(queryable, clauses)

        n ->
          Process.put(:misses, n - 1)
          nil
      end
    end

    defdelegate insert(changeset), to: Repo
    defdelegate update!(changeset), to: Repo
  end

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 06" do
    @tag verifies: "auth-sources"
    test "two sources ship; a source is a struct dispatched on its module" do
      alias Macaw.Auth.Native.Source
      alias Macaw.Auth.Native.Source.Ldap

      for module <- [Password, Ldap], {name, arity} <- Source.behaviour_info(:callbacks) do
        assert function_exported?(module, name, arity), "#{inspect(module)}.#{name}/#{arity}"
      end

      {:ok, config} =
        Config.parse(
          repo: Repo,
          sources: [
            %{type: :password},
            %{
              type: :ldap,
              name: "nas",
              host: "ldap",
              ssl: false,
              starttls: true,
              user_dn_template: "uid={username}"
            }
          ]
        )

      assert [%Password{}, %Ldap{}] = config.sources

      # The chain names no source module: a struct of any module that is one is run.
      chain([dir("plug-in", %{"una" => %{password: "pw"}})])
      assert {:ok, %User{source: "plug-in"}} = sign_in("una", "pw")
    end

    @tag verifies: "auth-source-behavior"
    test "the behavior's four callbacks, and the two shapes of an acceptance" do
      alias Macaw.Auth.Native.Source

      assert Enum.sort(Source.behaviour_info(:callbacks)) ==
               [authenticate: 4, explain: 1, knows?: 2, parse: 2]

      # parse/2: the struct, from the context's repo and hasher.
      assert {:ok, %Password{repo: Repo, hasher: @hasher}} =
               Password.parse(%{"type" => "password"}, repo: Repo, hasher: @hasher, env: %{})

      # A source that keeps the row gives it; another, what it knows of the user.
      local_user!("vic", "pw")

      assert {:ok, %{record: %UserRecord{username: "vic"}}} =
               Password.authenticate(local(), "vic", "pw", [])

      directory =
        dir("nas", %{"wes" => %{password: "pw", display_name: "Wes", groups: ["staff"]}})

      assert {:ok,
              %{
                username: "wes",
                display_name: "Wes",
                roles: ["viewer"],
                extra: %{"groups" => ["staff"]}
              }} =
               FakeDirectory.authenticate(directory, "wes", "pw", [])

      # knows?/2 decides; explain/1 is a sentence.
      refute Password.knows?(local(), :no_user)
      assert Password.knows?(local(), :invalid_credentials)
      assert Password.explain(:no_user) =~ "no local user"
    end

    @tag verifies: "auth-chain"
    test "run/5: the first source that knows the user decides, and what it returns" do
      alias Macaw.Auth.Native.Source

      run = fn sources, username, password ->
        Source.run(sources, Repo, username, password, [])
      end

      record = local_user!("xan", "local pw")
      down = dir("down", %{}, reachable: false)
      nas = dir("nas", %{"yul" => %{password: "pw"}, "xan" => %{password: "dir pw"}})

      # An acceptance: the source's own row as it is, or one the chain provisions.
      assert {:ok, %UserRecord{id: id}, %Password{name: "local"}} =
               run.([down, local()], "xan", "local pw")

      assert id == record.id

      assert {:ok, %UserRecord{username: "yul", source: "nas"}, %FakeDirectory{name: "nas"}} =
               run.([local(), nas], "yul", "pw")

      # A refusal by a source that knows the user is final.
      asked()
      assert {:error, :invalid_credentials, %Password{}} = run.([local(), nas], "xan", "dir pw")
      assert asked() == []

      # A source that doesn't know the user passes it on; with none knowing it,
      # the last source's refusal.
      assert {:error, :connect_failed, %FakeDirectory{name: "down"}} =
               run.([local(), down], "zed", "x")

      assert {:error, :no_user, %Password{}} = run.([down, local()], "zed", "x")
      assert run.([], "zed", "x") == {:error, :invalid_credentials, nil}

      # A provisioning refusal is final: "xan" is the local source's row.
      asked()

      assert {:error, :username_taken, %FakeDirectory{name: "nas"}} =
               run.([nas, dir("later", %{"xan" => %{password: "dir pw"}})], "xan", "dir pw")

      assert asked() == ["nas"]
    end

    @tag verifies: "auth-provision"
    test "directory_user/3 merges extra, re-reads once after a racing insert, and raises on any other failure" do
      alias Macaw.Auth.Native.Provision

      attrs = %{
        username: "Yan",
        display_name: "Yan",
        roles: ["viewer"],
        extra: %{"dn" => "uid=yan"}
      }

      # First sign-in: the normalized username, the source's name, no password.
      assert {:ok, row} = Provision.directory_user(Repo, "nas", attrs)
      assert {row.username, row.source, row.hashed_password} == {"yan", "nas", nil}

      # Later: the directory's display name and roles replace the row's; its extra
      # is merged over the row's.
      Repo.update!(Ecto.Changeset.change(row, extra: %{"dn" => "old", "host_field" => 1}))

      assert {:ok, row} =
               Provision.directory_user(Repo, "nas", %{attrs | display_name: "Yan Y", roles: []})

      assert {row.display_name, row.roles} == {"Yan Y", []}
      assert row.extra == %{"dn" => "uid=yan", "host_field" => 1}

      # Two first sign-ins at once: the insert meets the unique username, and
      # the row the other made is used, re-read once.
      Process.put(:misses, 1)
      assert {:ok, %UserRecord{id: id}} = Provision.directory_user(RacingRepo, "nas", attrs)
      assert id == row.id

      Process.put(:misses, 2)
      assert Provision.directory_user(RacingRepo, "nas", attrs) == {:error, :username_taken}
      assert Repo.aggregate(UserRecord, :count) == 1

      # Any other insert failure is a bug, and raises.
      assert_raise Ecto.InvalidChangesetError, fn ->
        Provision.directory_user(Repo, "nas", %{attrs | username: "zoe", roles: "admin"})
      end
    end
  end
end
