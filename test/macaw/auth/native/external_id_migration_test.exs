defmodule Macaw.Auth.Native.ExternalIdMigrationTest do
  @moduledoc """
  `add_macaw_auth_external_id` on a host coming from 0.4: a database of its
  own (`Macaw.Auth.Test.MigrationRepo`) migrated to the throttle's
  migration, rows written as the earlier release kept their ids (in
  `extra`, the value itself when printable, else hex), then migrated on,
  signed in through `Macaw.Auth.Test.FakeLdap`, and migrated back down.
  """

  use Macaw.Auth.DataCase, async: false

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.UserRecord
  alias Macaw.Auth.Test.{FakeLdap, MigrationRepo}
  alias Macaw.Auth.User
  alias Mix.Tasks.MacawAuth.Gen.Migration

  @base "dc=example,dc=test"
  @uuid "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
  @guid <<0x12, 0x34, 0x56, 0x78, 0, 255, 16, 1, 0x9A, 0xBC, 0xDE, 0xF0, 7, 8, 9, 10>>

  # username => {source, extra as 0.4 wrote it}
  @rows %{
    # Not hex (a UUID's dashes): the value itself.
    "uma" => {"nas", %{"external_id" => @uuid, "email" => "uma@example.test"}},
    # Hex of printable bytes ("abcd"): 0.4 would have kept those as they are,
    # so this is a printable value that looks like hex.
    "hex" => {"nas", %{"external_id" => "61626364"}},
    # Hex of bytes that don't print: an objectGUID 0.4 spelled as hex, or
    # text that happens to look so. Not told apart: left empty.
    "gus" => {"nas", %{"external_id" => Base.encode16(@guid, case: :lower), "dn" => "x"}},
    "num" => {"nas", %{"external_id" => "12345678"}},
    # The DN, for an entry without the id attribute.
    "dan" => {"nas", %{"external_id" => "uid=dan,cn=users,#{@base}"}},
    # A local user: no external id; the host's own fields untouched.
    "lou" => {"local", %{"theme" => "dark"}}
  }

  setup do
    n = System.unique_integer([:positive])
    root = Path.expand("../../../../tmp/test/external_id_migration_#{n}", __DIR__)

    on_exit(fn -> File.rm_rf!(root) end)
    Mix.shell(Mix.Shell.Process)
    on_exit(fn -> Mix.shell(Mix.Shell.IO) end)

    migrations = Path.join(root, "migrations")
    # The repo's name is only text in the files: a name of their own, so
    # each test's migration modules are its own.
    Migration.run(["--repo", "Host#{n}.Repo", "--migrations-path", migrations])
    start_supervised!({MigrationRepo, database: Path.join(root, "host.db"), pool_size: 1})
    %{migrations: migrations}
  end

  defp version(migrations, name) do
    [path] = Path.wildcard(Path.join(migrations, "*_#{name}.exs"))
    <<v::binary-14, "_", _::binary>> = Path.basename(path)
    String.to_integer(v)
  end

  defp insert_old_rows do
    for {username, {source, extra}} <- @rows do
      MigrationRepo.query!(
        "INSERT INTO macaw_auth_users (id, username, source, roles, must_change_password, " <>
          "extra, inserted_at, updated_at) VALUES (?, ?, ?, '[]', 0, ?, ?, ?)",
        [Ecto.UUID.generate(), username, source, JSON.encode!(extra), now(), now()]
      )
    end
  end

  defp now, do: "2026-10-28T00:00:00.000000Z"

  defp column(username) do
    [[value]] =
      MigrationRepo.query!("SELECT external_id FROM macaw_auth_users WHERE username = ?", [
        username
      ]).rows

    value
  end

  defp record(username), do: MigrationRepo.get_by!(UserRecord, username: username)

  defp extra(username) do
    [[json]] =
      MigrationRepo.query!("SELECT extra FROM macaw_auth_users WHERE username = ?", [username]).rows

    JSON.decode!(json)
  end

  @tag verifies: "migrations-external-id"
  test "each old spelling moves into the column, or is left for the next sign-in",
       %{migrations: migrations} do
    throttle = version(migrations, "create_macaw_auth_throttle")
    Ecto.Migrator.run(MigrationRepo, migrations, :up, to: throttle, log: false)
    insert_old_rows()

    Ecto.Migrator.run(MigrationRepo, migrations, :up, all: true, log: false)

    # The one spelling, read back as the directory's binary.
    assert column("uma") == Base.encode16(@uuid, case: :lower)
    assert record("uma").external_id == @uuid
    assert column("hex") == Base.encode16("61626364", case: :lower)
    assert record("hex").external_id == "61626364"
    assert record("dan").external_id == "uid=dan,cn=users,#{@base}"

    # Either spelling could have written these: empty until the next sign-in.
    assert column("gus") == nil
    assert column("num") == nil
    assert column("lou") == nil

    # The key leaves extra; everything else in it stays.
    assert extra("uma") == %{"email" => "uma@example.test"}
    assert extra("gus") == %{"dn" => "x"}
    assert extra("num") == %{}
    assert extra("lou") == %{"theme" => "dark"}
  end

  @tag verifies: "migrations-external-id-sign-in"
  test "after the migration, a directory user signs in to their own row, its id written",
       %{migrations: migrations} do
    throttle = version(migrations, "create_macaw_auth_throttle")
    Ecto.Migrator.run(MigrationRepo, migrations, :up, to: throttle, log: false)
    insert_old_rows()
    Ecto.Migrator.run(MigrationRepo, migrations, :up, all: true, log: false)
    ids = Map.new(MigrationRepo.all(UserRecord), &{&1.username, &1.id})

    port =
      FakeLdap.start(%{
        binds: %{"uid=gus,cn=users,#{@base}" => "gus-pw", "uid=uma,cn=users,#{@base}" => "uma-pw"},
        entries: %{
          "uid=gus,cn=users,#{@base}" => %{"uid" => ["gus"], "objectGUID" => [@guid]},
          "uid=uma,cn=users,#{@base}" => %{"uid" => ["uma"], "entryUUID" => [@uuid]}
        }
      })

    ldap = fn id_attr ->
      %{
        type: :ldap,
        name: "nas",
        host: "127.0.0.1",
        port: port,
        ssl: false,
        allow_plaintext: true,
        user_dn_template: "uid={username},cn=users,#{@base}",
        default_role: "viewer",
        id_attr: id_attr
      }
    end

    # The id the migration couldn't tell is written from the directory.
    configure!(repo: MigrationRepo, sources: [ldap.("objectGUID")])
    assert {:ok, %User{id: id}} = Native.authenticate(%{username: "gus", password: "gus-pw"})
    assert id == ids["gus"]
    assert column("gus") == Base.encode16(@guid, case: :lower)
    assert MigrationRepo.get_by!(UserRecord, external_id: @guid).id == ids["gus"]

    # The one it moved is the directory's, unchanged by the sign-in.
    configure!(repo: MigrationRepo, sources: [ldap.("entryUUID")])
    assert {:ok, %User{id: id}} = Native.authenticate(%{username: "uma", password: "uma-pw"})
    assert id == ids["uma"]
    assert column("uma") == Base.encode16(@uuid, case: :lower)
    assert MigrationRepo.aggregate(UserRecord, :count) == map_size(@rows)

    # Down: each id back in extra as 0.4 spelled it, and the column gone.
    # The migrator compiles the file again to run it down: the same module, on purpose.
    conflict = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)
    Ecto.Migrator.run(MigrationRepo, migrations, :down, step: 1, log: false)
    Code.put_compiler_option(:ignore_module_conflict, conflict)
    assert extra("uma")["external_id"] == @uuid
    assert extra("gus")["external_id"] == Base.encode16(@guid, case: :lower)
    assert extra("hex")["external_id"] == "61626364"
    assert extra("num") == %{}
    assert extra("lou") == %{"theme" => "dark"}

    refute "external_id" in List.flatten(
             MigrationRepo.query!("SELECT name FROM pragma_table_info('macaw_auth_users')").rows
           )
  end

  describe "the sections of spec 12" do
    @tag verifies: "auth-migrations-external-id"
    test "it runs after the throttle's, is its own code, and drops a value that isn't a string",
         %{migrations: migrations} do
      throttle = version(migrations, "create_macaw_auth_throttle")
      external_id = version(migrations, "add_macaw_auth_external_id")
      assert external_id > throttle

      [path] = Path.wildcard(Path.join(migrations, "*_add_macaw_auth_external_id.exs"))
      assert File.read!(path) =~ "use Ecto.Migration"
      refute File.read!(path) =~ ~r/Macaw\.Auth\.Native\.\w+\./

      Ecto.Migrator.run(MigrationRepo, migrations, :up, to: throttle, log: false)

      MigrationRepo.query!(
        "INSERT INTO macaw_auth_users (id, username, source, roles, must_change_password, " <>
          "extra, inserted_at, updated_at) VALUES (?, 'odd', 'nas', '[]', 0, ?, ?, ?)",
        [Ecto.UUID.generate(), JSON.encode!(%{"external_id" => 42, "kept" => true}), now(), now()]
      )

      Ecto.Migrator.run(MigrationRepo, migrations, :up, all: true, log: false)
      assert column("odd") == nil
      assert extra("odd") == %{"kept" => true}
    end
  end
end
