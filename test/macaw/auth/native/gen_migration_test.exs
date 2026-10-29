defmodule Mix.Tasks.MacawAuth.Gen.MigrationTest do
  use Macaw.Auth.DataCase, async: false

  alias Macaw.Auth.Native.{RecoveryCodeRecord, SessionRecord, ThrottleRecord, UserRecord}
  alias Mix.Tasks.MacawAuth.Gen.Migration

  setup do
    dir =
      Path.expand(
        "../../../../tmp/test/gen_migration_#{System.unique_integer([:positive])}",
        __DIR__
      )

    on_exit(fn -> File.rm_rf!(dir) end)
    Mix.shell(Mix.Shell.Process)
    on_exit(fn -> Mix.shell(Mix.Shell.IO) end)
    %{dir: dir}
  end

  @tag verifies: "migrations-write"
  test "writes the five migrations, in order, naming the repo", %{dir: dir} do
    [users, sessions, factor, throttle, external_id] =
      Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])

    assert Path.basename(users) =~ ~r/^\d{14}_create_macaw_auth_users\.exs$/
    assert Path.basename(sessions) =~ ~r/^\d{14}_create_macaw_auth_sessions\.exs$/
    assert Path.basename(factor) =~ ~r/^\d{14}_add_macaw_auth_second_factor\.exs$/
    assert Path.basename(throttle) =~ ~r/^\d{14}_create_macaw_auth_throttle\.exs$/
    assert Path.basename(external_id) =~ ~r/^\d{14}_add_macaw_auth_external_id\.exs$/
    assert Path.basename(users) < Path.basename(sessions)
    assert Path.basename(sessions) < Path.basename(factor)
    assert Path.basename(factor) < Path.basename(throttle)
    assert Path.basename(throttle) < Path.basename(external_id)
    assert File.read!(users) =~ "defmodule MyApp.Repo.Migrations.CreateMacawAuthUsers do"
    assert File.read!(sessions) =~ "defmodule MyApp.Repo.Migrations.CreateMacawAuthSessions do"
    assert File.read!(factor) =~ "defmodule MyApp.Repo.Migrations.AddMacawAuthSecondFactor do"
    assert File.read!(throttle) =~ "defmodule MyApp.Repo.Migrations.CreateMacawAuthThrottle do"
    assert File.read!(external_id) =~ "defmodule MyApp.Repo.Migrations.AddMacawAuthExternalId do"

    for path <- [users, sessions, factor, throttle, external_id],
        do: assert_received({:mix_shell, :info, ["* creating " <> ^path]})
  end

  @tag verifies: "migrations-refuse-again"
  test "refuses a second time, writing nothing", %{dir: dir} do
    Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])

    assert_raise Mix.Error, ~r/already has the macaw_auth migrations/, fn ->
      Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])
    end

    assert length(File.ls!(dir)) == 5
  end

  @tag verifies: "migrations-only-missing"
  test "a host with some of the migrations gets only the others", %{dir: dir} do
    [users | rest] = Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])
    Enum.each(rest, &File.rm!/1)

    assert [sessions, factor, throttle, external_id] =
             Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])

    assert Path.basename(sessions) =~ ~r/_create_macaw_auth_sessions\.exs$/
    assert Path.basename(factor) =~ ~r/_add_macaw_auth_second_factor\.exs$/
    assert Path.basename(throttle) =~ ~r/_create_macaw_auth_throttle\.exs$/
    assert Path.basename(external_id) =~ ~r/_add_macaw_auth_external_id\.exs$/
    assert Path.wildcard(Path.join(dir, "*_create_macaw_auth_users.exs")) == [users]

    # With the users and sessions migrations, the second factor's and the later ones.
    Enum.each([factor, throttle, external_id], &File.rm!/1)

    assert [again, throttle, external_id] =
             Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])

    assert Path.basename(again) =~ ~r/_add_macaw_auth_second_factor\.exs$/
    assert Path.basename(again) > Path.basename(sessions)
    assert Path.wildcard(Path.join(dir, "*_create_macaw_auth_users.exs")) == [users]
    assert Path.wildcard(Path.join(dir, "*_create_macaw_auth_sessions.exs")) == [sessions]

    # A host on 0.4 (the three earlier ones) gets the throttle's and the external id's.
    Enum.each([throttle, external_id], &File.rm!/1)

    assert [throttle, external_id] =
             Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])

    assert Path.basename(throttle) =~ ~r/_create_macaw_auth_throttle\.exs$/
    assert Path.basename(throttle) > Path.basename(again)

    # A host with the throttle's gets only the external id's, after it.
    File.rm!(external_id)

    assert [only] = Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])
    assert Path.basename(only) =~ ~r/_add_macaw_auth_external_id\.exs$/
    assert Path.basename(only) > Path.basename(throttle)
  end

  @tag verifies: "migrations-configured-repo"
  test "takes the configured repo when none is given", %{dir: dir} do
    [users, sessions | _] = Migration.run(["--migrations-path", dir])

    assert File.read!(users) =~
             "defmodule Macaw.Auth.Test.Repo.Migrations.CreateMacawAuthUsers do"

    assert File.read!(sessions) =~
             "defmodule Macaw.Auth.Test.Repo.Migrations.CreateMacawAuthSessions do"
  end

  @tag verifies: "migrations-after-existing"
  test "a migration dated ahead: the files come after it, one second apart", %{dir: dir} do
    File.mkdir_p!(dir)
    ahead = DateTime.add(DateTime.utc_now(), 3600, :second)
    File.write!(Path.join(dir, "#{version(ahead)}_the_hosts_own.exs"), "")

    versions =
      ["--repo", "MyApp.Repo", "--migrations-path", dir]
      |> Migration.run()
      |> Enum.map(&seconds/1)

    assert versions == Enum.map(1..5, &(DateTime.to_unix(ahead) + &1))
  end

  defp version(%DateTime{} = at), do: Calendar.strftime(at, "%Y%m%d%H%M%S")

  defp seconds(path) do
    <<v::binary-14, "_", _::binary>> = Path.basename(path)

    <<y::binary-4, m::binary-2, d::binary-2, hh::binary-2, mm::binary-2, ss::binary-2>> = v

    [y, m, d, hh, mm, ss]
    |> Enum.map(&String.to_integer/1)
    |> then(fn [y, m, d, hh, mm, ss] ->
      DateTime.new!(Date.new!(y, m, d), Time.new!(hh, mm, ss)) |> DateTime.to_unix()
    end)
  end

  defp columns(table) do
    Repo.query!("SELECT name FROM pragma_table_info('#{table}')").rows
    |> List.flatten()
    |> Enum.sort()
  end

  defp unique_index?(table, column) do
    Repo.query!(
      "SELECT \"unique\" FROM pragma_index_list('#{table}') WHERE name LIKE '%#{column}%'"
    ).rows == [[1]]
  end

  # test_helper ran the generated migrations against SQLite: these are their tables.
  @tag verifies: "migrations-tables"
  test "the generated migrations made the tables the schemas read" do
    assert columns("macaw_auth_users") ==
             Enum.sort(~w(id username display_name hashed_password source roles disabled_at
                          must_change_password extra external_id inserted_at updated_at
                          totp_secret_sealed totp_enabled_at totp_last_step))

    assert unique_index?("macaw_auth_users", "username")

    assert columns("macaw_auth_sessions") ==
             Enum.sort(~w(id user_id token_hash remote_ip user_agent second_factor_passed
                          completed_steps last_used_at inserted_at updated_at))

    assert unique_index?("macaw_auth_sessions", "token_hash")

    assert [["macaw_auth_users", "CASCADE"]] =
             Repo.query!(
               "SELECT \"table\", on_delete FROM pragma_foreign_key_list('macaw_auth_sessions')"
             ).rows

    assert columns("macaw_auth_recovery_codes") ==
             Enum.sort(~w(id user_id code_hash inserted_at))

    assert unique_index?("macaw_auth_recovery_codes", "user_id_code_hash")

    assert [["macaw_auth_users", "CASCADE"]] =
             Repo.query!(
               "SELECT \"table\", on_delete FROM pragma_foreign_key_list('macaw_auth_recovery_codes')"
             ).rows

    assert columns("macaw_auth_throttle") == Enum.sort(~w(kind subject failures last_failure_ms))
    assert unique_index?("macaw_auth_throttle", "kind_subject")
    refute unique_index?("macaw_auth_throttle", "last_failure_ms")

    assert Repo.query!(
             "SELECT 1 FROM pragma_index_list('macaw_auth_throttle') WHERE name LIKE '%last_failure_ms%'"
           ).rows == [[1]]

    assert Repo.query!("SELECT 1 FROM pragma_foreign_key_list('macaw_auth_throttle')").rows == []
  end

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 12" do
    @tag verifies: "auth-migrations"
    test "the migrations the tests ran are the ones the task writes", %{dir: dir} do
      shipped = Path.expand("../../../../tmp/test/migrations", __DIR__)
      written = Migration.run(["--repo", "Macaw.Auth.Test.Repo", "--migrations-path", dir])

      body = fn path -> path |> Path.basename() |> String.slice(15..-1//1) end
      ran = shipped |> File.ls!() |> Enum.sort()
      assert Enum.map(ran, &String.slice(&1, 15..-1//1)) == Enum.map(written, body)

      for {name, path} <- Enum.zip(ran, written) do
        assert File.read!(Path.join(shipped, name)) == File.read!(path)
      end

      # Plain DDL the host reads: Ecto.Migration, no call into this library.
      for path <- written do
        assert File.read!(path) =~ "use Ecto.Migration"
        refute File.read!(path) =~ ~r/Macaw\.Auth\.Native\.\w+\./
      end
    end

    @tag verifies: "auth-migrations-options"
    test "the default path is made when missing; with no repo, or an unknown option, the task stops",
         %{dir: dir} do
      File.mkdir_p!(dir)

      written = File.cd!(dir, fn -> Migration.run(["--repo", "MyApp.Repo"]) end)
      assert length(written) == 5
      assert length(File.ls!(Path.join(dir, "priv/repo/migrations"))) == 5

      assert_raise Mix.Error, ~r/unknown option: .*--frob/, fn ->
        Migration.run(["--frob", "--migrations-path", Path.join(dir, "other")])
      end

      refute File.exists?(Path.join(dir, "other"))

      configured = Application.fetch_env!(:macaw_auth, Macaw.Auth.Native)
      on_exit(fn -> Application.put_env(:macaw_auth, Macaw.Auth.Native, configured) end)
      Application.put_env(:macaw_auth, Macaw.Auth.Native, Keyword.delete(configured, :repo))

      assert_raise Mix.Error,
                   "no repo: pass --repo MyApp.Repo, or configure " <>
                     "config :macaw_auth, Macaw.Auth.Native, repo: MyApp.Repo",
                   fn -> Migration.run(["--migrations-path", Path.join(dir, "none")]) end
    end

    defp column(table, name) do
      Repo.query!(
        "SELECT \"notnull\", dflt_value FROM pragma_table_info('#{table}') WHERE name = ?",
        [name]
      ).rows
    end

    @tag verifies: "auth-migrations-files"
    test "the columns' nulls and defaults, the user index, and arrays on SQLite", %{dir: dir} do
      not_null = fn table, names ->
        for name <- names, do: assert([[1, _]] = column(table, name), "#{table}.#{name}")
      end

      not_null.("macaw_auth_users", ~w(username source roles must_change_password extra))
      assert column("macaw_auth_users", "must_change_password") == [[1, "false"]]
      assert [[0, nil]] = column("macaw_auth_users", "hashed_password")

      not_null.(
        "macaw_auth_sessions",
        ~w(user_id token_hash second_factor_passed completed_steps last_used_at)
      )

      assert column("macaw_auth_sessions", "second_factor_passed") == [[1, "true"]]
      not_null.("macaw_auth_recovery_codes", ~w(user_id code_hash))
      not_null.("macaw_auth_throttle", ~w(kind subject failures last_failure_ms))

      assert Repo.query!(
               "SELECT 1 FROM pragma_index_list('macaw_auth_sessions') WHERE name LIKE '%user_id%'"
             ).rows == [[1]]

      # The arrays are {:array, :string}: JSON text here, a list again when read.
      [users, sessions, _, throttle, external_id] =
        Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])

      assert File.read!(users) =~ "add :roles, {:array, :string}, null: false"
      assert File.read!(sessions) =~ "add :completed_steps, {:array, :string}, null: false"
      # Milliseconds of the system clock outgrow a 32-bit integer.
      assert File.read!(throttle) =~ "add :last_failure_ms, :bigint, null: false"
      # Nil for a local user.
      assert File.read!(external_id) =~ "add :external_id, :string\n"
      assert [[0, nil]] = column("macaw_auth_users", "external_id")

      # Each table is its schema's, column for column.
      for schema <- [UserRecord, SessionRecord, RecoveryCodeRecord, ThrottleRecord] do
        fields = Enum.map(schema.__schema__(:fields), &Atom.to_string/1)
        assert Enum.sort(fields) == columns(schema.__schema__(:source)), inspect(schema)
      end

      record = local_user!("ruth", "correct horse battery", %{roles: ["admin", "ops"]})
      assert Repo.get!(UserRecord, record.id).roles == ["admin", "ops"]

      assert [[~s(["admin","ops"])]] =
               Repo.query!("SELECT roles FROM macaw_auth_users WHERE username = 'ruth'").rows
    end

    @tag verifies: "auth-migrations-missing"
    test "any *_<name>.exs counts as present; the refusal names the five", %{dir: dir} do
      File.mkdir_p!(dir)
      File.write!(Path.join(dir, "hosts_create_macaw_auth_users.exs"), "")

      assert [sessions, factor, throttle, external_id] =
               Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])

      assert sessions =~ "_create_macaw_auth_sessions.exs"
      assert factor =~ "_add_macaw_auth_second_factor.exs"
      assert throttle =~ "_create_macaw_auth_throttle.exs"
      assert external_id =~ "_add_macaw_auth_external_id.exs"

      assert_raise Mix.Error,
                   "#{dir} already has the macaw_auth migrations " <>
                     "(create_macaw_auth_users, create_macaw_auth_sessions, " <>
                     "add_macaw_auth_second_factor, create_macaw_auth_throttle, " <>
                     "add_macaw_auth_external_id)",
                   fn -> Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir]) end
    end

    @tag verifies: "auth-migrations-order"
    test "versions are UTC seconds from now, one apart; a name that isn't a timestamp is ignored",
         %{dir: dir} do
      File.mkdir_p!(dir)
      # Month 13: not a valid timestamp, so not a migration to come after.
      File.write!(Path.join(dir, "20991399000000_not_a_version.exs"), "")

      before = DateTime.to_unix(DateTime.utc_now())

      [first, second, third, fourth, fifth] =
        Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])

      later = DateTime.to_unix(DateTime.utc_now())

      assert seconds(first) in before..later
      assert seconds(second) == seconds(first) + 1
      assert seconds(third) == seconds(first) + 2
      assert seconds(fourth) == seconds(first) + 3
      assert seconds(fifth) == seconds(first) + 4

      # A second run within the same moment still runs after what is there.
      Enum.each([second, third, fourth, fifth], &File.rm!/1)
      before = DateTime.to_unix(DateTime.utc_now())

      [again, next, then, last] =
        Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])

      later = DateTime.to_unix(DateTime.utc_now())
      assert seconds(again) in max(seconds(first) + 1, before)..max(seconds(first) + 1, later)
      assert seconds(next) == seconds(again) + 1
      assert seconds(then) == seconds(again) + 2
      assert seconds(last) == seconds(again) + 3
    end
  end
end
