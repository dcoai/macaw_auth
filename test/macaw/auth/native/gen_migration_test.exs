defmodule Mix.Tasks.MacawAuth.Gen.MigrationTest do
  use Macaw.Auth.DataCase, async: false

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

  test "writes the three migrations, in order, naming the repo, and refuses a second time",
       %{dir: dir} do
    [users, sessions, factor] =
      Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])

    assert Path.basename(users) =~ ~r/^\d{14}_create_macaw_auth_users\.exs$/
    assert Path.basename(sessions) =~ ~r/^\d{14}_create_macaw_auth_sessions\.exs$/
    assert Path.basename(factor) =~ ~r/^\d{14}_add_macaw_auth_second_factor\.exs$/
    assert Path.basename(users) < Path.basename(sessions)
    assert Path.basename(sessions) < Path.basename(factor)
    assert File.read!(users) =~ "defmodule MyApp.Repo.Migrations.CreateMacawAuthUsers do"
    assert File.read!(sessions) =~ "defmodule MyApp.Repo.Migrations.CreateMacawAuthSessions do"
    assert File.read!(factor) =~ "defmodule MyApp.Repo.Migrations.AddMacawAuthSecondFactor do"

    for _ <- 1..3, do: assert_received({:mix_shell, :info, ["* creating " <> _]})

    assert_raise Mix.Error, ~r/already has the macaw_auth migrations/, fn ->
      Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])
    end

    assert length(File.ls!(dir)) == 3
  end

  test "a host with the users migration gets only the others", %{dir: dir} do
    [users, first, second] = Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])
    File.rm!(first)
    File.rm!(second)

    assert [sessions, factor] = Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])
    assert Path.basename(sessions) =~ ~r/_create_macaw_auth_sessions\.exs$/
    assert Path.basename(factor) =~ ~r/_add_macaw_auth_second_factor\.exs$/
    assert Path.wildcard(Path.join(dir, "*_create_macaw_auth_users.exs")) == [users]
  end

  test "a host with the users and sessions migrations gets only the second factor's",
       %{dir: dir} do
    [users, sessions, factor] = Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])
    File.rm!(factor)

    assert [again] = Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])
    assert Path.basename(again) =~ ~r/_add_macaw_auth_second_factor\.exs$/
    assert Path.basename(again) > Path.basename(sessions)
    assert Path.wildcard(Path.join(dir, "*_create_macaw_auth_users.exs")) == [users]
  end

  test "takes the configured repo when none is given", %{dir: dir} do
    [users, sessions, _factor] = Migration.run(["--migrations-path", dir])

    assert File.read!(users) =~
             "defmodule Macaw.Auth.Test.Repo.Migrations.CreateMacawAuthUsers do"

    assert File.read!(sessions) =~
             "defmodule Macaw.Auth.Test.Repo.Migrations.CreateMacawAuthSessions do"
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
  test "the generated migrations made the tables the schemas read" do
    assert columns("macaw_auth_users") ==
             Enum.sort(~w(id username display_name hashed_password source roles disabled_at
                          must_change_password extra inserted_at updated_at
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
  end
end
