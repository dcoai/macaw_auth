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

  test "writes one timestamped migration naming the repo, and refuses a second", %{dir: dir} do
    path = Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])
    assert Path.basename(path) =~ ~r/^\d{14}_create_macaw_auth_users\.exs$/
    assert File.read!(path) =~ "defmodule MyApp.Repo.Migrations.CreateMacawAuthUsers do"
    assert_received {:mix_shell, :info, ["* creating " <> _]}

    assert_raise Mix.Error, ~r/already exists/, fn ->
      Migration.run(["--repo", "MyApp.Repo", "--migrations-path", dir])
    end
  end

  test "takes the configured repo when none is given", %{dir: dir} do
    path = Migration.run(["--migrations-path", dir])
    assert File.read!(path) =~ "defmodule Macaw.Auth.Test.Repo.Migrations.CreateMacawAuthUsers do"
  end

  # test_helper ran the generated migration against SQLite: this is its table.
  test "the generated migration made the table the schema reads" do
    columns =
      Repo.query!("SELECT name FROM pragma_table_info('macaw_auth_users')").rows
      |> List.flatten()
      |> Enum.sort()

    assert columns ==
             Enum.sort(~w(id username display_name hashed_password source roles disabled_at
                          must_change_password extra inserted_at updated_at))

    assert [[1]] =
             Repo.query!(
               "SELECT \"unique\" FROM pragma_index_list('macaw_auth_users') WHERE name LIKE '%username%'"
             ).rows
  end
end
