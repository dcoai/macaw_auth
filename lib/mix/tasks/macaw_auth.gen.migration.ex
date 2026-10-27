defmodule Mix.Tasks.MacawAuth.Gen.Migration do
  @shortdoc "Writes the migration creating macaw_auth_users"

  @moduledoc """
  Writes the migration that creates the native backend's users table,
  `macaw_auth_users`, into the host's migrations:

      mix macaw_auth.gen.migration
      mix macaw_auth.gen.migration --repo MyApp.Repo --migrations-path priv/repo/migrations

  The repo's name is `--repo`, else the configured one (`config
  :macaw_auth, Macaw.Auth.Native, repo: MyApp.Repo`); it is only written
  into the file as text. The path defaults to `priv/repo/migrations`. The
  file is timestamped like `mix ecto.gen.migration`'s, and the task refuses
  to write a second one.

  The migration is plain DDL the host owns and can read, and it is the one
  this library's own tests run against SQLite, so what ships is what is
  tested. It works on Postgres and SQLite alike: `roles` is
  `{:array, :string}`, a native array on Postgres and JSON text on SQLite.
  """

  use Mix.Task

  @switches [repo: :string, migrations_path: :string]
  @name "create_macaw_auth_users"

  @impl true
  def run(argv) do
    {opts, _args, invalid} = OptionParser.parse(argv, strict: @switches)
    if invalid != [], do: Mix.raise("unknown option: #{inspect(invalid)}")

    repo = opts[:repo] || configured_repo()
    dir = opts[:migrations_path] || Path.join(["priv", "repo", "migrations"])

    case Path.wildcard(Path.join(dir, "*_#{@name}.exs")) do
      [] ->
        path = Path.join(dir, "#{timestamp()}_#{@name}.exs")
        File.mkdir_p!(dir)
        File.write!(path, migration(repo))
        Mix.shell().info("* creating #{path}")
        path

      [existing | _] ->
        Mix.raise("#{existing} already exists: the users table has its migration")
    end
  end

  defp configured_repo do
    Mix.Task.run("app.config")

    case Application.get_env(:macaw_auth, Macaw.Auth.Native, [])[:repo] do
      nil ->
        Mix.raise(
          "no repo: pass --repo MyApp.Repo, or configure " <>
            "config :macaw_auth, Macaw.Auth.Native, repo: MyApp.Repo"
        )

      repo ->
        inspect(repo)
    end
  end

  defp timestamp do
    {{y, m, d}, {hh, mm, ss}} = :calendar.universal_time()
    :io_lib.format("~4..0B~2..0B~2..0B~2..0B~2..0B~2..0B", [y, m, d, hh, mm, ss]) |> to_string()
  end

  @doc false
  def migration(repo) do
    """
    defmodule #{repo}.Migrations.CreateMacawAuthUsers do
      # Written by `mix macaw_auth.gen.migration`: the native backend's
      # users (Macaw.Auth.Native.UserRecord). Usernames are stored
      # normalized (trimmed, lower case), so a plain unique index makes them
      # unique without regard to case on every database.
      use Ecto.Migration

      def change do
        create table(:macaw_auth_users, primary_key: false) do
          add :id, :binary_id, primary_key: true
          add :username, :string, null: false
          add :display_name, :string
          # nil for a directory user: the directory checks their password.
          add :hashed_password, :string
          # "local", or the name of the directory source that owns the row.
          add :source, :string, null: false
          # A native array on Postgres; JSON text on SQLite.
          add :roles, {:array, :string}, null: false
          add :disabled_at, :utc_datetime_usec
          add :must_change_password, :boolean, null: false, default: false
          add :extra, :map, null: false

          timestamps(type: :utc_datetime_usec)
        end

        create unique_index(:macaw_auth_users, [:username])
      end
    end
    """
  end
end
