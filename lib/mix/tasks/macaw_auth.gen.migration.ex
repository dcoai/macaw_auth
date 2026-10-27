defmodule Mix.Tasks.MacawAuth.Gen.Migration do
  @shortdoc "Writes the migrations for the native backend's tables (users, sessions, second factor)"

  @moduledoc """
  Writes the migrations that create the native backend's tables into the
  host's migrations, one file each:

  - `create_macaw_auth_users`: `macaw_auth_users`
    (`Macaw.Auth.Native.UserRecord`);
  - `create_macaw_auth_sessions`: `macaw_auth_sessions`
    (`Macaw.Auth.Native.SessionRecord`), referencing the users;
  - `add_macaw_auth_second_factor`: the second factor's columns on
    `macaw_auth_users` and the `macaw_auth_recovery_codes` table
    (`Macaw.Auth.Native.Totp`, `Macaw.Auth.Native.RecoveryCodeRecord`).

      mix macaw_auth.gen.migration
      mix macaw_auth.gen.migration --repo MyApp.Repo --migrations-path priv/repo/migrations

  The repo's name is `--repo`, else the configured one (`config
  :macaw_auth, Macaw.Auth.Native, repo: MyApp.Repo`); it is only written
  into the files as text. The path defaults to `priv/repo/migrations`.

  Each has its own file, and the task writes only those not yet there: a
  host that has the users and sessions migrations gets the second
  factor's added after them, and a host that has all three is refused, so
  no table or column is ever created twice. Files are timestamped like `mix ecto.gen.migration`'s,
  one second apart, so they run in order.

  The migrations are plain DDL the host owns and can read, and they are
  the ones this library's own tests run against SQLite, so what ships is
  what is tested. They work on Postgres and SQLite alike: the array
  columns are `{:array, :string}`, a native array on Postgres and JSON
  text on SQLite.
  """

  use Mix.Task

  @switches [repo: :string, migrations_path: :string]
  @migrations [
    {"create_macaw_auth_users", :users},
    {"create_macaw_auth_sessions", :sessions},
    {"add_macaw_auth_second_factor", :second_factor}
  ]

  @impl true
  def run(argv) do
    {opts, _args, invalid} = OptionParser.parse(argv, strict: @switches)
    if invalid != [], do: Mix.raise("unknown option: #{inspect(invalid)}")

    dir = opts[:migrations_path] || Path.join(["priv", "repo", "migrations"])

    case Enum.reject(@migrations, fn {name, _} -> exists?(dir, name) end) do
      [] ->
        Mix.raise(
          "#{dir} already has the macaw_auth migrations " <>
            "(#{Enum.map_join(@migrations, ", ", &elem(&1, 0))})"
        )

      missing ->
        repo = opts[:repo] || configured_repo()
        File.mkdir_p!(dir)
        start = first_free_second(dir)

        missing
        |> Enum.with_index()
        |> Enum.map(fn {{name, table}, i} ->
          path = Path.join(dir, "#{timestamp(start + i)}_#{name}.exs")
          File.write!(path, migration(table, repo))
          Mix.shell().info("* creating #{path}")
          path
        end)
    end
  end

  defp exists?(dir, name), do: Path.wildcard(Path.join(dir, "*_#{name}.exs")) != []

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

  # Now, or just after the latest migration already there when that is
  # later (a second run within the same second): versions must be unique
  # and ours must run after the users table's.
  defp first_free_second(dir) do
    now = :calendar.datetime_to_gregorian_seconds(:calendar.universal_time())

    dir
    |> Path.join("*.exs")
    |> Path.wildcard()
    |> Enum.flat_map(&version_seconds(Path.basename(&1)))
    |> Enum.reduce(now, &max(&1 + 1, &2))
  end

  defp version_seconds(
         <<y::binary-4, m::binary-2, d::binary-2, hh::binary-2, mm::binary-2, ss::binary-2, "_",
           _::binary>>
       ) do
    with [{y, ""}, {m, ""}, {d, ""}, {hh, ""}, {mm, ""}, {ss, ""}] <-
           Enum.map([y, m, d, hh, mm, ss], &Integer.parse/1),
         true <- :calendar.valid_date(y, m, d) do
      [:calendar.datetime_to_gregorian_seconds({{y, m, d}, {hh, mm, ss}})]
    else
      _ -> []
    end
  end

  defp version_seconds(_name), do: []

  defp timestamp(seconds) do
    {{y, m, d}, {hh, mm, ss}} = :calendar.gregorian_seconds_to_datetime(seconds)
    :io_lib.format("~4..0B~2..0B~2..0B~2..0B~2..0B~2..0B", [y, m, d, hh, mm, ss]) |> to_string()
  end

  @doc false
  def migration(:users, repo) do
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

  def migration(:sessions, repo) do
    """
    defmodule #{repo}.Migrations.CreateMacawAuthSessions do
      # Written by `mix macaw_auth.gen.migration`: the native backend's
      # sessions (Macaw.Auth.Native.SessionRecord). The client holds the
      # session's token; this table holds only its SHA-256, so reading it
      # signs nobody in.
      use Ecto.Migration

      def change do
        create table(:macaw_auth_sessions, primary_key: false) do
          add :id, :binary_id, primary_key: true

          add :user_id, references(:macaw_auth_users, type: :binary_id, on_delete: :delete_all),
            null: false

          add :token_hash, :binary, null: false
          add :remote_ip, :string
          # Truncated to 255 characters.
          add :user_agent, :string
          add :second_factor_passed, :boolean, null: false, default: true
          # Step names; a native array on Postgres, JSON text on SQLite.
          add :completed_steps, {:array, :string}, null: false
          # What idle expiry reads; written at most hourly.
          add :last_used_at, :utc_datetime_usec, null: false

          timestamps(type: :utc_datetime_usec)
        end

        create unique_index(:macaw_auth_sessions, [:token_hash])
        create index(:macaw_auth_sessions, [:user_id])
      end
    end
    """
  end

  def migration(:second_factor, repo) do
    """
    defmodule #{repo}.Migrations.AddMacawAuthSecondFactor do
      # Written by `mix macaw_auth.gen.migration`: the native backend's
      # second factor (Macaw.Auth.Native.Totp). The TOTP secret is stored
      # sealed (AES-256-GCM under the configured sealing_key), and recovery
      # codes only as SHA-256, so reading these tables passes nobody's
      # second factor.
      use Ecto.Migration

      def change do
        alter table(:macaw_auth_users) do
          # The sealed secret; set while enrollment is pending, too.
          add :totp_secret_sealed, :binary
          # Set when enrollment was confirmed: the second factor is on.
          add :totp_enabled_at, :utc_datetime_usec
          # The last 30-second step a code was accepted for: no code is
          # accepted twice.
          add :totp_last_step, :bigint
        end

        create table(:macaw_auth_recovery_codes, primary_key: false) do
          add :id, :binary_id, primary_key: true

          add :user_id, references(:macaw_auth_users, type: :binary_id, on_delete: :delete_all),
            null: false

          # SHA-256 of the code; a spent code's row is deleted.
          add :code_hash, :binary, null: false

          timestamps(type: :utc_datetime_usec, updated_at: false)
        end

        create unique_index(:macaw_auth_recovery_codes, [:user_id, :code_hash])
      end
    end
    """
  end
end
