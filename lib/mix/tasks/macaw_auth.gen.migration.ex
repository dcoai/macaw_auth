defmodule Mix.Tasks.MacawAuth.Gen.Migration do
  @shortdoc "Writes the migrations for the native backend's tables (users, sessions, second factor, throttle, external ids)"

  @moduledoc """
  Writes the migrations that create the native backend's tables into the
  host's migrations, one file each:

  - `create_macaw_auth_users`: `macaw_auth_users`
    (`Macaw.Auth.Native.UserRecord`);
  - `create_macaw_auth_sessions`: `macaw_auth_sessions`
    (`Macaw.Auth.Native.SessionRecord`), referencing the users;
  - `add_macaw_auth_second_factor`: the second factor's columns on
    `macaw_auth_users` and the `macaw_auth_recovery_codes` table
    (`Macaw.Auth.Native.Totp`, `Macaw.Auth.Native.RecoveryCodeRecord`);
  - `create_macaw_auth_throttle`: `macaw_auth_throttle`
    (`Macaw.Auth.Native.ThrottleRecord`), the sign-in throttle's counts;
  - `add_macaw_auth_external_id`: the `external_id` column on
    `macaw_auth_users` (`Macaw.Auth.Native.ExternalId`), each id an
    earlier release kept in `extra` moved into it in the one spelling.

      mix macaw_auth.gen.migration
      mix macaw_auth.gen.migration --repo MyApp.Repo --migrations-path priv/repo/migrations

  The repo's name is `--repo`, else the configured one (`config
  :macaw_auth, Macaw.Auth.Native, repo: MyApp.Repo`); it is only written
  into the files as text. The path defaults to `priv/repo/migrations`.

  Each has its own file, and the task writes only those not yet there: a
  host that has the users and sessions migrations gets the second
  factor's, the throttle's and the external id's added after them, and a
  host that has all five is refused, so no table or column is ever
  created twice. Files are timestamped like `mix ecto.gen.migration`'s,
  one second apart, so they run in order.

  The migrations are plain DDL the host owns and can read (the external
  id's also rewrites the rows it moves, in its own code, calling nothing
  in this library), and they are
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
    {"add_macaw_auth_second_factor", :second_factor},
    {"create_macaw_auth_throttle", :throttle},
    {"add_macaw_auth_external_id", :external_id}
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

  def migration(:throttle, repo) do
    """
    defmodule #{repo}.Migrations.CreateMacawAuthThrottle do
      # Written by `mix macaw_auth.gen.migration`: the sign-in throttle's
      # failure counts (Macaw.Auth.Native.ThrottleRecord), kept here so a
      # restart forgets none of them. A row is one key: an account (by id,
      # so a rename keeps its count), a name no account has, or a client
      # address.
      use Ecto.Migration

      def change do
        create table(:macaw_auth_throttle, primary_key: false) do
          # "account", "second_factor", "name", "invalid" or "address".
          add :kind, :string, null: false
          # The account's id, the name, the address, or "" for "invalid".
          add :subject, :string, null: false
          add :failures, :integer, null: false
          # The latest failure's time, in milliseconds of the system clock.
          add :last_failure_ms, :bigint, null: false
        end

        # A check, a failure's upsert and a success each find their rows by it.
        create unique_index(:macaw_auth_throttle, [:kind, :subject])
        # The sweep deletes by age.
        create index(:macaw_auth_throttle, [:last_failure_ms])
      end
    end
    """
  end

  def migration(:external_id, repo) do
    """
    defmodule #{repo}.Migrations.AddMacawAuthExternalId do
      # Written by `mix macaw_auth.gen.migration`: a directory user's
      # external id gets its own column on macaw_auth_users, spelled one way
      # for every value: lower-case hex of the bytes the directory gave
      # (Macaw.Auth.Native.ExternalId reads it back to those bytes). Earlier
      # releases kept it in extra["external_id"], as the value itself when
      # it printed and as hex otherwise, so one spelling could be either.
      # This moves each one into the column and drops the key from extra.
      #
      # An old value becomes the directory's bytes when its spelling says
      # which it was:
      # - not lower-case hex (a UUID's dashes, a DN's "="): the value itself;
      # - lower-case hex of bytes that print: those bytes would have been
      #   kept as themselves, so this too is the value itself;
      # - lower-case hex of bytes that don't print: either could have written
      #   it ("12345678" as text, or the four bytes 12 34 56 78), so the
      #   column is left empty. A directory user's row is found by username
      #   and its id rewritten at every sign-in, so their next sign-in fills
      #   it from the directory.
      use Ecto.Migration

      import Ecto.Query

      def up do
        alter table(:macaw_auth_users) do
          # Lower-case hex of the directory's id; nil for a local user.
          add :external_id, :string
        end

        flush()

        for {id, extra, _} <- users(), Map.has_key?(extra, "external_id") do
          {old, extra} = Map.pop(extra, "external_id")
          set(id, extra, spelling(old))
        end
      end

      # Back to the old spellings, which each column value has exactly one of.
      def down do
        for {id, extra, external_id} <- users(), external_id != nil do
          set(id, Map.put(extra, "external_id", old_spelling(external_id)), nil)
        end

        alter table(:macaw_auth_users) do
          remove :external_id
        end
      end

      defp users do
        repo().all(
          from(u in "macaw_auth_users",
            select: {type(u.id, :binary_id), type(u.extra, :map), u.external_id}
          )
        )
      end

      defp set(id, extra, external_id) do
        repo().update_all(
          from(u in "macaw_auth_users",
            where: u.id == type(^id, :binary_id),
            update: [set: [extra: type(^extra, :map), external_id: ^external_id]]
          ),
          []
        )
      end

      # The column's spelling of an old value, or nil when it can't be told.
      defp spelling(old) when is_binary(old) do
        case Base.decode16(old, case: :lower) do
          {:ok, bytes} ->
            if String.printable?(bytes), do: Base.encode16(old, case: :lower), else: nil

          :error ->
            Base.encode16(old, case: :lower)
        end
      end

      defp spelling(_not_a_string), do: nil

      defp old_spelling(spelling) do
        bytes = Base.decode16!(spelling, case: :lower)
        if String.printable?(bytes), do: bytes, else: spelling
      end
    end
    """
  end
end
