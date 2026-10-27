# The test repo: a fresh SQLite file, migrated with the migration
# `mix macaw_auth.gen.migration` writes, so the shipped migration is the
# tested one.
alias Macaw.Auth.Test.Repo

tmp = Path.expand("../tmp/test", __DIR__)
File.rm_rf!(tmp)
File.mkdir_p!(tmp)

migrations = Path.join(tmp, "migrations")

Mix.shell(Mix.Shell.Quiet)

Mix.Tasks.MacawAuth.Gen.Migration.run([
  "--repo",
  inspect(Repo),
  "--migrations-path",
  migrations
])

Mix.shell(Mix.Shell.IO)

# Migrated over a plain pool, then restarted sandboxed: the sandbox has one
# connection (SQLite allows one writer), which the migrator would contend for.
{:ok, migrating} = Repo.start_link(pool: DBConnection.ConnectionPool, pool_size: 1)
Ecto.Migrator.run(Repo, migrations, :up, all: true, log: false)
:ok = Supervisor.stop(migrating)
{:ok, _} = Repo.start_link()
Ecto.Adapters.SQL.Sandbox.mode(Repo, :manual)

# The :ldap tests need the OpenLDAP fixture directory (macaw's
# ci/tools/ldap image); they run when MACAW_AUTH_LDAP_HOST names it.
exclude = if System.get_env("MACAW_AUTH_LDAP_HOST"), do: [], else: [:ldap]

ExUnit.start(exclude: exclude, formatters: [ExUnit.CLIFormatter, Surfex.ExUnitFormatter])
