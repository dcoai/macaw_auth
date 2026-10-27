import Config

# The library's own test setup only; a host configures its own. The test
# repo is a SQLite file under tmp/ (ignored), migrated by test_helper with
# the migration `mix macaw_auth.gen.migration` writes.
if config_env() == :test do
  config :macaw_auth, Macaw.Auth.Test.Repo,
    database: Path.expand("../tmp/test/macaw_auth_test.db", __DIR__),
    pool: Ecto.Adapters.SQL.Sandbox,
    pool_size: 1

  config :macaw_auth, ecto_repos: [Macaw.Auth.Test.Repo]
  config :macaw_auth, Macaw.Auth.Native, repo: Macaw.Auth.Test.Repo

  # Elixir's own JSON, for the array and map columns on SQLite.
  config :ecto_sqlite3, json_library: JSON

  # Cheap hashes: the tests count work, not seconds (the timing test sets
  # its own cost).
  config :bcrypt_elixir, log_rounds: 4
  config :argon2_elixir, t_cost: 1, m_cost: 8, parallelism: 1

  config :logger, level: :warning
end
