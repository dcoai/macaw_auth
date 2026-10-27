# 12 — Native: migrations {#auth-migrations}

The native backend's tables live in the host's repo, and the host owns their migrations: `mix macaw_auth.gen.migration` writes them into the host's migrations directory, as plain DDL the host can read. **They are the ones this library's own tests run** (the test helper generates them and migrates a fresh SQLite database with them), so what ships is what is tested (macaw_compose#50).

```sh
mix macaw_auth.gen.migration
mix macaw_auth.gen.migration --repo MyApp.Repo --migrations-path priv/repo/migrations
```

## 1. The options {#auth-migrations-options}

- **`--repo`:** the repo's module name, only written into the files as text (`defmodule MyApp.Repo.Migrations.…`). Without it, the configured one (`config :macaw_auth, Macaw.Auth.Native, repo:`), read after loading the app's configuration; with neither, the task stops: `"no repo: pass --repo MyApp.Repo, or configure config :macaw_auth, Macaw.Auth.Native, repo: MyApp.Repo"`.
- **`--migrations-path`:** default `priv/repo/migrations`, made when missing.
- **An unknown option** stops the task, naming it.

```test:migrations-configured-repo
without --repo, the files are named for the configured repo: "defmodule Macaw.Auth.Test.Repo.Migrations.CreateMacawAuthUsers do"
```

## 2. The three files {#auth-migrations-files}

One file each, in this order:
1. **`create_macaw_auth_users`:** `macaw_auth_users` (`Macaw.Auth.Native.UserRecord`, [06 §5](06-native-sources.md#auth-user-record)): `id` binary id primary key; `username` (not null) under a **unique index**; `display_name`; `hashed_password` (nil for a directory user); `source` (not null); `roles` `{:array, :string}` (not null); `disabled_at`; `must_change_password` (not null, default false); `extra` a map (not null); `inserted_at` and `updated_at` in microseconds;
2. **`create_macaw_auth_sessions`:** `macaw_auth_sessions` (`Macaw.Auth.Native.SessionRecord`, [09](09-native-sessions.md)): `id` binary id; `user_id` referencing the users **with `on_delete: :delete_all`** (not null) and indexed; `token_hash` binary (not null) under a **unique index**; `remote_ip`; `user_agent`; `second_factor_passed` (not null, default true); `completed_steps` `{:array, :string}` (not null); `last_used_at` (not null); timestamps;
3. **`add_macaw_auth_second_factor`:** on `macaw_auth_users`, `totp_secret_sealed` (binary), `totp_enabled_at` and `totp_last_step` (bigint); and **`macaw_auth_recovery_codes`** (`Macaw.Auth.Native.RecoveryCodeRecord`, [11 §6](11-native-totp.md#auth-totp-recovery)): `id`; `user_id` referencing the users with `on_delete: :delete_all` (not null); `code_hash` binary (not null); `inserted_at` only; a **unique index on `(user_id, code_hash)`**.

**They work on Postgres and SQLite alike:** the array columns are `{:array, :string}`, a native array on Postgres and JSON text on SQLite (which ecto_sqlite3 encodes and decodes for an array field itself); no query looks inside them.

```test:migrations-write
the task writes three files named <14 digits>_create_macaw_auth_users.exs, _create_macaw_auth_sessions.exs and _add_macaw_auth_second_factor.exs, in that order by name, defining MyApp.Repo.Migrations.CreateMacawAuthUsers, …CreateMacawAuthSessions and …AddMacawAuthSecondFactor, and says "* creating <path>" for each
```

```test:migrations-tables
the migrated test database has exactly the users, sessions and recovery-code columns listed, the unique indexes on username, token_hash and (user_id, code_hash), and both foreign keys to macaw_auth_users with ON DELETE CASCADE
```

## 3. Only the missing ones {#auth-migrations-missing}

A file counts as present when the directory holds any `*_<name>.exs`. **The task writes only the files not yet there:** a host that has the users and sessions migrations gets the second factor's added after them, and **a host that has all three is refused** (`"<dir> already has the macaw_auth migrations (create_macaw_auth_users, create_macaw_auth_sessions, add_macaw_auth_second_factor)"`), so no table or column is ever created twice.

```test:migrations-refuse-again
running the task a second time raises "already has the macaw_auth migrations" and the directory still holds three files
```

```test:migrations-only-missing
with only the users file present, the task writes the sessions and second-factor files and leaves the users file alone; with users and sessions present, it writes only the second factor's, named after the sessions file
```

## 4. Ordering {#auth-migrations-order}

Files are timestamped as `mix ecto.gen.migration`'s (`YYYYMMDDhhmmss`, UTC), **one second apart,** so they run in their order. The first is **now, or one second after the latest migration already in the directory when that is later** (any `*.exs` whose name starts with a valid timestamp): a second run within the same second, or a directory with a migration dated ahead, still gets unique versions that run after what is there, and the second factor's file always runs after the users table's.

```test:migrations-after-existing
a directory holding a migration timestamped one hour ahead gets the macaw_auth files timestamped after it, one second apart
```
