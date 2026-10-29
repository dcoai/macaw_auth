# 12 — Native: migrations {#auth-migrations}

The native backend's tables live in the host's repo, and the host owns their migrations: `mix macaw_auth.gen.migration` (`Mix.Tasks.MacawAuth.Gen.Migration`) writes them into the host's migrations directory, as plain DDL the host can read. **They are the ones this library's own tests run** (the test helper generates them and migrates a fresh SQLite database with them), so what ships is what is tested (macaw_compose#50).

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

## 2. The five files {#auth-migrations-files}

One file each, in this order:
1. **`create_macaw_auth_users`:** `macaw_auth_users` (`Macaw.Auth.Native.UserRecord`, [06 §5](06-native-sources.md#auth-user-record)): `id` binary id primary key; `username` (not null) under a **unique index**; `display_name`; `hashed_password` (nil for a directory user); `source` (not null); `roles` `{:array, :string}` (not null); `disabled_at`; `must_change_password` (not null, default false); `extra` a map (not null); `inserted_at` and `updated_at` in microseconds;
2. **`create_macaw_auth_sessions`:** `macaw_auth_sessions` (`Macaw.Auth.Native.SessionRecord`, [09](09-native-sessions.md)): `id` binary id; `user_id` referencing the users **with `on_delete: :delete_all`** (not null) and indexed; `token_hash` binary (not null) under a **unique index**; `remote_ip`; `user_agent`; `second_factor_passed` (not null, default true); `completed_steps` `{:array, :string}` (not null); `last_used_at` (not null); timestamps;
3. **`add_macaw_auth_second_factor`:** on `macaw_auth_users`, `totp_secret_sealed` (binary), `totp_enabled_at` and `totp_last_step` (bigint); and **`macaw_auth_recovery_codes`** (`Macaw.Auth.Native.RecoveryCodeRecord`, [11 §6](11-native-totp.md#auth-totp-recovery)): `id`; `user_id` referencing the users with `on_delete: :delete_all` (not null); `code_hash` binary (not null); `inserted_at` only; a **unique index on `(user_id, code_hash)`**;
4. **`create_macaw_auth_throttle`:** `macaw_auth_throttle` (`Macaw.Auth.Native.ThrottleRecord`, [10 §6](10-native-throttle.md#auth-throttle-table)), no `id`: `kind` and `subject` (not null) under a **unique index on `(kind, subject)`**, which a check, a failure's upsert and a success each find their rows by; `failures` integer (not null); `last_failure_ms` bigint (not null, milliseconds of the system clock outgrow 32 bits) under a plain index, for the sweep. No foreign key: an address or a name has no user row;
5. **`add_macaw_auth_external_id`:** on `macaw_auth_users`, `external_id` (a string, nil for a local user), a directory user's id in its one spelling ([06 §6](06-native-sources.md#auth-external-id)), and each id an earlier release kept in `extra` moved into it (§5).

**A release that adds a table adds a file,** after the others; it never changes one a host has already run. So a host on an earlier release runs the task again and gets only the new files (§3): from 0.4, the throttle's and the external id's, in that order. **A release that changes how stored values are spelled adds a file too,** rewriting the rows a host has (the external id's, §5).

**They work on Postgres and SQLite alike:** the array columns are `{:array, :string}`, a native array on Postgres and JSON text on SQLite (which ecto_sqlite3 encodes and decodes for an array field itself); no query looks inside them. The external id's rewrite reads and writes rows through `Ecto.Query` on the table (no schema), its `extra` loaded and dumped as `:map`, so it is the same code on both.

```test:migrations-write
the task writes five files named <14 digits>_create_macaw_auth_users.exs, _create_macaw_auth_sessions.exs, _add_macaw_auth_second_factor.exs, _create_macaw_auth_throttle.exs and _add_macaw_auth_external_id.exs, in that order by name, defining MyApp.Repo.Migrations.CreateMacawAuthUsers, …CreateMacawAuthSessions, …AddMacawAuthSecondFactor, …CreateMacawAuthThrottle and …AddMacawAuthExternalId, and says "* creating <path>" for each
```

```test:migrations-tables
the migrated test database has exactly the users (external_id among them), sessions, recovery-code and throttle columns listed, the unique indexes on username, token_hash, (user_id, code_hash) and (kind, subject), the throttle's plain index on last_failure_ms, both foreign keys to macaw_auth_users with ON DELETE CASCADE, and none from the throttle
```

## 3. Only the missing ones {#auth-migrations-missing}

A file counts as present when the directory holds any `*_<name>.exs`. **The task writes only the files not yet there:** a host that has the users and sessions migrations gets the second factor's, the throttle's and the external id's added after them, a host that has the first three (0.4) gets the throttle's and the external id's, one that has the first four the external id's alone, and **a host that has all five is refused** (`"<dir> already has the macaw_auth migrations (create_macaw_auth_users, create_macaw_auth_sessions, add_macaw_auth_second_factor, create_macaw_auth_throttle, add_macaw_auth_external_id)"`), so no table or column is ever created twice.

```test:migrations-refuse-again
running the task a second time raises "already has the macaw_auth migrations" and the directory still holds five files
```

```test:migrations-only-missing
with only the users file present, the task writes the sessions, second-factor, throttle and external-id files and leaves the users file alone; with users and sessions present, it writes the second factor's, named after the sessions file, the throttle's and the external id's; with the first three, the throttle's and the external id's, after them; with the first four, only the external id's, after them
```

## 4. Ordering {#auth-migrations-order}

Files are timestamped as `mix ecto.gen.migration`'s (`YYYYMMDDhhmmss`, UTC), **one second apart,** so they run in their order. The first is **now, or one second after the latest migration already in the directory when that is later** (any `*.exs` whose name starts with a valid timestamp): a second run within the same second, or a directory with a migration dated ahead, still gets unique versions that run after what is there, and the second factor's file always runs after the users table's.

```test:migrations-after-existing
a directory holding a migration timestamped one hour ahead gets the macaw_auth files timestamped after it, one second apart
```

## 5. The external ids moved {#auth-migrations-external-id}

`add_macaw_auth_external_id` runs after the throttle's. **Up,** it adds the `external_id` column, then, for each row whose `extra` has an `"external_id"` key, drops the key (the rest of `extra` stays as it was) and writes the column from the old value. Earlier releases spelled the id as the value itself when it printed (`String.printable?/1`) and as lower-case hex otherwise, so an old value is the directory's bytes when its spelling says which it was:
- **not lower-case hex** (a UUID's dashes, a DN's `=`): it was the value itself; the column gets its hex;
- **lower-case hex of bytes that print:** those bytes would have been kept as themselves, so it too was the value itself (the text `"61626364"`, not `"abcd"`); the column gets its hex;
- **lower-case hex of bytes that don't print:** either spelling could have written it (the text `"12345678"`, an employee number, or the four bytes `12 34 56 78`), so **the column is left nil.** The migration can't read the source's configuration (which attribute, which directory), and nothing needs a guess: a directory user's row is found by username, and **their next sign-in writes the id from the directory** (06 §4). Nothing else reads the column, so until then nothing is wrong, only empty;
- a value that isn't a string (a host's own edit) is dropped the same way, the column nil.

**Down** puts each column value back into `extra["external_id"]` as the earlier release spelled it (the bytes when they print, else the hex), then drops the column; an id left nil stays absent.

Like the other files it is the host's to read: its rewrite is its own code, calling nothing in this library, so a later release changing `Macaw.Auth.Native.ExternalId` never changes what this file did.

```test:migrations-external-id
a database migrated to the throttle's migration holds 0.4's rows (a UUID, the text "61626364", an objectGUID's hex, "12345678", a DN, and a local user); migrated on, the UUID, the text and the DN are their hex in the column and read back as they were, the objectGUID's, "12345678" and the local user's columns are nil, and the key leaves extra with the rest of it kept
```

```test:migrations-external-id-sign-in
after the migration, the objectGUID user signs in from the fake directory to the same row, its column now the GUID's hex and found by it; the UUID user's row is the same and its column unchanged; no row is added; migrated down, each id is back in extra as 0.4 spelled it, "12345678" absent, the local user's extra untouched, and the column gone
```
