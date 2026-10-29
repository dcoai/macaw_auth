# 13 — Native: administering users {#auth-users}

A host administers the native backend's users without writing code for it: its first admin made at boot, and the everyday commands (list, add, disable, enable, delete, a password, roles, a lost second factor) from a terminal during development (`mix macaw_auth.user`) and on a deployed host through its `<app>-ctl` (the release entry points). macaw_compose#32 proposed them, and #75 scoped them; deleting a user came with macaw#93, for an adopter moving its users onto the library. All three run the same functions of `Macaw.Auth.Native` (§1) through one implementation of the commands, `Macaw.Auth.Native.UserCommands` (§3).

## 1. The user functions {#auth-users-api}

`Macaw.Auth.Native`'s public functions for administering users, beside `create_user/1` ([05 §3](05-native-config.md#auth-native-users)) and `admin_reset/2` ([11 §8](11-native-totp.md#auth-totp-disable)). A user is named by username, **trimmed and lower-cased as sign-in matches it** ([06 §5](06-native-sources.md#auth-user-record)):
- `Macaw.Auth.Native.list_users/0`: every user, local and directory, **by username**;
- `Macaw.Auth.Native.get_user/1`: the user named, or nil, also for a string that can't be a username;
- `Macaw.Auth.Native.disable_user/1`: sets `disabled_at`, so sign-in is refused (`:disabled` to someone with the right password, [05 §1.1](05-native-config.md#auth-native-refusal)) and each session at its next look-up, so open pages leave at their next re-check ([09 §4](09-native-sessions.md#auth-sessions-disabled)). **A user already disabled keeps when it was first done.** `{:ok, record}` or `{:error, :not_found}`;
- `Macaw.Auth.Native.enable_user/1`: clears `disabled_at`; `{:ok, record}` or `{:error, :not_found}`;
- `Macaw.Auth.Native.delete_user/2`: **every session of theirs revoked** (reason `:user_deleted`), **then the row deleted,** local or directory; its sessions and recovery codes go with it by the schema's cascade ([12](12-native-migrations.md)), as does any row of the host's that references it with `on_delete: :delete_all`. Signing in as them is then **refused as an unknown user's is** (`:invalid_credentials`, [05 §1.1](05-native-config.md#auth-native-refusal)). `{:ok, record}`, the row as it was, or `{:error, :not_found}`, also when another deletion took the row between the look-up and the delete. **A directory user deleted is made again** at their next sign-in the directory accepts ([06 §4](06-native-sources.md#auth-provision)): to keep them out, remove them from the directory, or disable them. It is the administrator's way to remove a user, so a host never deletes the row with its own repo, which would skip the revocation's push and couple the host to the table;
- `Macaw.Auth.Native.set_password/3`: **a local user's** new password, hashed with the configured hasher, and **every session of theirs revoked** (reason `:password_changed`), so whoever held the old password is signed out. `{:error, :not_local}` for a directory user, whose password the directory checks and is never set here; `{:error, :no_password}` for nil or `""`; `{:error, :not_found}`;
- `Macaw.Auth.Native.set_roles/2`: **a local user's** roles replaced, a list of non-empty strings (`{:error, :invalid_roles}` otherwise). `{:error, :not_local}` for a directory user, whose roles are re-derived from the directory at each sign-in ([06 §4](06-native-sources.md#auth-provision)); `{:error, :not_found}`.

A user is local when their `source` is the configured `Password` source's name (`"local"` when none is configured), as `create_user/1` makes them.

**The revocations an administrator's change makes** (`set_password/3`, `admin_reset/2`, `delete_user/2`) go through `Macaw.Auth.Native.Sessions.revoke_all/3` ([09 §5](09-native-sessions.md#auth-sessions-revoke)), which tells the user's open pages, which disconnect. **Option `announce: false`** revokes without telling them: a process that is not the app's node (a mix task, a release's `eval`) has no page to tell, and the pages leave at their next re-check ([03 §4](03-live.md#auth-live-recheck)).

```test:users-list-get
with carol, alice and a directory user bob, list_users/0 gives alice, bob, carol; get_user(" Alice ") is alice; get_user of "nobody" and "not a name!" is nil
```

```test:users-disable-enable
disable_user("dave") refuses dave's sign-in with :disabled; disabling "DAVE" again keeps the first disabled_at; enable_user lets him sign in; both answer {:error, :not_found} for nobody
```

```test:users-delete
delete_user(" Mona ") of mona, enrolled, with two sessions and recovery codes, answers her row; her user, session and recovery-code rows are gone, her token no longer resolves, a subscriber hears {:sessions_revoked, [_, _]}, and signing in as her is {:error, :invalid_credentials} as for nobody; with announce: false nothing is heard; a directory user is deleted too; nobody is {:error, :not_found}
```

```test:users-set-password
set_password("frank", new) refuses the old password and accepts the new; frank's session token no longer resolves and a subscriber hears {:sessions_revoked, [_]}; with announce: false the token is revoked and nothing is heard
```

```test:users-set-password-refused
set_password of a directory user is {:error, :not_local}, their hash still nil; of "" and nil {:error, :no_password}; of nobody {:error, :not_found}
```

```test:users-set-roles
set_roles("ivy", ["admin", "editor"]) is what her next sign-in carries; a directory user's is {:error, :not_local} and unchanged; [""] and "admin" are {:error, :invalid_roles}; nobody is {:error, :not_found}
```

```test:users-admin-reset-quiet
admin_reset(user, announce: false) of an enrolled user with a session clears the factor and its recovery codes and revokes the session, and a subscriber hears nothing
```

## 2. The first admin {#auth-users-bootstrap}

`Macaw.Auth.Native.bootstrap_admin/1` makes the first user, **a local one with the given role, only when no user exists:**
- it takes `:username`, `:password` and `:role`, and optionally `:display_name` and `:must_change_password`;
- `{:ok, record}` when it made one; **`:exists` when any user is there,** local or a directory's, whoever it is. **It is idempotent and safe to call at every boot:** with users there, neither the password nor the role is looked at, so a host may stop providing the password once its admin exists;
- with no user yet, `{:error, :no_password}` for a missing or empty password, `{:error, :no_role}` for a missing or empty role, `{:error, changeset}` for an invalid username;
- **two first boots at once** with the same username make one user: the second insert meets the unique index on `username`, and that call answers `:exists`. Two at once with different usernames would make two users; a host bootstraps from one configuration, so they share the username.

**There is still no registration** ([00 §5](00-overview.md#auth-closed)): the first admin is the host's, its name, password and role given by the host, and nothing is made once any user exists.

```test:users-bootstrap
bootstrap_admin of "Root" with role "admin" makes root, local, roles ["admin"], who signs in; two more calls with another password are each :exists, the old password still signs in and the new doesn't, and there is one user
```

```test:users-bootstrap-exists
with a local user there, bootstrap_admin is :exists, with or without a password, and no root is made; with only a directory user there, it is :exists too
```

```test:users-bootstrap-needs
with no user, an empty or nil password is {:error, :no_password}, an empty or missing role {:error, :no_role}, "not a name!" {:error, changeset} with a username error, and nothing is made
```

## 3. The commands {#auth-users-commands}

`Macaw.Auth.Native.UserCommands` is the one implementation of the commands, for the mix task (§4) and the release entry points (§5). `Macaw.Auth.Native.UserCommands.run/3` takes the words, the password (the value of the password's environment variable, or nil), and options: `:password_var`, the variable's name, for messages; `:announce`, passed to the revoking functions (§1). It answers `{:ok, objects}`, printed **one JSON object per line,** or `{:error, message}`: **a user's mistake is an answer, never a raise.** Before running a command it makes ready what the command needs (`Macaw.Auth.Native.UserCommands.start/0`): the native backend's configuration (`Macaw.Auth.Native.Config.fetch/0`, a fault answered as an error) and its repo, **started without query logging** when it isn't running, so nothing but the answer reaches stdout and no query's parameters (a password's hash) reach a log.

| Words | Answer |
|---|---|
| `list` | one object per user, by username: `{username, display_name, source, roles, disabled, must_change_password, second_factor}`, `second_factor` as the contract's (`"none"`, `"required"` or `"enrolled"`) |
| `add NAME --role R [--role R…]` | a local user (`create_user/1`) with those roles and the password: `{"ok": true, "added": NAME, "roles": [R…]}` |
| `disable NAME` | `{"ok": true, "disabled": NAME}` |
| `enable NAME` | `{"ok": true, "enabled": NAME}` |
| `delete NAME` | the user deleted with their sessions (`delete_user/2`): `{"ok": true, "deleted": NAME}` |
| `password NAME` | the password set (`set_password/3`): `{"ok": true, "password_set": NAME}` |
| `roles NAME R…` | the roles replaced (`set_roles/2`): `{"ok": true, "roles_set": NAME, "roles": [R…]}` |
| `reset-second-factor NAME` | the second factor cleared and the sessions revoked (`admin_reset/2`): `{"ok": true, "second_factor_reset": NAME}` |

- **NAME in an answer is the stored username,** lower case.
- **A role is a word, not a flag:** `add` needs at least one `--role`, and `roles` at least one role; a role that is empty or starts with `-` is a usage error.
- **The errors:** `"no user named NAME"`; `"NAME's roles come from the directory SOURCE"` and `"NAME's password is checked by the directory SOURCE"` for a directory user; a changeset's errors on one line, `"username: has already been taken"`; for a missing password, `"set VAR to the password (it is never read from the command line)"`; for any other shape of words, `"usage: "` and the commands (`Macaw.Auth.Native.UserCommands.usage/0`).
- **Words are matched as strings;** nothing typed becomes an atom ([macaw_host 03 §1](https://github.com/dcoai/macaw_host/blob/main/spec/03-release.md#host-release-protocol)).

```test:users-commands
add Alice with roles admin and ops answers added "alice", and she signs in with them; list shows alice and a directory user erin, each with the seven keys; roles, password, disable, enable and reset-second-factor each answer their object and change what they say
```

```test:users-delete-command
delete " Nora " answers deleted "nora", and nora is gone with her session; delete of nobody is "no user named nobody"; delete with no name or with two names is the usage error
```

### 3.1 A password never comes from the command line {#auth-users-passwords}

**A password never comes from the command line,** where `ps` and shell history show it: `add`, `password` and `bootstrap` take it from an environment variable (§4, §5), and **a `--password`, `--password=…` or `-p` anywhere among the words is refused** before anything runs, `"a password is never read from the command line: set VAR to it instead"`. **No message repeats a word it didn't understand,** which may be a password typed in the wrong place: a stray word is a usage error, and the only word an answer repeats is a user's name. The password appears in no answer.

```test:users-password-argv
add carol with --password hunter2, --password=hunter2 or -p hunter2, and password bob with --password or -p, are each refused with exit status 1 and one error line naming the variable and "never read from the command line", without "hunter2"; a stray hunter2 after add carol or password bob is a usage error without it; carol isn't made, bob's password is unchanged
```

```test:users-password-env
add and password with the variable unset or empty answer "set VAR …" with exit status 1, and make no user
```

## 4. mix macaw_auth.user {#auth-users-task}

`mix macaw_auth.user` (`Mix.Tasks.MacawAuth.User`) runs the commands (§3) against the configured repo, after loading the app's configuration (`app.config`):

```sh
mix macaw_auth.user list
MACAW_AUTH_USER_PASSWORD='…' mix macaw_auth.user add alice --role admin
```

- **The password** is the `MACAW_AUTH_USER_PASSWORD` environment variable.
- **The output** is one JSON object per line on stdout. **An error** is one JSON object, `{"ok": false, "error": "…"}`, on stderr, and **the task exits with status 1,** never with a stack trace.
- The task runs apart from the app, so it revokes **with `announce: false`** (§1).

```test:users-task-errors
disable nobody, roles and password of a directory user, add of a taken name, add without a role, roles without one, frob and no words each print exactly one stderr line {"ok": false, "error": …} with the message of §3 and exit with status 1
```

## 5. Release entry points {#auth-users-release}

`Macaw.Auth.Native.Release` puts the commands on **macaw_host's release protocol** ([macaw_host 03 §1](https://github.com/dcoai/macaw_host/blob/main/spec/03-release.md#host-release-protocol)), through `Macaw.Host.Release`, so an app's `<app>-ctl` runs them:
- **`Macaw.Auth.Native.Release.bootstrap/0`:** `bootstrap NAME --role R`, the first admin (§2) through `Macaw.Auth.Native.UserCommands.bootstrap/3`, safe at every deployment: `{"ok": true, "created": NAME, "role": R}`, or, once any user exists, `{"ok": true, "created": null, "reason": "a user already exists"}`. Any other shape of words is `"usage: bootstrap NAME --role R"`;
- **`Macaw.Auth.Native.Release.user/0`:** the commands of §3;
- **the arguments** are the JSON array of strings in `<PREFIX>_CTL_ARGS` (`Macaw.Host.Release.ctl_args!/1`), **the password** `<PREFIX>_CTL_PASSWORD` (`ctl_password/1`), never on a command line; **malformed arguments** fail as macaw_host says, `"<PREFIX>_CTL_ARGS must be a JSON array of strings"` on stderr and exit status 1;
- **the output** is one JSON object per line on stdout (`emit/1`); **a failure** is one line on stderr, `{"ok": false, "error": "…"}`, and exit status 1 (`fail/1`), never a stack trace;
- **`<PREFIX>` is the app's `:env_prefix`** ([macaw_host 06 §3.1](https://github.com/dcoai/macaw_host/blob/main/spec/06-ctl-generator.md#host-gen-required)), configured as `config :macaw_auth, Macaw.Auth.Native.Release, env_prefix: "MY_APP"`. **It has no default:** without it, both fail with `"config :macaw_auth, Macaw.Auth.Native.Release, env_prefix: is not set"`. `Macaw.Auth.Native.Release.bootstrap/1` and `Macaw.Auth.Native.Release.user/1` take the prefix instead, for an app's release module to delegate to;
- they run where `bin/<app> eval` runs, a throwaway container of the image ([macaw_host 07 §6](https://github.com/dcoai/macaw_host/blob/main/spec/07-ctl-script.md#host-script-docker)), so they work with the app stopped, **revoking with `announce: false`** (§1).

The app's own commands ([macaw_host 06 §4](https://github.com/dcoai/macaw_host/blob/main/spec/06-ctl-generator.md#host-gen-app-commands)) run them with `Ctl.Docker.eval_args/3`, the expression `Macaw.Auth.Native.Release.user()` (or `bootstrap()`), the words as JSON and the password **passed by name:**

```elixir
eval_args(env, "Macaw.Auth.Native.Release.user()", [
  {"MY_APP_CTL_ARGS", JSON.encode!(["add", name, "--role", "admin"])},
  {"MY_APP_CTL_PASSWORD", password}
])
```

```test:users-release-bootstrap
bootstrap of Root with role admin answers created "root" and role "admin", and root signs in; again, with another password or none, it answers created null and "a user already exists", and there is one user
```

```test:users-release-commands
user/1 runs add, list, roles, password, disable, enable and reset-second-factor, the words in <PREFIX>_CTL_ARGS and the password in <PREFIX>_CTL_PASSWORD, each answering the object of §3
```

```test:users-release-delete
user/1 with ["delete", "alice"] answers {"ok": true, "deleted": "alice"}, and alice is gone and can't sign in; ["delete", "nobody"] fails with {"ok": false, "error": "no user named nobody"} and exit status 1
```

```test:users-release-fresh-vm
in a fresh VM with only the build's code paths, over its own migrated SQLite database and env_prefix "RT": bootstrap/0 creates root once and then answers "a user already exists", both with exit status 0 and nothing on stderr; user/0 adds alice and lists her, the password nowhere in the output
```

```test:users-release-fresh-vm-errors
in a fresh VM, disable nobody and frob each print exactly one stderr line {"ok": false, "error": …} and exit 1 with nothing on stdout; a --password among the arguments is refused without echoing it; RT_CTL_ARGS "not json" and "[1, 2]" give exactly "RT_CTL_ARGS must be a JSON array of strings\n" and exit 1; without env_prefix, bootstrap/0 and user/0 each give the not-set line and exit 1
```

## 6. No store behavior yet {#auth-users-store}

The native backend's users and sessions are Ecto only. The `Store` behavior that macaw_compose#32 proposed, to put another store behind them, **stays out until uficap adopts `macaw_auth`** (macaw_compose#75).
