# 05 — Native: configuration and sign-in {#auth-native}

`Macaw.Auth.Native` is the native backend: users and sessions in the host's database, passwords checked by a chain of sources, sign-in failures throttled, a TOTP second factor. It implements every `Macaw.Auth.Backend` callback ([01 §2](01-contract.md#auth-backend)):

```elixir
config :macaw_auth, backend: Macaw.Auth.Native

config :macaw_auth, Macaw.Auth.Native,
  repo: MyApp.Repo,
  sources: [%{type: :password}, %{type: :ldap, name: "nas", ...}],
  session_idle_days: 14
```

| Callback | Implemented by |
|---|---|
| `authenticate/2` | `Macaw.Auth.Native.authenticate/2` (§1), the source chain ([06](06-native-sources.md)), the throttle ([10](10-native-throttle.md)) |
| `create_session/2`, `fetch_session/2`, `fetch_session_by_id/2`, `list_sessions/2`, `revoke_sessions/2`, `complete_step/3` | `Macaw.Auth.Native.Sessions` ([09](09-native-sessions.md)) |
| `verify_second_factor/3` | `Macaw.Auth.Native.verify_second_factor/3` ([11 §5](11-native-totp.md#auth-totp-verify)) |
| `check_config!/0` | `Macaw.Auth.Native.check_config!/0`: `Macaw.Auth.Native.Config.load!/0` (§2.1) |

## 1. Signing in {#auth-native-authenticate}

`Macaw.Auth.Native.authenticate/2` takes `%{username: _, password: _}` (a missing or non-string value counts as `""`) and options `:remote_ip` (a string or an address tuple, the client's) and `:now` (a `DateTime`, the throttle's clock). It:
1. **asks the throttle** ([10](10-native-throttle.md)) whether the username or the address must wait; the username's key is the username normalized as the users table stores it ([06 §5](06-native-sources.md#auth-user-record)), or one shared key, `:invalid`, for anything that can't be a username;
2. if not, **runs the source chain** ([06 §2](06-native-sources.md#auth-chain));
3. on success, **resets the username's failure count** and returns the user (§3); on a refusal, **counts a failure** for the username and the address.

```test:native-authenticate
a local user signs in as %Macaw.Auth.User{source: "local", second_factor: :none}, with the row's id, username, display name and roles
```

### 1.1 One refusal {#auth-native-refusal}

Whatever a source's reason, the caller sees one of three refusals:
- **`:disabled`**, only for a disabled user who gave the right password, so a disabled account can't be probed;
- **`:throttled`**, while a wait runs (§1.2);
- **`:invalid_credentials`** for everything else: a wrong password, an unknown user, an invalid username, a directory that refused, a provisioning refusal ([06 §4](06-native-sources.md#auth-provision)).

The specific reason, and the source, go to telemetry (§1.3) and to `mix macaw_auth.ldap.check` ([07 §7](07-native-ldap.md#auth-ldap-check)), never to the visitor.

```test:native-one-refusal
a wrong password, an unknown username, "not a name!", an empty password and %{} all give {:error, :invalid_credentials}; a disabled user gets :disabled with the right password and :invalid_credentials with a wrong one
```

### 1.2 Throttled {#auth-native-throttled}

While the username or the address waits, **the password is not checked, but a hash's time is still spent** (the configured hasher's `no_user_verify/0`), so a blocked attempt takes as long as a checked one, and the response time doesn't tell a guesser when the block starts or ends. The refusal is `{:error, :throttled}`. **A throttled attempt is not counted as a failure:** only a checked refusal adds to the counts, so the wait grows with checked guesses, not with retries inside it.

```test:native-throttled-no-hash-check
with a counting hasher, a blocked attempt with the right password spends no_user_verify and never verify, and is {:error, :throttled}
```

```test:native-throttled-not-counted
five failures, then attempts inside the one-second wait are throttled; a failure after the wait makes the next wait two seconds, not more
```

### 1.3 Telemetry {#auth-native-telemetry}

Every attempt emits `[:macaw_auth, :native, :authenticate]` with `%{count: 1}` and `%{result: :ok | :error, reason: atom | nil, source: name | nil, user_id: id | nil}`: `reason` the deciding source's own (or `:throttled`), `source` its name, `user_id` on success. **Never the username or the password.**

```test:native-telemetry
a wrong password at the directory "nas" emits %{result: :error, reason: :invalid_credentials, source: "nas"}, whose inspection doesn't contain the password; a success emits %{result: :ok, source: "nas", user_id: id}
```

```test:native-telemetry-throttled
a throttled attempt emits %{count: 1} with %{result: :error, reason: :throttled, user_id: nil}
```

## 2. The configuration {#auth-native-config}

`Macaw.Auth.Native.Config` is the backend's configuration, `config :macaw_auth, Macaw.Auth.Native, …`, parsed once into a struct with **every fault named** (exio's `AuthConfig` approach):

| Key | What | Default | Checked |
|---|---|---|---|
| `repo` | the host's `Ecto.Repo`, holding the tables | required | a module (an atom but `nil`, `true`, `false`) |
| `hasher` | `Macaw.Auth.Native.Hasher.Bcrypt` or `.Argon2` ([08](08-native-hashers.md)) | `Bcrypt` | loaded, with its library ([08 §1](08-native-hashers.md#auth-hasher-behavior)) |
| `sources` | the chain, in order ([06](06-native-sources.md)) | `[%{type: :password}]` | a non-empty list of maps, each a known type, parsed by its source, names unique |
| `session_idle_days` | how long a session may go unused ([09 §3](09-native-sessions.md#auth-sessions-touch)) | 14 | an integer in 1..3650 |
| `totp_issuer` | the name an authenticator app shows ([11 §3](11-native-totp.md#auth-totp-enroll)) | `"Macaw"` | a non-empty string without a colon (it prefixes the otpauth label) |
| `totp_required` | whether policy requires a second factor ([11 §7](11-native-totp.md#auth-totp-policy)) | false | `false`, `true`, or a non-empty list of non-empty role names |
| `sealing_key` | what TOTP secrets are sealed with ([11 §4](11-native-totp.md#auth-totp-seal)) | nil | a binary of at least 32 bytes, or `{module, function, args}` |

- **An unknown key is a fault:** `":shade: is not a Macaw.Auth.Native setting"`.
- **Faults read as `<key>: <what is wrong>`:** `"repo: is required (the host's Ecto.Repo)"`, `"session_idle_days: must be an integer in 1..3650, got 0"`, `"totp_issuer: must not contain a colon"`, `"totp_required: a list of roles must be non-empty role names (strings)"`, `"sealing_key: must be at least 32 bytes"`; a source's as `sources[<name>].<key>: …` ([06 §1.1](06-native-sources.md#auth-source-settings)).
- **A source map may use string keys and a string `type`,** as a JSON or `config.exs` file writes them; a known key or type becomes its atom only by lookup among the known ones, never by creating an atom. An unknown type is `"sources: unknown type :oauth; one of :password, :ldap"`.
- **The sealing key is never shown:** the struct's inspection leaves `sealing_key` out, and no message contains it. A literal key shorter than 32 bytes is refused here; a missing one, or a function's short result, at first use ([11 §4](11-native-totp.md#auth-totp-seal)).

```test:native-config-defaults
parse([repo: Repo]) gives the Bcrypt hasher, one Password source named "local", session_idle_days 14, totp_issuer "Macaw", totp_required false, sealing_key nil
```

```test:native-config-faults
parse([]) is {:error, "repo: is required (the host's Ecto.Repo)"}; shade: 1, hasher: String, sources: [], sources: [%{type: :oauth}], two password sources, session_idle_days 0, 3651, "14", 1.5 or nil, totp_required [] or "yes", totp_issuer "a:b", sealing_key "too short a key" or 42 each give its named fault
```

```test:native-config-sealing-hidden
the inspection of a parsed configuration contains neither "sealing_key" nor the key
```

### 2.1 Reading it once {#auth-native-config-load}

- `Macaw.Auth.Native.Config.parse/2` parses a keyword list or map: `{:ok, config}` or `{:error, message}`. Its option `:env` (a map) is the environment `{:env, VAR}` secrets resolve from, by default the process's.
- `Macaw.Auth.Native.Config.load!/0` parses the application's configuration and keeps it; a fault raises `Macaw.Auth.Native.Config.Error` with `"config :macaw_auth, Macaw.Auth.Native: "` and the fault. **It runs when the application starts with `backend: Macaw.Auth.Native`:** the backend's `check_config!/0` calls it and returns `:ok`, and the application calls that ([01 §2.9](01-contract.md#auth-backend-check-config)), so a bad configuration refuses boot rather than a sign-in.
- The parsed configuration is kept in `:persistent_term`: `Macaw.Auth.Native.Config.get/0` reads it, loading it at first use when boot didn't, and `Macaw.Auth.Native.Config.put/1` replaces it (tests swap it).

```test:native-check-config
with the native backend configured and session_idle_days 0, :macaw_auth refuses to start, the Config.Error naming session_idle_days; with a working configuration, Macaw.Auth.Native.check_config!/0 is :ok, keeps that configuration, and the application starts
```

```test:native-config-load
with sources: [%{type: :ldap}] configured, load!/0 raises Config.Error "config :macaw_auth, Macaw.Auth.Native: sources: a source of type ldap needs a name"
```

## 3. Users {#auth-native-users}

`Macaw.Auth.Native.to_user/1` makes a users row ([06 §5](06-native-sources.md#auth-user-record)) the contract's `%Macaw.Auth.User{}`: its id, username, display name, source, roles (`[]` when nil), `disabled` when `disabled_at` is set, `must_change_password`, `extra` (`%{}` when nil), and `second_factor` from the row and the configured policy ([11 §7](11-native-totp.md#auth-totp-policy)).

`Macaw.Auth.Native.create_user/1` makes a local user from `:username` and a non-empty `:password`, and optionally `:display_name`, `:roles`, `:must_change_password` and `:extra`: the password hashed with the configured hasher, `source` the configured `Password` source's name (`"local"` when none is configured). `{:ok, record}` or `{:error, changeset}`; a username taken, in any case, is a changeset error. There is no registration: this is how a host makes a local user. Listing, disabling, enabling and deleting users, their passwords and roles, and the first admin at boot are [13](13-native-users.md)'s.

```test:native-create-user
create_user(%{username: "Alice", password: …}) stores username "alice" with a bcrypt hash and source "local"; then create_user(%{username: " Frank"…}) after "frank" exists is {:error, changeset} with "has already been taken" on username
```
