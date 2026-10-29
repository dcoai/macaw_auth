# 06 — Native: sources and the chain {#auth-sources}

Where `Macaw.Auth.Native` checks a password: `Macaw.Auth.Native.Source`, a behavior, and the chain that tries the configured sources in order (ported from exio's `sign_in/3`). Two sources ship, `Macaw.Auth.Native.Source.Password` (§3) and `Macaw.Auth.Native.Source.Ldap` ([07](07-native-ldap.md)). A source is a struct, made from its configuration and dispatched on its module, so adding one is a module, not a case in the chain.

## 1. The source behavior {#auth-source-behavior}

A source implements:
- **`parse(config, context)`:** its struct from its configuration (a map with atom or string keys), `{:ok, source}`, or `{:error, "sources[<name>].<key>: …"}` naming what is wrong. `context` carries `:repo`, `:hasher` and `:env` (the environment for `{:env, VAR}` secrets);
- **`authenticate(source, username, password, opts)`:** `{:ok, attrs}` for a user it accepted, or `{:error, reason}`. `attrs` is either **`%{record: row}`**, for a source that keeps the user's row (`Password`), or **what it knows about the user**, `%{username, display_name, roles, extra}` and, from a directory, `external_id` (the binary it identifies the entry by, §6), from which the chain provisions the row (§4);
- **`knows?(source, reason)`:** whether a refusal with `reason` means the source knows the user, and so decides (§2);
- **`explain(reason)`:** a sentence explaining a reason, for logs and diagnostics.

### 1.1 Source settings {#auth-source-settings}

Every source's settings are checked the same way:
- **a name** is 1–32 of `a-z 0-9 _ -`, starting with a letter or digit; a password source defaults to `"local"`, an LDAP source must have one (`"sources: a source of type ldap needs a name"`). **Names are unique** across the chain (`"sources[local].name: is used by two sources"`): a name is the `source` of the rows it provisions;
- **an unknown key is a fault,** `"sources[nas].hostname: is not a known setting"`; a string key that isn't known stays a string, so it is named too, never made an atom;
- **a fault names the source and the key** (`sources[nas].port: must be in 1..65535`), and **no message ever holds a secret;**
- **a secret** (an LDAP `search.bind_password` or `groups.bind_password`, [07 §1.4](07-native-ldap.md#auth-ldap-groups-config)) is a literal non-empty string, `{:env, "VAR"}` or `{:file, path}` (a trailing newline trimmed), **resolved when the configuration is read,** so a reference that can't be read refuses the configuration rather than a sign-in: `"the environment variable LDAP_PW is not set"`, `"<path> is empty"`, `"cannot read <path>: <reason>"`.

```test:source-settings
a password source with hasher: :x is "sources[local].hasher: is not a known setting"; an LDAP source named "Bad Name" is "sources[\"Bad Name\"].name: must be …"; {:env, "LDAP_PW"} resolves from the :env option, and unset is "sources[nas].search.bind_password: the environment variable LDAP_PW is not set"
```

## 2. The chain {#auth-chain}

`Macaw.Auth.Native.Source.run/5` (`sources`, `repo`, `username`, `password`, `opts`) tries the sources in their configured order, and **the first that knows the user decides:**
- **an acceptance signs the user in:** a source's own row as it is, or a row the chain provisions (§4). `{:ok, record, source}`;
- **a refusal by a source that knows the user is final:** a wrong password there never falls through to the next source, or one account's password could be guessed against another's. `{:error, reason, source}`;
- **a refusal by a source that doesn't know the user passes the attempt on:** no such user, a directory it couldn't reach, a direct-bind directory that can't tell a wrong password from a missing entry ([07 §6](07-native-ldap.md#auth-ldap-knows));
- **when no source knows the user,** the result is the last source's refusal (`{:error, :invalid_credentials, nil}` with no sources);
- **a provisioning refusal is final** (`{:error, reason, source}`).

```test:chain-order
two directories that both have "ann": her first directory's password signs her in from it and only it is asked; her second directory's password is refused, still asking only the first; "ben", known only to the second, signs in from the second after both are asked
```

```test:chain-no-fallthrough
with [local, directory], a local user's directory password is refused without the directory being asked
```

```test:chain-unreachable
with [unreachable directory, local], a local user signs in, and a wrong password is :invalid_credentials
```

```test:chain-none-knows
with [local, directory] and a username neither has, the directory is asked too, and the refusal is :invalid_credentials
```

## 3. Local passwords {#auth-source-password}

`Macaw.Auth.Native.Source.Password`: users with a `macaw_auth_users` row that has a password hash. `%{type: :password}` (named `"local"`) or `%{type: :password, name: "staff"}`; its only keys are `type` and `name`.

- **It knows a user whose row has a password hash.** A directory user's row (no hash) is not its to judge, and the attempt passes on (`:no_user`).
- **The username is normalized** (§5) before it is looked up, so `"  BOB "` is `bob`.
- **An unknown user and a wrong password take the same time:** an unknown user (or an invalid username, or a row without a hash) spends the hasher's `no_user_verify/0`, so the response time can't tell which usernames exist. A missing password is checked as `""`.
- **The password is checked before the account's state,** so `:disabled` is only ever said to someone who knows the password.
- **A hash made with other parameters, or by the other algorithm, is replaced** at a successful sign-in ([08 §3](08-native-hashers.md#auth-hasher-rehash)).

Its reasons: `:no_user` (doesn't know the user), `:invalid_credentials`, `:disabled`.

```test:password-timing-work
with a counting hasher: an unknown user and an invalid username each spend no_user_verify; a wrong password spends verify and not no_user_verify
```

```test:password-timing-measured
at bcrypt cost 9, the median time to refuse an unknown user and a wrong password (nine each, the throttle emptied before each) are within a factor of three
```

```test:password-trim-case
a user made as "Alice" is stored as "alice" and signs in as "alice"; a user "bob" signs in with the username "  BOB "
```

```test:password-directory-row
a row with source "nas" and no hash refuses "" and "anything" with :invalid_credentials through the chain
```

## 4. Provisioning directory users {#auth-provision}

`Macaw.Auth.Native.Provision` is where the chain makes them: `Macaw.Auth.Native.Provision.directory_user/3` (`repo`, the source's name, its `attrs`) gives the row for a user a directory accepted (ported from exio's `External.resolve/2`):
- **first sign-in:** a new row with the directory's normalized username, `source` the directory's name, **no password**, and its display name, roles, external id (§6) and `extra`;
- **every later sign-in: the directory's word replaces** the row's roles, display name and external id, and its `extra` is merged over the row's. The directory is the authority on who is in which group, so a user removed from an admin group loses the role at their next sign-in, not whenever someone remembers to edit the row;
- **a row with that username that another source owns** (a local user, or another directory's) **is never taken over:** `{:error, :username_taken}`. A directory that happens to have an `owner` entry doesn't become the local `owner`;
- **a disabled row stays refused,** `{:error, :disabled}`, whatever the directory says, and is left as it is;
- **a directory username that isn't a valid one** is `{:error, :invalid_username}`, and no row is made;
- **two first sign-ins at once:** the second insert fails on the unique username; it re-reads, once, and uses the row the other made. Any other insert failure is a bug, and raises.

```test:provision-first
a directory user's first sign-in makes a row with source "nas", no hash, the directory's display name and roles, and extra %{"groups" => ["staff"]}; the next sign-in finds the same row (one row in all)
```

```test:provision-refresh
roles edited locally to ["superuser"] are back to the directory's ["viewer", "admin"] at the next sign-in; removed from "admins" in the directory, the user signs in with ["viewer"] and the row says so
```

```test:provision-no-takeover
a directory entry "owner" never signs in as the local "owner", whichever order the sources are in, and the local row keeps source "local"; a user provisioned by directory "a" is refused by directory "b"
```

```test:provision-no-takeover-ldap
on the fixture directory, through the chain: its "owner" entry's password never signs in as the local "owner", with [local, directory] or [directory, local]; the local owner signs in from "local", and there is one row
```

```test:provision-disabled
a disabled directory user is refused :disabled and their row's roles stay as they were
```

```test:provision-invalid-username
a directory username "Bad User" is refused :invalid_credentials and no row is made
```

## 5. The users row {#auth-user-record}

`Macaw.Auth.Native.UserRecord` is a row of `macaw_auth_users` ([12](12-native-migrations.md)):
- **`username` is stored normalized** and unique. `Macaw.Auth.Native.UserRecord.normalize_username/1` trims and lower-cases, then requires **1–64 characters of `a-z 0-9 . _ @ + -`, starting with a letter or digit:** `{:ok, name}` or `{:error, :invalid_username}`. Nothing else is rewritten, so two distinct inputs never become one user, and `Alice` and `alice ` are one user on every database without a case-insensitive collation;
- `hashed_password` is nil for a directory user; `source` names the owning source (`"local"` by default); `roles` a list of strings (`[]`); `disabled_at` set means refused; `must_change_password` (false); `external_id` a directory user's id (§6), nil for a local user; `extra` (`%{}`) holds what a source knows beyond these (an LDAP DN, email) and the host's own fields;
- `totp_secret_sealed`, `totp_enabled_at` and `totp_last_step` are the second factor's ([11](11-native-totp.md)): only `Macaw.Auth.Native.Totp` writes them, each by a conditional update, and `changeset/2` never casts them;
- `hashed_password` and `totp_secret_sealed` are redacted from inspection;
- `Macaw.Auth.Native.UserRecord.changeset/2` casts the rest but `external_id`, which only `Macaw.Auth.Native.Provision` writes, requires `username` and `source`, normalizes the username (an invalid one is the error `"must be 1–64 of a-z 0-9 . _ @ + -"`) and checks it unique.

```test:username-normalize
normalize_username(" Alice ") is {:ok, "alice"}; "not a name!", "", a 65-character name, "-x" and nil are {:error, :invalid_username}
```

## 6. The external id {#auth-external-id}

A directory identifies an entry by an id of its own (an LDAP source's `id_attr`, [07 §3](07-native-ldap.md#auth-ldap-flow)): **the id is the binary the directory gave,** whatever its bytes. An `entryUUID` is text, an `objectGUID` sixteen bytes that mostly don't print. The source hands it over as it is (`attrs.external_id`), and the row holds it as `external_id`; a local user has none (nil).

**The column holds one spelling of it for every value: lower-case hex of its bytes** (`Macaw.Auth.Native.ExternalId`, an Ecto type, `:string` in the database). Encoding at this edge, never in the source, is what keeps it one id:
- **no value has two spellings,** and **no two values share one:** hex is a bijection on byte strings. (Earlier releases kept the value itself when it printed and hex otherwise, so the text `"00ff"` and the bytes `<<0, 255>>` were both spelled `00ff`, and one id's spelling turned on a test of its bytes);
- **read back, it is the directory's binary,** exactly (`Macaw.Auth.Native.ExternalId.decode/1`);
- it is text every database stores, compares and indexes alike, with **no case or padding variants** (upper-case hex or Base64 would have them), so a query by it (`get_by(UserRecord, external_id: binary)`, the type spelling the binary) matches on every database;
- **a column value that isn't lower-case hex fails the load** (`ArgumentError`): a row written by anything else is a bug surfaced, not a value guessed at.

```test:external-id-spelling
through the chain from the fake directory: an entryUUID, a 16-byte objectGUID and the printable "00ff" are stored as lower-case hex of their bytes ("30306666" for "00ff"), each read back as the directory gave it, and found by get_by external_id; without the attribute the source hands over the DN; the next sign-in writes the directory's new id over the row's; a local user's column is nil
```

```test:external-id-load
load of "ABCD", "abc", "zz" or a UUID is :error, "" is {:ok, ""}; cast of an atom and dump of an integer are :error; a row whose column says "NOT HEX" raises ArgumentError when read
```

```test:external-id-one-spelling
property, 50 runs over pairs of binaries: the spelling is lower-case hex, the dump, decode and load give back the binary, and two distinct binaries never share a spelling; "00ff", <<0, 255>>, "abcd", <<0xAB, 0xCD>>, "", " ", "é" and <<233>> have eight spellings
```
