# macaw_auth specification

`macaw_auth` is authentication for Phoenix hosts, implemented once for the Macaw family's host applications: a narrow contract an app uses (the current user, plugs and LiveView hooks, sessions, steps and revocation that reaches open pages), with backends behind it, and the native backend (passwords, LDAP, hashed sessions, throttling, TOTP). Each Macaw component has its own spec in its own repository (dco-tek/macaw_compose#61); this is `macaw_auth`'s. The family's overview, and where the host libraries sit in it, is in [macaw_compose 00 §4](https://gitlab.conet.yarina.org/dco-tek/macaw_compose/-/blob/main/spec/00-overview.md#overview-packaging). The Ash backend has its own spec, in [macaw_auth_ash](https://gitlab.conet.yarina.org/dco-tek/macaw_auth_ash/-/blob/main/spec/README.md).

| File | Covers | Status |
|---|---|---|
| [00 — Overview](00-overview.md) | what `macaw_auth` holds, the contract-plus-backends shape, dependencies, the boundary with Macaw composition, known gaps | |
| [01 — The contract](01-contract.md) | `Macaw.Auth`, `Macaw.Auth.Backend` and every callback, `Macaw.Auth.User`, `Macaw.Auth.Session`, steps and `pending_step/2`, paths, revocation (`revoke/2`, `subscribe/1`, `announce_revoked/2`), `viewer/1`, `Macaw.Auth.Authorizer` and `authorize/3` | implemented (v0.3.0) |
| [02 — Plugs](02-plugs.md) | `Macaw.Auth.Plug`: the session keys, every plug and function, the return path and the site-path guard, the role refusal's flash, `authorize/2`, the client address | implemented (v0.3.1) |
| [03 — LiveView hooks](03-live.md) | `Macaw.Auth.Live`: each `on_mount` (`{:authorize, action}` among them), the guard, the revocation push and the re-check | implemented (v0.3.0) |
| [04 — The conformance kit](04-conformance.md) | `Macaw.Auth.Conformance`, its `Fixtures` behavior, every check, `pending:` | implemented (v0.2.0) |
| [05 — Native: configuration and sign-in](05-native-config.md) | `Macaw.Auth.Native` (sign-in, one refusal, telemetry, users), `Macaw.Auth.Native.Config` (every key, defaults, validation, hidden secrets) | implemented (v0.1.0) |
| [06 — Native: sources and the chain](06-native-sources.md) | `Macaw.Auth.Native.Source` (the behavior and the chain), `Source.Password`, `Macaw.Auth.Native.Provision`, the users row and its usernames | implemented (v0.1.0) |
| [07 — Native: LDAP](07-native-ldap.md) | `Source.Ldap` and `Source.Ldap.Config` (TLS rules, `allow_plaintext`, direct or search bind, groups, roles), `Source.Ldap.Escape` (RFC 4514/4515), `Source.Ldap.Filter`, `diagnose/3` and `mix macaw_auth.ldap.check` | implemented (v0.1.0) |
| [08 — Native: hashers](08-native-hashers.md) | `Macaw.Auth.Native.Hasher`, bcrypt and argon2, rehash at sign-in, across algorithms | implemented (v0.2.0) |
| [09 — Native: sessions](09-native-sessions.md) | `Macaw.Auth.Native.Sessions`: the token and its hash, idle expiry and touch, disabled users, steps storage, revocation, telemetry | implemented (v0.3.1) |
| [10 — Native: the throttle](10-native-throttle.md) | `Macaw.Auth.Native.Throttle`: keys, the backoff and its cap, reset rules, the second factor's key, the sweep, a block's timing | implemented (v0.1.0) |
| [11 — Native: the second factor](11-native-totp.md) | `Macaw.Auth.Native.Totp` and `Macaw.Auth.Native.Seal`: the window, replay by conditional update, sealing, recovery codes, lifecycle, policy, `admin_reset` | implemented (v0.1.0) |
| [12 — Native: migrations](12-native-migrations.md) | `mix macaw_auth.gen.migration`: the three files, only the missing ones, their order | implemented (v0.1.0) |
| [13 — Native: administering users](13-native-users.md) | `Macaw.Auth.Native`'s user functions and `bootstrap_admin/1`, `Macaw.Auth.Native.UserCommands`, `mix macaw_auth.user`, the release entry points `Macaw.Auth.Native.Release` on macaw_host's protocol, passwords never from the command line, no `Store` behavior yet | implemented (v0.3.0) |

Every heading carries an anchor prefixed `auth-`, so links into this spec stay stable when a heading is reworded. Each behavioral rule carries a test hint (a fenced block whose info string is `test:<id>`) that says what a test of it must show.
