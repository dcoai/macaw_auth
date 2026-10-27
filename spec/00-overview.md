# 00 — Overview {#auth-overview}

## 1. What macaw_auth holds {#auth-holds}

Eight projects carried their own authentication, in three lineages, about 17,600 lines of it, and the copies had drifted on security: a DN-escaping bug fixed in one lineage and live in another, four projects without login throttling, two storing session tokens in the clear, two unable to revoke an open LiveView (macaw_compose#32). `macaw_auth` implements it once, grown from the exio and macaw lineage, which carried every fix the others lacked. It holds:
- **the contract** an app uses, the same whatever backend is behind it: `Macaw.Auth` (sign-in, sessions, steps, paths, revocation that reaches open pages, the viewer), the `Macaw.Auth.Backend` behavior, and the `Macaw.Auth.User` and `Macaw.Auth.Session` structs ([01](01-contract.md));
- **the request side:** `Macaw.Auth.Plug`, plugs for a Phoenix router ([02](02-plugs.md));
- **the LiveView side:** `Macaw.Auth.Live`, `on_mount` hooks that disconnect a page the moment its session is revoked ([03](03-live.md));
- **the conformance kit:** `Macaw.Auth.Conformance`, the tests every backend runs ([04](04-conformance.md));
- **the native backend,** `Macaw.Auth.Native`, on the host's Ecto repo: its configuration and sign-in ([05](05-native-config.md)), a chain of sources with local passwords and just-in-time provisioning ([06](06-native-sources.md)), LDAP over OTP's `:eldap` ([07](07-native-ldap.md)), bcrypt or argon2 ([08](08-native-hashers.md)), hashed sessions ([09](09-native-sessions.md)), the sign-in throttle ([10](10-native-throttle.md)), TOTP and recovery codes ([11](11-native-totp.md)), the generator of its migrations ([12](12-native-migrations.md)), and administering its users: the first admin at boot, `mix macaw_auth.user`, and the same commands as release entry points for an app's `<app>-ctl` ([13](13-native-users.md)).

## 2. A contract with backends behind it {#auth-shape}

A consumer needs only a narrow contract: who the current user is, plugs and hooks that guard requests and pages, and a session's lifecycle (sign in, sign out, list, revoke one or all, with the push to open pages). Everything else (storage, LDAP binding, TOTP sealing, the throttle, the hasher) is a backend's own, so the contract never forces a backend to reimplement the native feature set (macaw_compose#32, owner amendment of 2026-10-26).

- **What is the same for every backend is `Macaw.Auth`'s:** the steps a session owes and their order, the configured paths, the revocation push, the viewer, and the plugs and hooks built on them ([01 §1](01-contract.md#auth-contract-facade)).
- **What differs is the backend's:** who someone is, and their sessions, the nine callbacks of `Macaw.Auth.Backend` ([01 §2](01-contract.md#auth-backend)).
- **The backend is the developer's build-time choice,** `config :macaw_auth, backend: Macaw.Auth.Native` ([01 §1.1](01-contract.md#auth-backend-config)).
- **Two backends exist:** `Macaw.Auth.Native`, in this library, and `Macaw.Auth.Ash`, over AshAuthentication, in its own library, [macaw_auth_ash](https://gitlab.conet.yarina.org/dco-tek/macaw_auth_ash/-/blob/main/spec/00-overview.md#ash-overview), so `macaw_auth` never depends on Ash. The kit runs against both.

The test suite carries a third, `Macaw.Auth.Test.MemoryBackend` (`test/support`): the smallest correct implementation of the behavior, users and sessions in ETS, which proves the contract, the plugs and the hooks without a database.

## 3. Dependencies {#auth-dependencies}

- **Runtime, required:**
  - `phoenix` (`~> 1.7`), `phoenix_live_view` (`~> 1.0`) and `phoenix_pubsub` (`~> 2.1`). Every adopter is a Phoenix app, so the plugs redirect with `Phoenix.Controller.redirect/2` and flash with `put_flash/3`, and the hooks are always compiled. Keeping the plugs plain Plug meant re-implementing what Phoenix already does safely: the first, hand-written redirect missed the local-path check Phoenix has built in (an open redirect, fixed before merge) (macaw_compose#32, owner decision of 2026-10-27; done in #51);
  - `plug` and `telemetry`;
  - `ecto_sql`, for the native backend's store: the host gives its repo, and `mix macaw_auth.gen.migration` writes the tables into the host ([12](12-native-migrations.md));
  - `nimble_totp`, for the second factor ([11](11-native-totp.md));
  - `macaw_plug` (by git tag, v0.1.0): the host runs `Macaw.Plug.ClientIp` ahead of the plugs, so `conn.remote_ip` is the client's address the throttle counts ([macaw_plug 01 §4](https://gitlab.conet.yarina.org/dco-tek/macaw_plug/-/blob/main/spec/01-client-ip.md#plug-client-ip-call)). The throttle itself stays here: backoff after failures is a different policy from a request rate (macaw_compose#34). No `macaw_auth` module calls `macaw_plug`; the dependency is the pipeline's order.
  - `macaw_host` (by git tag, v0.1.1): the release side of `<app>-ctl`'s protocol, `Macaw.Host.Release` (the arguments as JSON in `<PREFIX>_CTL_ARGS`, the password in `<PREFIX>_CTL_PASSWORD`, JSON lines out, a failure one line on stderr and exit status 1), which the user commands' release entry points speak ([13 §5](13-native-users.md#auth-users-release), [macaw_host 03 §1](https://gitlab.conet.yarina.org/dco-tek/macaw_host/-/blob/main/spec/03-release.md#host-release-protocol)) (macaw_compose#75);
- **Runtime, optional:** `bcrypt_elixir` (`~> 3.2`) and `argon2_elixir` (`~> 4.1`). Each hasher is compiled only when its library is present; the configured one must be, checked when the configuration is read, with a named error ([08 §1](08-native-hashers.md#auth-hasher-behavior)).
- **OTP applications:** `:logger`, `:crypto`, `:eldap`, `:ssl`, `:public_key`. No LDAP library: the directory is spoken to over OTP's `:eldap`, as every adopter did.
- **Test only:** `ecto_sqlite3` (the test repo is SQLite, migrated with the generated migrations, so what ships is what is tested) and `stream_data`. The `:ldap` tests need macaw's OpenLDAP fixture directory (the `ci-ldap` image in CI) and run when `MACAW_AUTH_LDAP_HOST` names it; otherwise they are excluded.
- **Elixir** 1.18 or newer.

**The application** (`Macaw.Auth.Application`) starts two processes: `Macaw.Auth.Registry`, a `Registry` with duplicate keys, the local revocation channel ([01 §6](01-contract.md#auth-revocation)); and `Macaw.Auth.Native.Throttle`, the throttle's table, started whichever backend is configured ([10 §6](10-native-throttle.md#auth-throttle-table)). When the configured backend is `Macaw.Auth.Native`, it reads that backend's configuration first, so a fault refuses boot ([05 §2](05-native-config.md#auth-native-config)).

```test:application-children
the application starts Macaw.Auth.Registry and Macaw.Auth.Native.Throttle; Macaw.Auth.subscribe/1 then succeeds without a :pubsub, and Throttle.check/3 answers
```

It is released by git tag: v0.1.0; v0.1.1, which added `Macaw.Auth.announce_revoked/2` for the Ash backend (macaw_compose#53); and v0.2.0, which changed the backend contract: `session_idle_seconds/1` is a new callback, for the remember cookie (macaw_compose#77), `create_session/2` and `complete_step/3` may refuse with `{:error, :invalid}`, and the kit's fixtures delete users (`delete!/1`) (macaw_compose#74). A backend written for v0.1 must follow all three.

## 4. The boundary with Macaw composition {#auth-boundary}

Macaw's composition libraries (`macaw_layers`, `macaw_data`, `macaw_compose`, `macaw_live`) never depend on `macaw_auth`, and an identity or access system stays a non-goal of composition: the viewer arrives from the host ([macaw_compose 00 §2](https://gitlab.conet.yarina.org/dco-tek/macaw_compose/-/blob/main/spec/00-overview.md#overview-goals), goal 3). `macaw_auth` is what a host may get the viewer from: `Macaw.Auth.viewer/1` turns the signed-in user into a Macaw page's viewer, identity and roles only, never display preferences, which are state ([01 §8](01-contract.md#auth-viewer)). It sits with `macaw_plug` and `macaw_host` among the family's host libraries ([macaw_compose 00 §4](https://gitlab.conet.yarina.org/dco-tek/macaw_compose/-/blob/main/spec/00-overview.md#overview-packaging)).

## 5. Defaults are closed {#auth-closed}

Every setting that grants trust or loosens a policy defaults to granting nothing:
- **an LDAP source refuses to send a password in the clear** unless `allow_plaintext: true` names the decision, at configuration and again at connect ([07 §1.1](07-native-ldap.md#auth-ldap-transport));
- **a certificate is verified,** chain and hostname, unless `verify_peer: false` ([07 §2](07-native-ldap.md#auth-ldap-connect));
- **an anonymous directory search** needs `allow_anonymous_search: true` ([07 §1.2](07-native-ldap.md#auth-ldap-finding));
- **a directory user never takes over a row another source owns** ([06 §4](06-native-sources.md#auth-provision));
- **there is no registration:** a local user is made by the host (`Macaw.Auth.Native.create_user/1`, or an administrator's `mix macaw_auth.user add`), a directory user only by signing in, and **the first admin only while no user exists** ([13 §2](13-native-users.md#auth-users-bootstrap));
- **a password is never read from the command line:** the user commands take it from an environment variable and refuse one among their arguments ([13 §3.1](13-native-users.md#auth-users-passwords));
- **the release entry points have no default prefix:** without `env_prefix` they refuse ([13 §5](13-native-users.md#auth-users-release));
- **a role check passes only on membership,** and what a role allows is the app's ([02 §4](02-plugs.md#auth-plug-require-role));
- **the remember cookie is `secure` under https,** with no setting to turn it off, and is set only when a sign-in asks for it ([02 §10](02-plugs.md#auth-plug-remember)).

## 6. Known gaps {#auth-gaps}

Found while writing this spec from the code (v0.1.1); each section states what the code does, and these are open for the owner's decision. The bugs and smaller faults found then were fixed in v0.2.0 (macaw_compose#74).

**Gaps against the proposal (macaw_compose#32, #51):**
- **Not implemented:** the `authorize/3` callback; warnings at boot on `verify_peer: false` and on a no-authentication mode.
- **No `Store` behavior.** The native backend is Ecto only; the behavior stays out until uficap adopts `macaw_auth` (macaw_compose#75, [13 §6](13-native-users.md#auth-users-store)).
- **The backend has no default.** The proposal made native the default backend; `Macaw.Auth.backend/0` raises when `:backend` is unset ([01 §1.1](01-contract.md#auth-backend-config)).
- **The kit checks less than proposed.** It checks replay and revocation, but not timing parity, escaping or the throttle, which are the native backend's own tests ([04 §2](04-conformance.md#auth-kit-checks)).
- **A completed step is the host's word.** `Macaw.Auth.complete_step/3` marks `:second_factor` or `:second_factor_enroll` passed without a code or an enrollment: the second factor's page must go through `Macaw.Auth.Plug.verify_second_factor/2`, and enrollment's must call it only after `Macaw.Auth.Native.enroll_confirm/3` succeeded ([01 §4](01-contract.md#auth-steps)).
- **No viewer behavior to implement.** `macaw_compose` has no viewer behavior module yet for `Macaw.Auth.viewer/1` to implement ([01 §8](01-contract.md#auth-viewer)).
