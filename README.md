<img src="brand/logo/macaw_scarlet.svg" alt="The Macaw logo, a scarlet macaw in flight" width="128">

# macaw_auth

> **This software is a very early release, and not ready for general use.**

Public home: [github.com/dcoai/macaw_auth](https://github.com/dcoai/macaw_auth) · Docs: [hexdocs.pm](https://hexdocs.pm/macaw_auth)

Authentication for Phoenix hosts, implemented once for the Macaw family's host applications (dco-tek/macaw_compose#32). A narrow contract that apps use, with backends behind it.

| Module | What it does |
|---|---|
| `Macaw.Auth` | the contract: authenticate, sessions, steps, revocation that reaches open pages, `viewer/1` |
| `Macaw.Auth.Backend` | what a backend implements: who someone is, and their sessions; and a check of its configuration, which refuses boot on a fault |
| `Macaw.Auth.Authorizer` | what the app implements: what a user may do (`authorize/3`); none configured, nothing is allowed |
| `Macaw.Auth.Plug` | plugs for a Phoenix router: fetch the user, require sign-in or a role, authorize, sign in and out, step through second factor and password change |
| `Macaw.Auth.Live` | LiveView `on_mount` hooks that disconnect a page the moment its session is revoked |
| `Macaw.Auth.Conformance` | the kit every backend runs |

Backends: `Macaw.Auth.Native` (passwords, LDAP, hashed sessions, throttling, TOTP), here, and `Macaw.Auth.Ash` (AshAuthentication), in its own library, [macaw_auth_ash](https://github.com/dcoai/macaw_auth_ash), so this one never depends on Ash.

The native backend: users and sessions in the host's repo (`mix macaw_auth.gen.migration` writes the `macaw_auth_users`, `macaw_auth_sessions` and second-factor migrations, only those a host lacks), and `authenticate/2` through a chain of sources tried in order, where the first that knows the user decides: local password hashes (bcrypt or argon2, rehashed at sign-in) and LDAP directories over OTP's `:eldap` (TLS verified, plaintext refused unless allowed, directory users provisioned at first sign-in with their roles re-derived at every one). `mix macaw_auth.ldap.check SOURCE USERNAME` walks a directory sign-in step by step. Sessions store only a SHA-256 of their 32-byte token, expire after `session_idle_days` (default 14) unused, and record use at most hourly; sign-in failures back off per username and per client address (2^(n-5) s after five, capped at 15 minutes). The second factor is TOTP (RFC 6238 via `nimble_totp`, ±1 step, each step accepted once by a conditional update) with ten single-use recovery codes stored as SHA-256; the secret is sealed at rest with AES-256-GCM under `sealing_key`, and code attempts go through the same throttle. `totp_required` (`true` or a list of roles) makes a user who hasn't enrolled owe enrollment. `Macaw.Auth.Native.enroll_begin/2`, `enroll_confirm/3`, `disable/3`, `admin_reset/2`, `regenerate_recovery_codes/2`, and `Macaw.Auth.Plug.verify_second_factor/2` for the step's page.

Users are administered without host code: `Macaw.Auth.Native.bootstrap_admin/1` makes the first admin only while no user exists (safe at every boot), and `mix macaw_auth.user list | add NAME --role R | disable NAME | enable NAME | delete NAME | password NAME | roles NAME R… | reset-second-factor NAME` answers in JSON lines, the password from `MACAW_AUTH_USER_PASSWORD`, never argv. The same commands, and the bootstrap, are release entry points for an app's `<app>-ctl` (`Macaw.Auth.Native.Release`, on macaw_host's release protocol).

From Hex:

```elixir
{:macaw_auth, "~> 0.4.3"}
```

Phoenix and LiveView are required dependencies: the plugs redirect with `Phoenix.Controller` and flash a refused role, so the browser pipeline needs `fetch_flash`.

```elixir
config :macaw_auth, Macaw.Auth.Native,
  repo: MyApp.Repo,
  hasher: Macaw.Auth.Native.Hasher.Bcrypt,   # add {:bcrypt_elixir, "~> 3.2"} (or Argon2 and {:argon2_elixir, "~> 4.1"})
  session_idle_days: 14,
  totp_issuer: "My App",
  totp_required: ["admin"],                    # or true, or false (the default)
  sealing_key: {MyApp.Secrets, :sealing_key, []},   # or a binary of >= 32 bytes
  sources: [
    %{type: :password},
    %{type: :ldap, name: "nas", host: "nas.example.test", port: 389, ssl: false, starttls: true,
      cacertfile: "/etc/ssl/nas-ca.pem", user_dn_template: "uid={username},cn=users,dc=example,dc=test",
      groups: %{base_dn: "cn=groups,dc=example,dc=test", member_attr: "memberUid"},
      required_group: "macaw", role_mapping: %{"macaw-admin" => "admin"}, default_role: "viewer"}
  ]
```

```elixir
config :macaw_auth,
  backend: Macaw.Auth.Native,
  pubsub: MyApp.PubSub,
  endpoint: MyAppWeb.Endpoint,            # revocation also disconnects LiveView sockets
  remember_cookie: "_my_app_remember",    # optional; default "_macaw_auth_remember"
  authorizer: MyApp.Authorizer            # a Macaw.Auth.Authorizer; without one, authorize refuses everything

import Macaw.Auth.Plug
plug :fetch_session
plug :fetch_flash
plug Macaw.Plug.ClientIp, trusted_proxies: [...]
plug :fetch_current_user
```

**Remember me.** `Macaw.Auth.Plug.log_in(conn, user, remember: true)` also sets a signed cookie holding the session's token, for the backend's idle limit (`Macaw.Auth.session_idle_seconds/1`), `http_only`, `same_site: "Lax"`, and `secure` whenever the request is https (no setting turns that off). `fetch_current_user/2` reads it only when the session has no token, and sets it again whenever the backend records the session's use, so a browser in use keeps it; a revoked session's cookie no longer resolves, and `log_out/1` deletes it. The session cookie itself is the host's endpoint's: set `secure: true` in its `Plug.Session` options on an https site.

**LiveView sockets.** `log_in/3` puts `live_socket_id` (`"macaw_auth_sessions:<session id>"`) in the session. With `:endpoint` configured, every revocation (`Macaw.Auth.revoke/2`, sign-out) broadcasts `"disconnect"` on it, so Phoenix drops the session's sockets; without it, the hooks' own guard still takes revoked pages away.

Part of [Macaw](https://github.com/dcoai/macaw) (spec/00 §4, host libraries). Released on Hex.
