# macaw_auth

Authentication for Phoenix hosts, implemented once for the Macaw family's host applications (dco-tek/macaw_compose#32). A narrow contract that apps use, with backends behind it.

| Module | What it does |
|---|---|
| `Macaw.Auth` | the contract: authenticate, sessions, steps, revocation that reaches open pages, `viewer/1` |
| `Macaw.Auth.Backend` | what a backend implements: who someone is, and their sessions |
| `Macaw.Auth.Plug` | plain-Plug guards: fetch the user, require sign-in or a role, sign in and out, step through second factor and password change |
| `Macaw.Auth.Live` | LiveView `on_mount` hooks that disconnect a page the moment its session is revoked |
| `Macaw.Auth.Conformance` | the kit every backend runs |

Backends: `Macaw.Auth.Native` (passwords, LDAP, hashed sessions, throttling, TOTP; in progress) and `macaw_auth_ash` (AshAuthentication; later).

The native backend so far: users in the host's repo (`mix macaw_auth.gen.migration` writes the `macaw_auth_users` migration), and `authenticate/2` through a chain of sources tried in order, where the first that knows the user decides: local password hashes (bcrypt or argon2, rehashed at sign-in) and LDAP directories over OTP's `:eldap` (TLS verified, plaintext refused unless allowed, directory users provisioned at first sign-in with their roles re-derived at every one). `mix macaw_auth.ldap.check SOURCE USERNAME` walks a directory sign-in step by step. Sessions come next.

```elixir
config :macaw_auth, Macaw.Auth.Native,
  repo: MyApp.Repo,
  hasher: Macaw.Auth.Native.Hasher.Bcrypt,   # add {:bcrypt_elixir, "~> 3.2"} (or Argon2 and {:argon2_elixir, "~> 4.1"})
  sources: [
    %{type: :password},
    %{type: :ldap, name: "nas", host: "nas.example.test", port: 389, ssl: false, starttls: true,
      cacertfile: "/etc/ssl/nas-ca.pem", user_dn_template: "uid={username},cn=users,dc=example,dc=test",
      groups: %{base_dn: "cn=groups,dc=example,dc=test", member_attr: "memberUid"},
      required_group: "macaw", role_mapping: %{"macaw-admin" => "admin"}, default_role: "viewer"}
  ]
```

```elixir
config :macaw_auth, backend: Macaw.Auth.Native, pubsub: MyApp.PubSub

import Macaw.Auth.Plug
plug :fetch_session
plug Macaw.Plug.ClientIp, trusted_proxies: [...]
plug :fetch_current_user
```

Part of [Macaw](https://gitlab.conet.yarina.org/dco-tek/macaw_compose) (spec/00 §4, host libraries). Released by git tag.
