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

```elixir
config :macaw_auth, backend: Macaw.Auth.Native, pubsub: MyApp.PubSub

import Macaw.Auth.Plug
plug :fetch_session
plug Macaw.Plug.ClientIp, trusted_proxies: [...]
plug :fetch_current_user
```

Part of [Macaw](https://gitlab.conet.yarina.org/dco-tek/macaw_compose) (spec/00 §4, host libraries). Released by git tag.
