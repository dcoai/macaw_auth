# 03 — LiveView hooks {#auth-live}

`Macaw.Auth.Live` is the LiveView side of the contract: `on_mount` hooks for a router's `live_session`, which read the session's token from the LiveView session (the key `Macaw.Auth.Plug.token_key/0`, [02 §1](02-plugs.md#auth-plug-keys)) and guard an open page. It is always compiled: `phoenix_live_view` is a required dependency.

```elixir
live_session :signed_in, on_mount: [{Macaw.Auth.Live, :require_authenticated}] do
  live "/", DashboardLive
end

live_session :admin, on_mount: [{Macaw.Auth.Live, {:require_role, ["admin"]}}] do
  live "/admin", AdminLive
end
```

**A mount never touches the session:** every look-up here is `touch: false` ([01 §2.3](01-contract.md#auth-backend-fetch)), so an open page, or a re-mount, never keeps an idle session alive. A request through the plugs is what records use.

## 1. Mounting the current user {#auth-live-mount-user}

`Macaw.Auth.Live.on_mount(:mount_current_user, params, session, socket)` only assigns, and always continues: `:current_user` and `:current_session` from the token, or both nil when there is none or it is refused. It neither redirects nor guards the page, and assigns no `:pending_step`.

```test:live-mount-user
:mount_current_user with a live token continues with the user and session assigned; with no token, it continues with both nil
```

## 2. Guarded pages {#auth-live-guarded}

`on_mount(:require_authenticated, …)` and `on_mount({:require_role, roles}, …)` resolve the token, then, in order:
1. **no session** (none, revoked, expired, disabled): halt, redirecting to `path(:sign_in)`;
2. **a step owed** (`Macaw.Auth.pending_step/2`): halt, redirecting to that step's page. A LiveView page is never a step's page;
3. **`{:require_role, roles}` and the user has none of `roles`** (membership only): halt, redirecting to `path(:home)`, without a flash;
4. otherwise continue, with `:current_user` and `:current_session` assigned, and **the page guarded** while it is connected (§3, §4).

Each redirect is `Phoenix.LiveView.redirect/2`, a full page load (status 302 on the first, static render).

```test:live-require-signed-out
:require_authenticated with no token halts with redirected {:redirect, %{to: "/login", status: 302}}
```

```test:live-require-role
{:require_role, ["admin"]} for a viewer halts redirecting to "/"; for an admin it continues with current_user assigned
```

```test:live-require-step
:require_authenticated for a session owing :second_factor halts redirecting to the second factor's path
```

### 2.1 The guard {#auth-live-guard}

When the socket is connected, the guarded mount:
- **subscribes** the page's process to its user's revocations (`Macaw.Auth.subscribe/1`, [01 §6](01-contract.md#auth-revocation));
- **schedules a re-check** after `config :macaw_auth, revalidate_ms:` milliseconds (default 60 000);
- attaches `Macaw.Auth.Live.handle_guard/2` as a `handle_info` hook named `:macaw_auth_guard`, so the page's own `handle_info/2` never sees these messages.

A static (disconnected) render does none of this: it has no process that lives.

## 3. Revoked: leave at once {#auth-live-revoked}

`handle_guard({:sessions_revoked, ids}, socket)`: when **the page's own session id is among `ids`**, the page halts the message and redirects to `path(:sign_in)`; when it is not (another of the user's sessions ended), the message is consumed and the page stays. Either way it never reaches the page's `handle_info/2`.

This guard needs nothing of the host. With `config :macaw_auth, endpoint:` set, a revocation also broadcasts `"disconnect"` on the session's `live_socket_id`, which Phoenix answers by closing every socket of that session, guarded page or not ([01 §6](01-contract.md#auth-revocation)); the two are independent, and either alone takes a revoked page away.

```test:live-revoked
handle_guard({:sessions_revoked, [own_id]}, socket) redirects to "/login"; handle_guard({:sessions_revoked, [other_id]}, socket) halts with redirected nil
```

## 4. The re-check {#auth-live-recheck}

`handle_guard(:macaw_auth_recheck, socket)` re-resolves the page's session **by id, with `touch: false`** (so an idle browser tab never keeps its session alive):
- **still valid:** the page keeps going, `:current_user` and `:current_session` reassigned (so a changed name or role list shows in the page), and the next re-check is scheduled;
- **gone** (revoked without the push reaching this node, expired, the user disabled): redirect to `path(:sign_in)`.

The re-check is the backstop for what the push doesn't carry: a session that expired, or whose user was disabled, is never announced ([01 §6](01-contract.md#auth-revocation)).

**It does not re-apply the mount's guard:** a role removed from a user who opened a `{:require_role, roles}` page, or a step newly owed, leaves the page open until it is reloaded ([00 §6](00-overview.md#auth-gaps)).

```test:live-recheck
after a re-check, a live session's page keeps its user assigned; once the session is revoked, the next re-check redirects to "/login"
```

```test:live-recheck-no-touch
a page's re-checks never move the session's last_used_at
```

## 5. Other messages {#auth-live-other}

`handle_guard/2` of any other message continues (`{:cont, socket}`), so the page's own `handle_info/2` receives it.

```test:live-other-messages
handle_guard(:something_else, socket) is {:cont, socket}
```
