# 01 — The contract {#auth-contract}

What an app uses, whatever backend is behind it: `Macaw.Auth`, the facade; `Macaw.Auth.Backend`, what a backend implements; and the two structs every backend reports, `Macaw.Auth.User` and `Macaw.Auth.Session`. The plugs ([02](02-plugs.md)) and the hooks ([03](03-live.md)) are built on these.

## 1. The facade {#auth-contract-facade}

`Macaw.Auth` owns what is the same for every backend, so a backend never reimplements it: the steps a session owes (§4), the paths (§3), the revocation push (§6) and the viewer (§8). Its session and sign-in functions pass through to the configured backend:

| Function | Calls | Returns |
|---|---|---|
| `Macaw.Auth.authenticate/2` | `authenticate/2` | `{:ok, user}` or `{:error, refusal}` |
| `Macaw.Auth.create_session/2` | `create_session/2` (§5) | `{:ok, token, session}` |
| `Macaw.Auth.fetch/2` | `fetch_session/2` | `{:ok, user, session}` or `{:error, reason}` |
| `Macaw.Auth.fetch_by_id/2` | `fetch_session_by_id/2` | `{:ok, user, session}` or `{:error, reason}` |
| `Macaw.Auth.session_idle_seconds/1` | `session_idle_seconds/1` (§2.8) | the idle limit, in seconds |
| `Macaw.Auth.list_sessions/2` | `list_sessions/2` | the user's sessions, newest first |
| `Macaw.Auth.complete_step/3` | `complete_step/3` | `:ok` |
| `Macaw.Auth.verify_second_factor/3` | `verify_second_factor/3` | `:ok` or `{:error, reason}` |
| `Macaw.Auth.revoke/2` | `revoke_sessions/2`, then the push (§6) | `:ok` |

- **`fetch/2` of anything but a binary** (`nil`, a session without a token) is `{:error, :invalid}`, without asking the backend.
- **`complete_step/3` takes only a step** of `steps/0`; any other atom is a `FunctionClauseError`, never passed on.
- `opts` pass through unchanged; `:now` (a `DateTime`) overrides every backend's clock (§2).

```test:facade-fetch-non-binary
Macaw.Auth.fetch(nil) and Macaw.Auth.fetch(:x) are {:error, :invalid} without the backend being called
```

```test:facade-complete-step-guard
Macaw.Auth.complete_step(id, :not_a_step) raises FunctionClauseError; :second_factor, :second_factor_enroll and :password_change reach the backend
```

### 1.1 Choosing the backend {#auth-backend-config}

`Macaw.Auth.backend/0` is `config :macaw_auth, backend: Module`, read at each call: the developer's build-time choice, `Macaw.Auth.Native` or `Macaw.Auth.Ash`. **There is no default:** with `:backend` unset, `backend/0` raises (`Application.fetch_env!/2`), and so does every call through it.

```test:backend-unset
with :backend deleted from the application environment, Macaw.Auth.backend/0 raises ArgumentError; with it set to the memory backend, it returns that module
```

## 2. The backend behavior {#auth-backend}

`Macaw.Auth.Backend` is what a backend implements: who someone is, and their sessions. Nothing else. Every callback takes `opts`, a keyword list in which **`:now` (a `DateTime`) overrides the clock**, so expiry is testable. A backend **never raises for an ordinary refusal:** it returns an error value. And it must:
- **store no more than a hash of a session token;**
- **spend the same time refusing an unknown user as a wrong password,** and give both the same refusal;
- **refuse a disabled user's sessions, and expire idle ones.**

The conformance kit checks what it can of these ([04](04-conformance.md)).

### 2.1 authenticate/2 {#auth-backend-authenticate}

`authenticate(credentials, opts)` checks `%{username: _, password: _}` (at least): `{:ok, %Macaw.Auth.User{}}` or `{:error, refusal}`, a refusal one of:
- `:invalid_credentials`: a wrong password, an unknown user, or anything else the caller must not be told apart;
- `:disabled`: a disabled user (said only to whoever gave the right password, so disabled accounts can't be probed);
- `:throttled`: the attempt was refused unchecked while a wait runs;
- `{:unavailable, message}`: the type admits it; neither shipped backend returns it.

`opts` carries `:remote_ip` (the client's address, a string or a tuple), for a throttle by address, and `:now`.

```test:backend-one-refusal
for each backend: a wrong password and an unknown username give the same {:error, :invalid_credentials}
```

### 2.2 create_session/2 {#auth-backend-create-session}

`create_session(user, opts)` starts a session for a user who passed `authenticate/2`: `{:ok, token, %Macaw.Auth.Session{}}`, the token for the client only. Options: `:remote_ip`, `:user_agent`, `:second_factor_passed` (the facade always sets it, §5), `:now`.

### 2.3 fetch_session/2 and fetch_session_by_id/2 {#auth-backend-fetch}

`fetch_session(token, opts)` resolves a token: `{:ok, user, session}`, or `{:error, :invalid | :expired | :disabled}`:
- **`touch: true`** (a request) may record the session's use, no more often than the backend's interval, which extends an idle session;
- **`touch: false`** (a re-check) **never extends a session;**
- `:invalid` for a token no session has, a revoked one, or garbage; `:expired` for an idle one; `:disabled` for a disabled user's.

`fetch_session_by_id(id, opts)` is the same by the session's id: what an open page re-checks with, since a page holds the id and never the token.

### 2.4 list_sessions/2 {#auth-backend-list}

`list_sessions(user_id, opts)` gives the user's sessions, **newest first.**

### 2.5 revoke_sessions/2 {#auth-backend-revoke}

`revoke_sessions(target, opts)` revokes one session (`target` its id) or every session of a user (`{:user, user_id}`), keeping the one named by `except:`. It returns `{user_id, revoked_ids}`, **the ids empty when there was nothing to revoke.** It only revokes: the push to open pages is the facade's (§6). A backend never pushes here.

### 2.6 complete_step/3 {#auth-backend-complete-step}

`complete_step(session_id, step, opts)` records that a session completed a step (§4): `:second_factor` and `:second_factor_enroll` mark its second factor passed; `:password_change` joins its completed steps. `:ok`.

### 2.7 verify_second_factor/3 {#auth-backend-verify}

`verify_second_factor(session_id, code, opts)` checks a second-factor code (a TOTP code or a recovery code) for the session's user and, on success, completes the session's `:second_factor` step. **A code is accepted once:** the same code again is refused. A backend throttles these attempts as it does sign-ins. `:ok`, or `{:error, :invalid_code | :throttled}`, or the session's own refusal (`:invalid | :expired | :disabled`). Options: `:remote_ip`, `:now`. A backend without a second factor refuses every code (the Ash backend's `{:error, :unsupported}`).

### 2.8 session_idle_seconds/1 {#auth-backend-idle}

`session_idle_seconds(opts)` gives **the idle limit `fetch_session/2` expires sessions by,** in seconds, a positive integer: a session unused longer than this is `:expired` (§2.3). It is what the remember cookie's `max_age` is ([02 §10](02-plugs.md#auth-plug-remember)), so a remembered browser keeps its cookie exactly as long as an unused session lives. The native backend's is `session_idle_days` × 86 400 ([09 §3](09-native-sessions.md#auth-sessions-touch)); the in-memory test backend's is its fixed 3 600. Added in v0.2.0: a backend written for v0.1 must add it, and the kit checks it agrees with the fixtures' `idle_seconds/0` ([04 §2](04-conformance.md#auth-kit-checks)).

```test:backend-idle-seconds
Macaw.Auth.session_idle_seconds/0 with the native backend is 14 × 86 400 by default and 86 400 with session_idle_days 1; with the memory backend, 3 600; for each backend, it equals the fixtures' idle_seconds/0
```

## 3. Paths {#auth-paths}

`Macaw.Auth.path/1` gives a configured path, `config :macaw_auth, paths: %{name => path}`, else its default:

| Name | Default |
|---|---|
| `:sign_in` | `"/login"` |
| `:sign_out` | `"/logout"` |
| `:home` | `"/"` |
| `:second_factor` | `"/login/second-factor"` |
| `:second_factor_enroll` | `"/second-factor/enroll"` |
| `:password_change` | `"/password"` |

A configured map need name only what it changes; the rest keep their defaults. A name neither configured nor in the table raises `FunctionClauseError`.

```test:paths-defaults
with no :paths, each name of the table gives its default; with paths %{home: "/home"}, path(:home) is "/home" and path(:sign_in) is still "/login"
```

## 4. Steps {#auth-steps}

A session may owe **steps** before the app is open to it. `Macaw.Auth.steps/0` lists them in the order they are owed: `[:second_factor, :second_factor_enroll, :password_change]`.

`Macaw.Auth.pending_step/2` takes a user and a session and gives the step owed, or nil, by the first that applies:
1. **`:second_factor`** while the session's second factor is not passed and the user's `second_factor` is `:enrolled`;
2. **`:second_factor_enroll`** while the session's second factor is not passed and the user's `second_factor` is `:required` (policy requires one the user hasn't enrolled);
3. **`:password_change`** while the user's `must_change_password` is set and `:password_change` is not among the session's `completed_steps`;
4. otherwise nil.

So the second factor comes before a password change, and a session owes at most one step at a time. **While a step is owed, only that step's page and sign-out are reachable:** `Macaw.Auth.allowed_paths/1` is `[path(step), path(:sign_out)]`, which the plugs enforce ([02 §3](02-plugs.md#auth-plug-require-authenticated)) and the hooks honor ([03 §2](03-live.md#auth-live-guarded)).

Completing a step is `complete_step/3` (§2.6). The facade records it on the host's word: the second factor's page goes through `Macaw.Auth.Plug.verify_second_factor/2`, which completes `:second_factor` only for an accepted code ([02 §8](02-plugs.md#auth-plug-verify)); enrollment's page completes `:second_factor_enroll` after the backend confirmed the enrollment; the password page completes `:password_change` after the password changed.

```test:pending-step-order
an enrolled user who must change their password: a fresh session owes :second_factor; with the second factor passed, :password_change; with :password_change completed, nil
```

```test:pending-step-required
a user whose second_factor is :required owes :second_factor_enroll until the session's second factor is passed; a user with :none owes nothing
```

```test:allowed-paths
allowed_paths(:second_factor) is [path(:second_factor), path(:sign_out)]
```

## 5. Starting a session {#auth-create-session}

`Macaw.Auth.create_session/2` passes `second_factor_passed` to the backend: the option when given, else **true only when the user's `second_factor` is `:none`**. So a user with one enrolled or required starts a session that owes it, and a caller can't forget to.

```test:create-session-owes
a user with second_factor :enrolled gets a session whose pending step is :second_factor; with :none, nil; second_factor_passed: true given explicitly overrides
```

## 6. Revocation reaches open pages {#auth-revocation}

**Every revocation tells the user's open pages,** which disconnect at once ([03 §3](03-live.md#auth-live-revoked)):
- `Macaw.Auth.revoke/2` revokes through the backend (§2.5) and, **when any session ended,** announces the ids. When none did, it tells nobody. It returns `:ok` either way.
- `Macaw.Auth.subscribe/1` subscribes the calling process to the revocations of a user's sessions, on the topic `"macaw_auth:user_sessions:<user_id>"`.
- `Macaw.Auth.announce_revoked/2` sends `{:sessions_revoked, ids}` to a user's subscribers. **Announcing `[]` sends nothing.** It is public (v0.1.1) for a backend whose sessions can also be revoked outside `macaw_auth` (an Ash token revoked through Ash), which calls it from that path too, so open pages hear of every revocation, whoever made it (macaw_compose#53).

**The channel** is chosen by `config :macaw_auth, pubsub:`:
- **without it, this node:** a subscriber registers in `Macaw.Auth.Registry` under the topic, and an announcement is dispatched to every registered process on this node;
- **with it, every node:** `Phoenix.PubSub.subscribe/2` and `Phoenix.PubSub.broadcast/3` on the host's PubSub, so a page on another node hears a revocation made here.

**Sockets by `live_socket_id`.** `Macaw.Auth.live_socket_id/1` gives a session's socket id, **`"macaw_auth_sessions:<session id>"`**, which `Macaw.Auth.Plug.log_in/3` puts in the session as `:live_socket_id` ([02 §7](02-plugs.md#auth-plug-log-in)), so Phoenix names that session's LiveView sockets by it. When **`config :macaw_auth, endpoint: MyAppWeb.Endpoint`** is set, `announce_revoked/2` (and so `revoke/2`) also calls **`endpoint.broadcast(live_socket_id(id), "disconnect", %{})` for each id announced**, after telling the subscribers, and Phoenix closes those sockets, whatever page they hold. **Without `:endpoint`, nothing more is sent:** the subscribers' guard ([03 §3](03-live.md#auth-live-revoked)) still takes the open pages away. Announcing `[]` broadcasts nothing either way. Both are as phx.gen.auth does it (exio, Snow); the guard reaches pages, the disconnect reaches every socket of the session.

A session ended by expiry, or because its user was disabled, is not announced: its open pages find it gone at their next re-check ([03 §4](03-live.md#auth-live-recheck)).

```test:revoke-announces
a process subscribed to a user's sessions receives {:sessions_revoked, [id]} when Macaw.Auth.revoke(id) ends one of them, and nothing when revoke({:user, id}) finds none
```

```test:announce-revoked
announce_revoked(user, [:a, :b]) reaches that user's subscriber as {:sessions_revoked, [:a, :b]}; announce_revoked(user, []) sends nothing; a subscriber of another user receives nothing
```

```test:revoke-disconnects-sockets
with :endpoint set to an endpoint that records broadcasts, revoke({:user, id}, except: kept) of two sessions broadcasts {"macaw_auth_sessions:<id>", "disconnect", %{}} for each ended session and nothing for the kept one; announce_revoked(user, [:a, :b]) broadcasts on live_socket_id(:a) and live_socket_id(:b), announce_revoked(user, []) nothing; without :endpoint nothing is broadcast
```

```test:live-socket-id
live_socket_id(42) is "macaw_auth_sessions:42"
```

```test:revocation-pubsub
with :pubsub naming a started Phoenix.PubSub, a subscribed process receives the revocation of a user's session, all but the kept one with except:
```

## 7. The structs {#auth-structs}

### 7.1 The user {#auth-user}

`Macaw.Auth.User`, the signed-in user as every backend reports it:

| Field | Meaning | Default |
|---|---|---|
| `id` (required) | the backend's id, stable for the account's life | |
| `username` (required) | what the person signs in with | |
| `display_name` | how the app shows them | nil |
| `source` | where the identity came from: `"local"`, an LDAP source's name, a provider | nil |
| `roles` | the roles the app's authorization reads, **as strings**; the library only checks membership | `[]` |
| `disabled` | a disabled user has no live session | false |
| `second_factor` | `:none`, `:enrolled`, or `:required` (policy demands one not yet enrolled) | `:none` |
| `must_change_password` | the next step is a password change | false |
| `extra` | the backend's or app's own fields, untouched by the library | `%{}` |

### 7.2 The session {#auth-session}

`Macaw.Auth.Session`, one signed-in session. **The client holds only its token;** an open page holds its `id`, never the token, and re-checks by id.

| Field | Meaning | Default |
|---|---|---|
| `id` (required) | the session's id | |
| `user_id` (required) | its user's id | |
| `created_at`, `last_used_at` | `DateTime`s; idle expiry reads the last | nil |
| `remote_ip` | the client's address, a string | nil |
| `user_agent` | the client's user agent | nil |
| `second_factor_passed` | false between a password and a second factor | true |
| `completed_steps` | the steps finished (`:password_change`) | `[]` |

```test:structs-enforce
struct!(Macaw.Auth.User, %{username: "a"}) and struct!(Macaw.Auth.Session, %{id: 1}) raise ArgumentError (enforced keys); with the required keys alone, every other field has the default the tables give
```

## 8. The viewer {#auth-viewer}

`Macaw.Auth.viewer/1` gives a Macaw page its viewer from the signed-in user: `%{id, username, roles, source}`, or nil when signed out. It takes a conn or socket (anything with `assigns`) or an assigns map, and reads `:current_user`. **Identity and access only:** display preferences are state, never part of the viewer ([macaw_compose 01 §2](https://gitlab.conet.yarina.org/dco-tek/macaw_compose/-/blob/main/spec/01-vocabulary.md#vocab-data)), and the session, `display_name` and `extra` stay out.

```test:viewer
a conn with a signed-in admin gives exactly %{id: id, username: name, roles: ["admin"], source: "local"}; a signed-out conn gives nil
```
