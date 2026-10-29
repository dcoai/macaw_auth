# 09 — Native: sessions {#auth-sessions}

`Macaw.Auth.Native.Sessions` keeps the native backend's sessions in `macaw_auth_sessions` (`Macaw.Auth.Native.SessionRecord`), ported from exio's `Accounts.Sessions`. It implements the backend's session callbacks ([01 §2](01-contract.md#auth-backend)) as `create/2`, `fetch/2`, `fetch_by_id/2`, `list/2`, `revoke/2` and `complete_step/3`; `Macaw.Auth.Native.session_idle_seconds/1` reports its idle limit (§3). **Every function honors `:now`** (a `DateTime`), kept at microsecond precision as the columns hold it.

## 1. The token is never stored {#auth-sessions-token}

`Macaw.Auth.Native.Sessions.create/2` makes **a token of 32 random bytes** (`:crypto.strong_rand_bytes/1`) and stores **only its SHA-256** (`Macaw.Auth.Native.Sessions.hash/1`) in `token_hash`, unique. The token goes to the client and is written nowhere else, so reading the table (a backup, a leaked dump) signs nobody in. Since the token is uniformly random, a plain unsalted hash is as strong as the token: there is nothing to guess. metresis and Snow stored their session tokens in the clear (macaw_compose#32).

The session row records:
- `user_id`, referencing `macaw_auth_users` (deleting a user deletes their sessions);
- `remote_ip`: the `:remote_ip` option, a string, or a tuple formatted as one;
- `user_agent`: the `:user_agent` option, **truncated to 255 characters,** so a client can't make the row as large as it likes;
- `second_factor_passed`: the option, default true (the facade always passes it, [01 §5](01-contract.md#auth-create-session));
- `completed_steps`: `[]`; `last_used_at`, `inserted_at` and `updated_at`: now.

`Macaw.Auth.Native.Sessions.to_session/1` makes a row the contract's `%Macaw.Auth.Session{}`, `created_at` its `inserted_at`.

**A user who no longer exists gets no session** ([01 §2.2](01-contract.md#auth-backend-create-session)). The row is inserted by one statement that selects it from the user's row (`INSERT … SELECT … FROM macaw_auth_users WHERE id = …`), so it is written only while the user exists, with no gap between a check and the insert: a user deleted since signing in inserts nothing, and `create/2` returns `{:error, :invalid}`, never the foreign-key error an insert would raise. A user id that isn't a UUID is refused the same way. No `:created` event is emitted.

```test:sessions-no-token-property
property: for up to six sessions of a user, no column of any session or user row contains a token, its Base64, unpadded URL-safe Base64, or hex in either case; each token's SHA-256 is stored exactly once
```

```test:sessions-record-client
a session made with remote_ip {203, 0, 113, 9} and a 400-character agent records "203.0.113.9" and an agent of 255 characters, and fetch gives them back
```

```test:sessions-create-deleted-user
after the user's row is deleted, create_session is {:error, :invalid}, as it is for a user id "junk"; no session row exists, and no :created event is emitted
```

## 2. Looking a session up {#auth-sessions-fetch}

`Macaw.Auth.Native.Sessions.fetch/2` finds the row by the token's hash; `Macaw.Auth.Native.Sessions.fetch_by_id/2` by its id, which must be a UUID (anything else, nil included, is `:invalid`, never raised). Either way, in order:
1. **no row,** or a row whose user is gone: `{:error, :invalid}`;
2. **a disabled user** (§4): the row is deleted, `{:error, :disabled}`;
3. **idle too long** (§3): the row is deleted, `{:error, :expired}`;
4. otherwise `{:ok, user, session}`, recording use when asked (§3).

The user is the row's user as `Macaw.Auth.Native.to_user/1` makes it, so a session look-up always reports the user as they are now (roles, second factor, disabled).

A row deleted meanwhile by a revocation racing the look-up is as good as deleted: the delete of steps 2 and 3 finds nothing and does nothing.

```test:sessions-invalid
a random 32-byte token, "not-a-uuid", nil and an unused UUID are each {:error, :invalid}
```

## 3. Idle expiry and touch {#auth-sessions-touch}

**Idle expiry slides.** A session whose `last_used_at` is more than `session_idle_days` × 86 400 seconds before now ([05 §2](05-native-config.md#auth-native-config), default 14) is expired and deleted at its next look-up. Exactly the idle period is still valid.

**`touch: true`** (a request) records use, but **writes `last_used_at` at most once an hour:** only when it is at least 3 600 seconds old, and then to now, by an update of that row. A write per request would make every page view a database write, which SQLite's single writer feels. **`touch: false`** (the default, and an open page's re-check) **never extends a session,** or an idle browser tab would keep it alive forever.

**A touch racing a revocation is a revoked session.** A session deleted between its look-up and the touch's write (a revocation, a sign-out elsewhere) updates no row: the look-up is then `{:error, :invalid}`, as the session is, never a crash in the request (`Macaw.Auth.Plug.fetch_current_user/2` signs it out).

```test:sessions-idle
a session made at t0 is valid at t0 + 14 days (touch: false) and {:error, :expired} one second later, its row deleted and the event :expired / :idle emitted; then its token is :invalid
```

```test:sessions-idle-configured
with session_idle_days 1, a session is valid at 86 400 s and :expired at 86 401 s
```

**The idle limit is reported.** `Macaw.Auth.Native.session_idle_seconds/1`, the backend's `session_idle_seconds/1` ([01 §2.8](01-contract.md#auth-backend-idle)), is **`session_idle_days` × 86 400**, read from the configuration at each call: exactly the limit above, and the remember cookie's `max_age` ([02 §10.1](02-plugs.md#auth-plug-remember-cookie)). A remembered session in use keeps its cookie: each hourly touch, and each request restored from the cookie, sets it again for another idle limit ([02 §10.2](02-plugs.md#auth-plug-remember-read)).

```test:sessions-idle-seconds
Macaw.Auth.Native.session_idle_seconds([]) and Macaw.Auth.session_idle_seconds() are 1 209 600 with the default configuration; with session_idle_days 1, 86 400
```

```test:sessions-touch-hourly
touch: true at 3 599 s leaves last_used_at at t0; at 3 600 s it becomes that time (stored too); at 3 660 s it stays; the session then expires 14 days after the touch, not after creation
```

```test:sessions-touch-revoked
a session whose row is deleted, by a repo telemetry handler, between the look-up's queries and the touch at 3 600 s is {:error, :invalid}, and stays gone
```

```test:sessions-no-touch
touch: false at 2 h, 30 h and 13 days, by token and by id, never moves last_used_at; by id at 14 days + 1 s it is :expired; a fetch with no :touch option doesn't touch either
```

## 4. A disabled user has no session {#auth-sessions-disabled}

A look-up of a disabled user's session **deletes it and refuses it** (`:disabled`), so disabling a user takes effect at their next request, and their open pages leave at their next re-check ([03 §4](03-live.md#auth-live-recheck)). The deletion is reported as a revocation (§7) with reason `:disabled`; it is not pushed to open pages.

```test:sessions-disabled
after the user's disabled_at is set, fetch is {:error, :disabled}, the row is gone, the next fetch is :invalid, and :revoked / :disabled was emitted
```

## 5. Listing and revoking {#auth-sessions-revoke}

`Macaw.Auth.Native.Sessions.list/2` gives a user's sessions **newest first, by creation time and then by id** (timestamps can tie). A user id that isn't a UUID lists nothing.

`Macaw.Auth.Native.Sessions.revoke/2` **only deletes;** the push to open pages is the facade's ([01 §6](01-contract.md#auth-revocation)):
- **one session** (its id): `{user_id, [id]}`, or `{nil, []}` when there is no such session, or the id isn't a UUID;
- **a user's** (`{:user, user_id}`), keeping `except:` when it is a session id: `{user_id, ids}`. **An `except:` that is no UUID keeps nothing.** A user id that isn't a UUID revokes nothing: `{user_id, []}`;
- the `:reason` option (an atom, such as `:password_changed` or `:second_factor_reset`) goes to telemetry (§7).

`Macaw.Auth.Native.Sessions.revoke_all/3` is what an administrator's change of a user revokes with (`set_password/3`, `admin_reset/2`, `delete_user/2`, [13 §1](13-native-users.md#auth-users-api)): every session of the user's deleted with the reason given, and then **the push** to their open pages (`Macaw.Auth.announce_revoked/2`), **unless option `announce: false`,** for a process that is not the app's node (a mix task, a release's `eval`), which has no page to tell: the pages leave at their next re-check ([03 §4](03-live.md#auth-live-recheck)). `:ok`.

```test:sessions-revoke-all
revoke_all of a user with a session, through set_password/3 and admin_reset/2: the token no longer resolves; a subscriber hears {:sessions_revoked, [_]}, and nothing with announce: false
```

```test:sessions-list
sessions made at 0, three at 10, at 20 and another user's at 30 list as the one at 20, the three tied in descending id order, then the one at 0
```

```test:sessions-list-junk
list_sessions("nope") and list_sessions of an unused UUID are both []
```

```test:sessions-revoke
revoking a's id gives {user_id, [a]} and again {nil, []}; revoking the user's except c gives {user_id, [b]}; except: "not-an-id" revokes c; then nothing is left, {user_id, []}; no subscriber hears anything from the backend itself
```

```test:sessions-revoke-junk
revoke_sessions("junk") is {nil, []} and revoke_sessions({:user, "junk"}) is {"junk", []}
```

```test:sessions-revoke-pages
through Macaw.Auth.revoke, a process subscribed to the user receives {:sessions_revoked, [id]} over the local Registry, and with a Phoenix.PubSub configured, the revocation of all but the kept session
```

## 6. Steps {#auth-sessions-steps}

`Macaw.Auth.Native.Sessions.complete_step/3` records a step:
- **`:second_factor`** sets `second_factor_passed` true, by an update of the row (enrollment is no step: a user owing it has no session, [11 §3.2](11-native-totp.md#auth-totp-owed));
- **any other step** (`:password_change`) joins `completed_steps`, **stored as its name** (a string), once.

**Steps come back as atoms only by lookup** among `Macaw.Auth.steps/0`: a stored name that isn't one (a row from a later version) is dropped, never made an atom. `completed_steps` is `{:array, :string}`: a native array on Postgres, JSON text on SQLite.

**A session that doesn't exist** (an unknown or non-UUID id) is left alone and refused, `{:error, :invalid}` ([01 §2.6](01-contract.md#auth-backend-complete-step)). So is one deleted meanwhile: the second factor's update finds no row, and `:password_change`'s write, after its read of the row, finds the row stale (`stale_error_field`, so an error value rather than `Ecto.StaleEntryError`). A step already completed is `:ok` without a write.

```test:sessions-steps
a session made with second_factor_passed false, after :second_factor and :password_change twice, reads second_factor_passed true and completed_steps [:password_change]; the row holds ["password_change"]
```

```test:sessions-steps-unknown-name
a row whose completed_steps hold "password_change" and "no_such_step_xyz" reads as [:password_change], and no atom no_such_step_xyz exists
```

```test:sessions-steps-gone
complete_step of an unused UUID and of "junk", with each step, is {:error, :invalid}
```

```test:sessions-steps-revoked
a session whose row is deleted, by a repo telemetry handler, between :password_change's read and its write gives {:error, :invalid}, and stays gone
```

## 7. Telemetry {#auth-sessions-telemetry}

`[:macaw_auth, :native, :session]`, measurements `%{count: n}`, metadata exactly `%{event, reason, user_id}`:
- `:created` (reason nil), one per session;
- `:expired` with reason `:idle`;
- `:revoked` with reason `:disabled` (§4), or the `:reason` option of a revocation, `count` the number revoked.

**Never a token or its hash.**

```test:sessions-telemetry
creating a session emits %{count: 1} with exactly %{event: :created, reason: nil, user_id: id}; Macaw.Auth.revoke({:user, id}, reason: :password_changed) of two sessions emits %{count: 2} with event :revoked and reason :password_changed
```
