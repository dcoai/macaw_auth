# 04 — The conformance kit {#auth-kit}

`Macaw.Auth.Conformance` is what every `Macaw.Auth.Backend` must do, as tests a backend's author runs: an ExUnit case template.

```elixir
defmodule MyBackend.ConformanceTest do
  use Macaw.Auth.Conformance, backend: MyBackend, fixtures: MyBackend.Fixtures
end
```

`backend:` and `fixtures:` are required. The kit's tests are `async: false`. Before each, it sets `config :macaw_auth, backend:` to the backend under test and calls the fixtures' `reset!/0`; after each, it puts back the backend that was configured (or deletes the setting when none was). It runs against the native backend and the in-memory test backend in this library's CI, and against the Ash backend in macaw_auth_ash's.

## 1. The fixtures {#auth-kit-fixtures}

The fixtures module implements `Macaw.Auth.Conformance.Fixtures`, what a backend gives the kit:

| Callback | What it does |
|---|---|
| `reset!/0` | resets the backend's store before each test; `:ok` |
| `user!/1` | makes a user from `attrs` (which may set `:second_factor` to `:none`, `:enrolled` or `:required`, and `:roles`); returns `{user, credentials}` that sign it in |
| `disable!/1` | disables a user; `:ok` |
| `delete!/1` | deletes a user from the backend's store, as an administrator would, after they signed in; `:ok` (v0.2.0) |
| `idle_seconds/0` | how long a session may idle before it expires, in seconds; the kit checks the backend's own `session_idle_seconds/1` agrees (§2, test 12) |
| `stored_session_values/0` | every value the backend stores for sessions, as binaries, so the kit can prove no token is stored as it is |
| `enroll_second_factor!/1` | enrolls the user the way a user would (begin, then confirm with a valid code) and returns a zero-arity function giving a code the backend accepts at the moment it is called and has not yet accepted: a fresh device's current code |

A fixture that confirms enrollment with the current step's code has spent it: it should confirm with the previous step's, so the current one is still unspent. `stored_session_values/0` should read what the database holds (plain SQL), not what a schema chooses to load.

## 2. The checks {#auth-kit-checks}

Twenty-one tests, in four groups.

**`conformance: authenticate`:**
1. valid credentials sign in, as the fixture's user;
2. **a wrong password and an unknown user are the same refusal**, both exactly `{:error, :invalid_credentials}` (no enumeration);
3. a disabled user is refused, with `:disabled` or `:invalid_credentials`.

**`conformance: sessions`:**

4. a session round-trips by token and by id: `fetch/2` gives its user and session, and `fetch_by_id/2` the same session;
5. **a user deleted since signing in gets no session:** after the fixtures' `delete!/1`, `Macaw.Auth.create_session/2` is `{:error, :invalid}` and `list_sessions/2` is empty ([01 §2.2](01-contract.md#auth-backend-create-session));
6. a garbage token (32 random bytes) and `nil` are `{:error, :invalid}`;
7. **no session token is stored as it is:** across three sessions, no stored value equals a token, its Base64, or its unpadded URL-safe Base64;
8. revoking a session ends it (its token is `:invalid`) and **tells a subscribed process** `{:sessions_revoked, [id]}`;
9. revoking all but one (`{:user, id}`, `except:`) keeps that one, ends the others, and tells a subscriber the two ids;
10. **revoking nothing tells nobody;**
11. an idle session is valid five seconds before `idle_seconds/0` and `{:error, :expired}` five seconds after, **looked up with `touch: false`, which never extends it;**
12. **the backend reports the idle limit it expires by:** `Macaw.Auth.session_idle_seconds/1` ([01 §2.8](01-contract.md#auth-backend-idle)) equals `idle_seconds/0`, so the remember cookie lives exactly as long as an unused session ([02 §10](02-plugs.md#auth-plug-remember));
13. a disabled user's live session is refused, with `:disabled` or `:invalid`;
14. a user's sessions list newest first.

**`conformance: steps`:**

15. a user without a second factor owes nothing;
16. **completing a step of a revoked session** (`:password_change`) is `{:error, :invalid}`, and its token stays `:invalid` ([01 §2.6](01-contract.md#auth-backend-complete-step)).

**`conformance: second factor`:**

17. a user made `:enrolled` owes `:second_factor` after signing in, and completing the step clears it;
18. a user enrolled through `enroll_second_factor!/1` signs in reported `:enrolled`, and **a valid code passes the step** (`Macaw.Auth.verify_second_factor/3`);
19. a wrong code (every digit changed) is refused, and the step is still owed;
20. **a code is accepted once:** accepted on one session, the same code is refused on another of the user's, which still owes the step;
21. a user policy requires to have one (`:required`) owes `:second_factor_enroll`, and completing it clears it.

Test 5 needs the fixtures: the contract has no way to delete a user, so `delete!/1` does it the backend's own way, as `disable!/1` disables one. A revocation racing a backend between its own read and write can't be driven portably, so the kit checks a session revoked before the step (test 16), and the native backend's own suite checks the race ([09 §6](09-native-sessions.md#auth-sessions-steps)).

The kit does not check timing parity, escaping or throttling; a backend's own suite does (the native backend's: [06 §3](06-native-sources.md#auth-source-password), [07 §5](07-native-ldap.md#auth-ldap-escape), [10](10-native-throttle.md)).

```test:kit-native
the kit run against Macaw.Auth.Native passes all twenty-one tests, none skipped
```

```test:kit-memory
the kit run against the in-memory test backend passes all twenty-one tests, none skipped
```

## 3. Pending capabilities {#auth-kit-pending}

A backend still being built may name a capability it doesn't have yet: `pending: [second_factor: "why"]`. The tests that need it are then **skipped, visibly,** tagged `skip: "pending (second factor): <why>"`, so every run's summary says so, rather than removed or passed by a fixture that pretends. The only capability is `:second_factor`, which skips the whole `conformance: second factor` group (tests 17–21). The native backend ran the kit with it pending until its second factor existed, and was then required to remove it (macaw_compose#51, #52); the Ash backend runs with it pending until AshAuthentication 5.0 is final.

```test:kit-pending
a backend run with pending: [second_factor: "reason"] reports the five second-factor tests skipped, each with "pending (second factor): reason", and the other sixteen run
```
