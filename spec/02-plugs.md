# 02 — Plugs {#auth-plug}

`Macaw.Auth.Plug` is the request side of the contract, for a Phoenix router. Its functions are function plugs (imported) and helpers a controller calls:

```elixir
import Macaw.Auth.Plug

pipeline :browser do
  plug :fetch_session
  plug :fetch_flash
  plug Macaw.Plug.ClientIp, trusted_proxies: [...]
  plug :fetch_current_user
end

pipeline :signed_in do
  plug :require_authenticated
end
```

- **`fetch_session` comes first:** the token is kept in the session.
- **`Macaw.Plug.ClientIp` runs before these,** so a session records, and the throttle counts, the client's address, not a proxy's ([macaw_plug 01 §4](https://gitlab.conet.yarina.org/dco-tek/macaw_plug/-/blob/main/spec/01-client-ip.md#plug-client-ip-call)).
- **`fetch_flash` runs before `require_role/2`,** or its refusal goes home without saying why (§4).

## 1. The session keys {#auth-plug-keys}

Two keys of the Plug session:
- **`"macaw_auth_token"`**, the session's token (`Macaw.Auth.Plug.token_key/0` gives it, for hosts that pass it to LiveView's session, where the hooks read it ([03 §1](03-live.md#auth-live-mount-user)));
- **`"macaw_auth_return_to"`**, the path a signed-out visitor was going to (§3.1).

Nothing else of the session is the library's.

```test:plug-token-key
token_key/0 is "macaw_auth_token", and fetch_current_user/2 reads the token from that session key
```

## 2. Fetching the current user {#auth-plug-fetch}

`Macaw.Auth.Plug.fetch_current_user/2` resolves the session's token with `Macaw.Auth.fetch/2` and **`touch: true`** (a request records the session's use, [01 §2.3](01-contract.md#auth-backend-fetch)), and assigns:
- **signed in:** `:current_user` (the `%Macaw.Auth.User{}`), `:current_session` (the `%Macaw.Auth.Session{}`) and `:pending_step` (`Macaw.Auth.pending_step/2`, [01 §4](01-contract.md#auth-steps));
- **otherwise** (no token, or one refused for any reason): all three nil, and **the token is deleted from the session,** so a revoked, expired or disabled session's cookie stops carrying it.

```test:plug-fetch
a session holding a live token assigns its user, session and a nil pending step; one holding a revoked token assigns three nils and loses "macaw_auth_token"
```

## 3. Requiring sign-in {#auth-plug-require-authenticated}

`Macaw.Auth.Plug.require_authenticated/2`, after `fetch_current_user/2`:
- **signed out:** remembers where a `GET` was going (§3.1) and redirects to `path(:sign_in)`, halted;
- **signed in, owing no step:** passes;
- **signed in, owing a step:** passes when the request's path is **exactly** one of `Macaw.Auth.allowed_paths(step)` (the step's page and sign-out); otherwise redirects to the step's page, halted.

```test:plug-require-signed-out
a signed-out GET to /reports is halted with 302 to the sign-in path
```

```test:plug-require-step
a session owing :second_factor is redirected from /reports to the second factor's path, and passes at that path and at the sign-out path
```

```test:plug-require-signed-in
a signed-in user owing nothing passes, unhalted, with :current_user and :pending_step nil
```

### 3.1 The return path {#auth-plug-return}

A signed-out **`GET`** is remembered in `"macaw_auth_return_to"` as its request path, plus `?` and the query string when there is one (`/reports?year=2026`). **Any other method is not remembered:** a form posted while signed out is not replayed after sign-in. The path is checked only when it is used (§9), since it came from a request.

```test:plug-return-get-only
a signed-out GET to /reports?year=2026 remembers "/reports?year=2026"; a signed-out POST to /reports remembers nothing
```

## 4. Requiring a role {#auth-plug-require-role}

`Macaw.Auth.Plug.require_role/2` takes a list of role names and passes when **the current user has any of them** (membership only: what a role allows is the app's to decide). Otherwise, signed in or signed out:
- **an error flash, `"You are not allowed to do that."`,** when the pipeline ran `fetch_flash` (the conn has a `:flash` assign); without it, no message;
- **a redirect to `path(:home)`,** halted. Not a bare 403: the user sees where they are and why, as exio does (macaw_compose#51).

```test:plug-require-role
an admin passes require_role(["admin", "owner"]); a viewer, after fetch_flash, is halted with 302 to home and the error flash "You are not allowed to do that."
```

```test:plug-require-role-no-flash
without fetch_flash, a viewer is still sent home, and no :flash is assigned; a signed-out request is sent home too
```

## 5. Checking credentials {#auth-plug-authenticate}

`Macaw.Auth.Plug.authenticate/3` (`conn`, `credentials`, `opts`) is `Macaw.Auth.authenticate/2` with **`:remote_ip` set to the conn's `remote_ip`** formatted as a string (the client's once `Macaw.Plug.ClientIp` has run), unless `opts` gives one. So the backend's throttle counts the client's address ([10 §1](10-native-throttle.md#auth-throttle-keys)).

```test:plug-authenticate-ip
with the native backend, five failed sign-ins through authenticate/3 from a conn whose remote_ip is 198.51.100.77 make Throttle.check(_, "198.51.100.77", _) wait 1000 ms
```

## 6. Away from the sign-in page {#auth-plug-redirect-signed-in}

`Macaw.Auth.Plug.redirect_if_signed_in/2` redirects a signed-in visitor to `path(:home)`, halted, and passes a signed-out one: for the sign-in page's own pipeline.

```test:plug-redirect-signed-in
a signed-in request to /login is sent home; a signed-out one passes unhalted
```

## 7. Signing in and out {#auth-plug-log-in}

`Macaw.Auth.Plug.log_in/3` (`conn`, `user`, `opts`) starts a session for a user who passed `Macaw.Auth.authenticate/2`:
1. **creates the session** (`Macaw.Auth.create_session/2`) with `:remote_ip` (the conn's, as a string) and `:user_agent` (the first `user-agent` header), which `opts` may override or add to;
2. **renews the session** (`configure_session(renew: true)`, a new session id, so a fixated one is useless) **and clears it,** keeping only the return path;
3. **stores the token** under `"macaw_auth_token"`;
4. assigns `:current_user`, `:current_session` and `:pending_step`;
5. **continues** (§7.1).

`Macaw.Auth.Plug.log_out/1` revokes the current session, if there is one, through `Macaw.Auth.revoke/2` (so its open pages disconnect, [01 §6](01-contract.md#auth-revocation)), renews and clears the session, and redirects to `path(:sign_in)`, halted.

```test:plug-log-in
log_in renews the session (plug_session_info :renew), stores a token that Macaw.Auth.fetch/1 resolves, and redirects to the remembered "/reports"
```

```test:plug-log-in-step
log_in of a user with a second factor enrolled redirects to the second factor's path
```

```test:plug-log-out
log_out revokes the session (its token no longer resolves), a subscriber hears {:sessions_revoked, [id]}, and the response is 302 to the sign-in path
```

### 7.1 Continuing {#auth-plug-continue}

`Macaw.Auth.Plug.continue/1` sends the browser on, halted: to **the step the session owes,** when there is one (`pending_step` assigned); else to **the remembered return path,** which it deletes from the session; else **home**.

### 7.2 Completing a step {#auth-plug-complete-step}

`Macaw.Auth.Plug.complete_step/2` (`conn`, `step`) records a step the current session completed (`Macaw.Auth.complete_step/3`), re-reads the session by id, reassigns user, session and pending step, and continues (§7.1). **A session that no longer resolves** is logged out (§7). Enrollment's page calls it with `:second_factor_enroll` after the backend confirmed the enrollment, and the password page with `:password_change`.

```test:plug-complete-step
a session owing :second_factor, after complete_step(conn, :second_factor), has a nil pending step and is redirected home
```

## 8. The second factor's page {#auth-plug-verify}

`Macaw.Auth.Plug.verify_second_factor/2` (`conn`, `code`) checks a submitted code for the current session with `Macaw.Auth.verify_second_factor/3`, passing the conn's address as `:remote_ip` for the backend's throttle:
- **accepted:** the `:second_factor` step is completed (§7.2) and the browser goes on, to the next step or where it was going: `{:ok, conn}`, redirected and halted;
- **refused:** `{:error, reason, conn}`, the conn unchanged and unhalted for the page to render the reason (`:invalid_code`, `:throttled`, or the session's own refusal);
- **no current session:** `{:error, :invalid, conn}`.

```elixir
def create(conn, %{"code" => code}) do
  case Macaw.Auth.Plug.verify_second_factor(conn, code) do
    {:ok, conn} -> conn
    {:error, reason, conn} -> render(conn, :new, error: reason)
  end
end
```

```test:plug-verify-ok
with a valid code, verify_second_factor/2 gives {:ok, conn} redirected to the remembered "/reports", and the session no longer owes a step
```

```test:plug-verify-refused
with "not a code", {:error, :invalid_code, conn}, unhalted, pending step still :second_factor; with no current session, {:error, :invalid, conn}
```

## 9. Redirects stay on the site {#auth-plug-site-path}

Every redirect here goes through `Phoenix.Controller.redirect(conn, to: path)` (302) and halts. A remembered path came from a request, so it could be `//evil.example/x` or `/\evil.example`, which browsers treat as another host; Phoenix raises on such a path, which would fail the request. So **a guard in front of Phoenix's redirect sends anything that isn't a plain site path home:** it neither leaves the site nor fails the request. The first, hand-written redirect missed this and was an open redirect, fixed before merge (macaw_compose#49, #51).

`Macaw.Auth.Plug.site_path?/1` is that guard, and agrees with `Phoenix.URL.classify_local_path/1`: true for a string that **starts with exactly one `/`** and contains **none of a backslash, `/%09`, `/` followed by a tab, a line feed or a carriage return.** A path not starting with `/` (`https://evil.example`, `x`, `""`) is false.

```test:plug-site-path-phoenix
for "/", "/a", "/a?b=c", "//x", "/\\x", "/a\\b", "/%09x", "/\tx", "/a\nb", "x" and "": site_path?/1 is true exactly when Phoenix.URL.classify_local_path/1 is :ok
```

```test:plug-open-redirect
log_in with a remembered "//evil.example/x", "/\\evil.example", "https://evil.example", "/a\\b", "/%09/evil.example" or "/x\r\nSet-Cookie: a=b" answers 302 to home, never raising
```
