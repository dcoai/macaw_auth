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

Three keys of the Plug session:
- **`"macaw_auth_token"`**, the session's token (`Macaw.Auth.Plug.token_key/0` gives it, for hosts that pass it to LiveView's session, where the hooks read it ([03 §1](03-live.md#auth-live-mount-user)));
- **`"macaw_auth_return_to"`**, the path a signed-out visitor was going to (§3.1);
- **`"live_socket_id"`**, the session's socket id, `"macaw_auth_sessions:<session id>"` (`Macaw.Auth.live_socket_id/1`), put at sign-in (§7) and when a remembered session is restored (§10.2). Phoenix reads it under this name and names the session's LiveView sockets by it, so a revocation can disconnect them ([01 §6](01-contract.md#auth-revocation)).

Nothing else of the session is the library's. Besides the session, the library owns one cookie, the remember cookie (§10).

```test:plug-token-key
token_key/0 is "macaw_auth_token", and fetch_current_user/2 reads the token from that session key
```

## 2. Fetching the current user {#auth-plug-fetch}

`Macaw.Auth.Plug.fetch_current_user/2` resolves the session's token with `Macaw.Auth.fetch/2` and **`touch: true`** (a request records the session's use, [01 §2.3](01-contract.md#auth-backend-fetch)), and assigns:
- **signed in:** `:current_user` (the `%Macaw.Auth.User{}`), `:current_session` (the `%Macaw.Auth.Session{}`) and `:pending_step` (`Macaw.Auth.pending_step/2`, [01 §4](01-contract.md#auth-steps));
- **otherwise** (no token, or one refused for any reason): all three nil, and **the token is deleted from the session,** so a revoked, expired or disabled session's cookie stops carrying it.

**Only when the session holds no token** is the remember cookie read (§10.2); a session token, live or refused, is never second-guessed by the cookie.

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
1. **creates the session** (`Macaw.Auth.create_session/2`) with `:remote_ip` (the conn's, as a string) and `:user_agent` (the first `user-agent` header), which `opts` may override or add to (every option but `:remember` goes to `create_session/2`);
2. **renews the session** (`configure_session(renew: true)`, a new session id, so a fixated one is useless) **and clears it,** keeping only the return path;
3. **stores the token** under `"macaw_auth_token"`, and **the session's `live_socket_id`** under `"live_socket_id"` (§1);
4. with **`remember: true`**, **sets the remember cookie** (§10); without it, deletes a remember cookie the browser sent, so an older session's cookie can't outlive this sign-in;
5. assigns `:current_user`, `:current_session` and `:pending_step`;
6. **continues** (§7.1).

**When the backend refuses the session** (`{:error, :invalid}`: the user was deleted since signing in, [01 §2.2](01-contract.md#auth-backend-create-session)), the sign-in fails cleanly instead: an error flash, **`"You could not be signed in."`**, when the pipeline ran `fetch_flash` (without it, no message), and a redirect to `path(:sign_in)`, halted. **Nothing else is touched:** no token or `live_socket_id` is put in the session, the session is neither renewed nor cleared, no remember cookie is set or deleted, whatever `remember:` says, and `:current_user`, `:current_session` and `:pending_step` are left as they were. It never raises.

```test:plug-log-in-refused
log_in(remember: true) of a user the memory backend deleted, after fetch_flash, is halted with 302 to the sign-in path and the error flash "You could not be signed in."; the session holds no token and no "live_socket_id", no remember cookie is set, and the user has no session; without fetch_flash, the same, with no :flash assigned
```

`Macaw.Auth.Plug.log_out/1` revokes the current session, if there is one, through `Macaw.Auth.revoke/2` (so its open pages disconnect, and with `:endpoint` its LiveView sockets, [01 §6](01-contract.md#auth-revocation)), renews and clears the session, **deletes the remember cookie** when the browser sent one, and redirects to `path(:sign_in)`, halted.

```test:plug-log-in
log_in renews the session (plug_session_info :renew), stores a token that Macaw.Auth.fetch/1 resolves, and redirects to the remembered "/reports"
```

```test:plug-live-socket-id
log_in puts "live_socket_id" = "macaw_auth_sessions:<the new session's id>" in the session (readable as :live_socket_id and "live_socket_id")
```

```test:plug-log-out-cookie
log_out of a request carrying a remember cookie answers with that cookie deleted (max_age 0), and the session's token no longer resolves
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

`Macaw.Auth.Plug.complete_step/2` (`conn`, `step`) records a step the current session completed (`Macaw.Auth.complete_step/3`), re-reads the session by id, reassigns user, session and pending step, and continues (§7.1). **A session the backend refuses the step for** (`{:error, :invalid}`, revoked meanwhile, [01 §2.6](01-contract.md#auth-backend-complete-step)), **or that no longer resolves,** is logged out (§7). Enrollment's page calls it with `:second_factor_enroll` after the backend confirmed the enrollment, and the password page with `:password_change`.

```test:plug-complete-step
a session owing :second_factor, after complete_step(conn, :second_factor), has a nil pending step and is redirected home
```

```test:plug-complete-step-revoked
a session revoked after the request was fetched, after complete_step(conn, :password_change), is halted with 302 to the sign-in path, its session holding no token
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

## 10. The remember cookie {#auth-plug-remember}

A host's sign-in form may offer "remember me": **`log_in(conn, user, remember: true)`** then also sets the remember cookie, so the browser stays signed in after it closes (which ends the host's session cookie). Without `remember: true` no remember cookie is set. As phx.gen.auth does it (exio, Snow), but holding this library's session token.

### 10.1 The cookie {#auth-plug-remember-cookie}

- **Its name** is `Macaw.Auth.Plug.remember_cookie/0`: `config :macaw_auth, remember_cookie: "..."`, default **`"_macaw_auth_remember"`**.
- **Its value is the session's token, signed** (`put_resp_cookie/4` with `sign: true`, under the endpoint's `secret_key_base`), never the bare token: a forged or altered cookie fails verification and is ignored as absent.
- **`max_age` is the backend's idle limit,** `Macaw.Auth.session_idle_seconds/1` ([01 §2.8](01-contract.md#auth-backend-idle)): a cookie outliving its session would only carry a dead token.
- **`http_only: true`** (no script reads it) and **`same_site: "Lax"`** (not sent on a cross-site sub-request or POST).
- **`secure`** exactly when the request is https (§10.3).

```test:plug-remember-cookie
log_in(conn, user, remember: true) over http sets "_macaw_auth_remember" with max_age the backend's idle limit (3 600 for the memory backend), http_only true, same_site "Lax", secure false, and a value that Plug.Crypto.verify(secret_key_base, "_macaw_auth_remember_cookie", value) gives back as the session's token
```

```test:plug-remember-name
with remember_cookie "_my_app_remember", log_in sets that cookie and not "_macaw_auth_remember", and the next request is restored from it; with none configured, remember_cookie/0 is "_macaw_auth_remember"
```

```test:plug-remember-off
log_in without remember: sets no live remember cookie; from a browser that sent one, it answers with that cookie deleted (max_age 0)
```

### 10.2 Reading it {#auth-plug-remember-read}

`fetch_current_user/2` reads the cookie **only when the session holds no token** (§2):
- **a token that resolves:** the request is signed in as that session, **the session is renewed** (a new session id) and **the token put back** under `"macaw_auth_token"`, with the session's `"live_socket_id"` (§1), and **the cookie is set again** with a fresh `max_age`, so a browser in use keeps it;
- **a token refused** for any reason (revoked, expired, disabled): signed out, and **the cookie is deleted.** So **a revoked session's cookie is dead:** revocation deletes the session, and its token no longer resolves, whoever revoked it;
- **an unsigned, forged or absent cookie:** signed out, as with no token.

**A touch refreshes it.** When the session's token is in the session and the backend **records the session's use on this request** (its touch, `touch: true`, at most once per its interval, [01 §2.3](01-contract.md#auth-backend-fetch)), and **the browser sent a remember cookie holding this session's token,** the cookie is set again with the same options and a fresh `max_age`. So a browser kept open past the idle limit keeps its cookie for as long as its session lives, and a restart after that still finds it. The plug tells a touch by the clock it passes: it calls `fetch/2` with `now:` and the session's `last_used_at` comes back equal to it exactly when the backend touched it (every backend honors `:now`, [01 §2](01-contract.md#auth-backend)). **A browser that sent no remember cookie never gets one here,** nor does a cookie holding another session's token: it is left as it is.

```test:plug-remember-touch
a remembered session aged past the backend's touch interval (400 s for the memory backend), requested with its token in the session and its cookie, answers with the cookie set again: max_age the idle limit, http_only, "Lax", secure false, holding the same token
```

```test:plug-remember-no-touch
the same request without the session aged (no touch) answers with no remember cookie; an aged session of a browser that sent no cookie answers with none; an aged session whose browser's cookie holds another session's token answers with none
```

```test:plug-remember-restore
a browser signed in with remember: true, on a later request with an empty session, is signed in as the same user and session, its session holding the same token and "live_socket_id" "macaw_auth_sessions:<id>"
```

```test:plug-remember-session-first
a request whose session holds one user's live token and whose remember cookie holds another's is signed in as the session's user
```

```test:plug-remember-revoked
after Macaw.Auth.revoke of the remembered session, the next request with an empty session is signed out, holds no token, and answers with the remember cookie deleted (max_age 0)
```

```test:plug-remember-unsigned
a cookie named "_macaw_auth_remember" holding a live token's Base64, unsigned, signs nobody in
```

### 10.3 `secure` under https {#auth-plug-secure}

The remember cookie is **`secure: true` exactly when `conn.scheme == :https`,** and no setting turns that off (defaults closed, [00 §5](00-overview.md#auth-closed)). Behind a TLS-terminating proxy, the host makes the request's scheme the client's (`Plug.RewriteOn` with `:x_forwarded_proto`, or the endpoint's `force_ssl`), so the scheme is https where the browser's is.

**The session cookie is the host's,** set by its endpoint's `Plug.Session` options, not by this library. A host served over https sets `secure: true` there too, as phx.gen.auth's hosts do; the library's own cookie never depends on it.

```test:plug-remember-secure
log_in(remember: true) of a request whose scheme is :https sets the cookie with secure true; over :http, secure false
```
