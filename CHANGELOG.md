# Changelog

## Unreleased

- A direct-bind LDAP source can read its groups as a service account: `groups: %{base_dn: …, member_attr: …, bind_dn: …, bind_password: …}` binds as `bind_dn` after the user's bind succeeded, then searches for the groups, for a directory that lets a user read only their own entry. `bind_password` is a secret as `search.bind_password` is, in no fault, log line, answer or diagnostic step; `mix macaw_auth.ldap.check` shows the bind as its own step. Refused with `from: :member_of`, in search mode, and one without the other; without them, the user's own bind reads the groups as before. A refused group bind is `:group_search_failed`, whose explanation now names the bind (#3, dco-tek/macaw/macaw#93).
- The remember cookie is `secure` when the request is https or the host declares an https public URL, `config :macaw_auth, public_url: "https://…"` (`Macaw.Auth.Plug.public_scheme/0`), so a host behind a TLS-terminating proxy gets it without trusting a forwarded header. It only adds `secure`: an https request always has it, and nothing declared leaves today's rule. A public URL that is not an http or https URL refuses boot (#2, dco-tek/macaw/macaw#93).
- `Macaw.Auth.Native.delete_user/2` deletes a user, their sessions revoked first (announced unless `announce: false`) and their sessions and recovery codes going with the row; `delete NAME` among `mix macaw_auth.user`'s commands and the release entry points (#1, dco-tek/macaw/macaw#93).

## v0.4.3 (2026-10-28)

- `macaw_host` `~> 0.2.0`, so a host can take its new release alongside `macaw_auth` (dco-tek/macaw/macaw#182).

## v0.4.2 (2026-10-28)

- `macaw_plug` `~> 0.2.0`, so a host can take its new security-header options alongside `macaw_auth` (dco-tek/macaw/macaw#178).
- The macaw logo in the docs and the README (macaw#175).
- CI: the LDAP fixture image moved with the server, now Collpa: `dco-tek/macaw/collpa/ci-ldap` (collpa#146).

## v0.4.1 (2026-10-28)

- On Hex: depends on `macaw_plug ~> 0.1.4` and `macaw_host ~> 0.1.4` from Hex instead of their git tags, and the README installs from Hex (macaw#155).
- The README opens with the early-release notice (macaw#174).
- Package metadata for Hex: the public home, the changelog link, the files shipped, and docs with `ex_doc` (macaw_compose#155).

## v0.4.0 (2026-10-27)

- check_config!/0: every backend's configuration checked at boot; v0.4.0 (part of macaw_compose#89)

## v0.3.1 (2026-10-27)

- plug require_role sends a signed-out visitor to sign in; v0.3.1

## v0.3.0 (2026-10-27)

- authorize/3, closed by default; v0.3.0

## v0.2.0 (2026-10-27)

- races, re-check guard, smaller fixes, create_session error return; v0.2.0

## v0.1.1 (2026-10-27)

- macaw_auth 0.1.1: Macaw.Auth.announce_revoked/2

## v0.1.0 (2026-10-27)

- macaw_auth 0.1.0: the contract, the conformance kit, and the native backend (passwords, LDAP, sessions, throttle, TOTP)
