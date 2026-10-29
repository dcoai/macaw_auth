# Changelog

## Unreleased

- **Breaking: enrollment owed at sign-in has no session; it is carried by a sealed ticket, and nothing unconfirmed is stored.** A user whom policy requires to enroll a second factor (`second_factor: :required`) gets no session when their password is accepted: `Macaw.Auth.Plug.log_in/3` puts an enrollment ticket in the Plug session instead (`"macaw_auth_enrollment_ticket"`), deletes a remember cookie the browser sent, assigns nothing, and redirects to `path(:second_factor_enroll)`. The ticket is a term (account id, purpose, issue time, the pending TOTP secret sealed as at rest), sealed with `Macaw.Auth.Native.Seal` under `sealing_key` (associated data `"macaw_auth enrollment_ticket"`), ten minutes long, a constant (`Macaw.Auth.Native.Ticket`). The enrollment page shows `Macaw.Auth.Plug.enrollment/1` and submits to `Macaw.Auth.Plug.enroll_second_factor/2`, which confirms the code behind the throttle (the account's `{:second_factor, id}` key and the address) and only then starts the session, its second factor passed, answering `{:ok, recovery_codes, conn}` unredirected for the page to show them. A ticket expired, tampered, of another purpose, spent (its account enrolled since), or whose account is gone, disabled or no longer required to enroll is `{:error, :invalid_ticket}`. The session-first path is removed, with no mode to keep it (#5, dco-tek/macaw/macaw#101):
  - `Macaw.Auth.create_session/2` of a `:required` user is `{:error, :enrollment_required}`, whatever the options, without asking the backend.
  - `:second_factor_enroll` is no longer a step: `Macaw.Auth.steps/0` is `[:second_factor, :password_change]`, `Macaw.Auth.complete_step/3` and `Macaw.Auth.Plug.complete_step/2` refuse it (`FunctionClauseError`), and `pending_step/2` never answers it (a session of a `:required` user, which only one from before policy required it could be, owes `:second_factor`, which no code passes). `path(:second_factor_enroll)` stays, as the enrollment page's.
  - `Macaw.Auth.Backend` gains three callbacks, `enrollment_ticket/2`, `enrollment/2` and `enroll_second_factor/3` (facade functions of the same names); a backend without a second factor answers them `{:error, :unsupported}`. macaw_auth_ash must add them to move to this release; the kit's ticket cases bind it as its other second-factor cases do, skipped while it runs with `pending: [second_factor: …]` (spec/04).
  - The conformance kit has twenty-five tests: test 21 (a `:required` user owes `:second_factor_enroll`) is replaced by four: no session but a ticket, enrolled from the ticket alone; expired (600 s, by `:now`) or tampered refused; spent by its enrollment; refused once its account is disabled. `pending: [second_factor: …]` skips eight.
  - A signed-in user choosing to enroll is by ticket too (purpose `:chosen`): `Macaw.Auth.Native.enroll_begin/2` answers `{:ok, %{ticket, secret, uri}}` and stores nothing (it used to store a pending sealed secret, and resume it on a reload); `Macaw.Auth.Native.enrollment/2` shows a ticket's secret again; `Macaw.Auth.Native.enroll_confirm/4` (`user`, `ticket`, `code`, `opts`) replaces `enroll_confirm/3`, refusing another account's ticket, and its `:not_started` refusal is gone (`:invalid_ticket`). A confirmation writes the ticket's sealed secret to the row, conditional on the account being neither enrolled nor disabled, so of two racing one enrolls.
  - **The adopter's change, Collpa's enrollment pages** (in a Collpa work item after this release, when Collpa adopts macaw_auth; today they are Collpa's own code): `lib/collpa/web/admin/user_auth.ex:130` `log_in/3` must not create a session for a user owing enrollment (`:enrol`), but hand over to `Macaw.Auth.Plug.log_in/3`, which issues the ticket; `:26` the `totp_enrol` step and `:69-74` `pending_step/2`'s enrollment branch go (only the code step remains); `lib/collpa/web/admin/session_controller.ex:17-18` passes the user to `Macaw.Auth.Plug.log_in/3`; `lib/collpa/web/admin_router.ex:54-55` moves `/totp/enrol` for the owed case out of the `:signed_in` scope (`:47-56`) into a signed-out one (keeping a signed-in route for the account page's chosen enrollment, `lib/collpa/web/admin/account_live.ex:175`); `lib/collpa/web/admin/totp_controller.ex:40-44` `enrol/2` renders from `Macaw.Auth.Plug.enrollment/1` (no current user), `:46-61` `confirm/2` calls `Macaw.Auth.Plug.enroll_second_factor/2` and renders the codes, dropping `Sessions.mark_totp_passed/1` (`:49`), `:63-78` `render_enrol/2` takes the ticket's secret and URI instead of `Totp.start_enrolment/2` (`:64`) and drops `required: pending_step == :totp_enrol` (`:76`); `lib/collpa/accounts/totp.ex:29` `start_enrolment/2` and `:56` `confirm_enrolment/3`, which keep an unconfirmed `user_totp` row, give way to the ticket.
- **Breaking: a migration.** The sign-in throttle's counts are rows of a new table, `macaw_auth_throttle` (`Macaw.Auth.Native.ThrottleRecord`), so a restart, a crash or a deploy forgets none of them; run `mix macaw_auth.gen.migration` again for its migration, `create_macaw_auth_throttle`, the only one a host on 0.4 lacks. The user key is the account's id (`{:account, id}`, from `Macaw.Auth.Native.Throttle.user_key/1`), so renaming an account keeps its count; a name no account has is counted on its own key with the same curve, so an unknown name waits exactly as a known one does. The second factor's key is the account's id too. Address counts are in the table as well, and the sweep deletes old rows; the process only sweeps. `Throttle.check/3`, `failure/3` and `success/1` take the new user keys, not a bare username, and `Throttle.rows/0` lists the rows. The curve is unchanged and still a constant. spec/10 §7's model gains a restart (#4, dco-tek/macaw/macaw#101).
- **Breaking: a migration.** A directory user's external id has one spelling for every value. It is the binary the directory gave (an LDAP source's first `id_attr` value, printable or not, else the DN), held in a new column, `macaw_auth_users.external_id`, whose Ecto type `Macaw.Auth.Native.ExternalId` spells it as lower-case hex of its bytes and reads it back to those bytes. Before, `extra["external_id"]` kept the value itself when it printed and hex otherwise, so the text `"00ff"` and the bytes `<<0, 255>>` were spelled alike. The source no longer spells it: `Source.Ldap.authenticate/4`'s attrs carry `external_id` (the binary) beside `extra`, which loses the key, and `Macaw.Auth.Native.Provision` writes it at the first sign-in and every later one; `UserRecord.changeset/2` never casts it. `Macaw.Auth.User`'s `extra` no longer holds it: read the row (`Macaw.Auth.Native.get_user/1`). Run `mix macaw_auth.gen.migration` again for `add_macaw_auth_external_id`, after the throttle's: it moves each stored id into the column, the value itself when its old spelling says so (not hex, or hex of bytes that print, which the old rule would have kept as themselves), and leaves the column nil when either spelling could have written it (hex of bytes that don't print, such as `"12345678"`), for the user's next sign-in to fill from the directory; the row is found by username, so the sign-in is unchanged. Down puts the old spellings back. spec/06 §6, spec/07 §3, spec/12 §5 (#13, dco-tek/macaw/macaw#188 A1).
- A direct-bind LDAP source can read its groups as a service account: `groups: %{base_dn: …, member_attr: …, bind_dn: …, bind_password: …}` binds as `bind_dn` after the user's bind succeeded, then searches for the groups, for a directory that lets a user read only their own entry. `bind_password` is a secret as `search.bind_password` is, in no fault, log line, answer or diagnostic step; `mix macaw_auth.ldap.check` shows the bind as its own step. Refused with `from: :member_of`, in search mode, and one without the other; without them, the user's own bind reads the groups as before. A refused group bind is `:group_search_failed`, whose explanation now names the bind (#3, dco-tek/macaw/macaw#93).
- The remember cookie is `secure` when the request is https or the host declares an https public URL, `config :macaw_auth, public_url: "https://…"` (`Macaw.Auth.Plug.public_scheme/0`), so a host behind a TLS-terminating proxy gets it without trusting a forwarded header. It only adds `secure`: an https request always has it, and nothing declared leaves today's rule. A public URL that is not an http or https URL refuses boot (#2, dco-tek/macaw/macaw#93).
- The conformance kit's "a user's sessions list newest first" no longer sleeps: it starts the two sessions a minute apart with `create_session/2`'s `:now` (spec/01 §2.2, already the contract) and expects the later first. A backend that stamps a session's creation time from `:now`, as the native and Ash backends do, passes unchanged; one that ignores `:now` there passed only by the sleep's wall-clock gap, and no longer reliably does. CI refuses `Process.sleep` and `:timer.sleep` in test/ and the kit (`ci/no_sleep.exs`, its allowlist empty) (#12, #9).
- The timing tests check their claim by the work that runs, not by elapsed time: an unknown user and a wrong password (spec/06 §3), and a blocked attempt and a checked one (spec/10 §5), are each exactly one bcrypt operation at the same cost, as a counting hasher reports it (`Macaw.Auth.Test.CountingHasher.work/1`), where they compared medians of `:timer.tc`, which on a shared runner measure the runner. CI refuses `:timer.tc`, the monotonic clocks, `:os.perf_counter` and `:timer.now_diff` in test/ and the kit (`ci/no_timing.exs`, its allowlist empty) (#16, #15).
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
