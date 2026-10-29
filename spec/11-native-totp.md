# 11 — Native: the second factor {#auth-totp}

The native backend's second factor is TOTP with recovery codes: `Macaw.Auth.Native.Totp`, on the `macaw_auth_users` row and in `macaw_auth_recovery_codes`, ported from exio's and macaw's `Accounts.Totp`, which are the same rules. apu and Snow implemented the same rules independently, a third and fourth time (macaw_compose#32). The secret is sealed at rest by `Macaw.Auth.Native.Seal` (§4), and an enrollment travels in a sealed ticket (§3.1), so nothing unconfirmed is ever stored.

**The throttle is `Macaw.Auth.Native`'s.** A host calls `Macaw.Auth.Native.verify_second_factor/3`, `enroll_second_factor/3`, `enroll_confirm/4` and `disable/3`, which put every code check behind it ([10 §4](10-native-throttle.md#auth-throttle-second-factor)); the `Macaw.Auth.Native.Totp` functions they call don't throttle. **Every function honors `:now`** (a `DateTime`).

## 1. Codes {#auth-totp-codes}

**RFC 6238 through `NimbleTOTP`:** SHA-1, six digits, 30-second steps, a 160-bit (20-byte) random secret. `Macaw.Auth.Native.Totp.code/2` (`secret`, unix seconds or a `DateTime`) gives a time's code, and `Macaw.Auth.Native.Totp.step/1` its step, `div(unix seconds, 30)`.

**The window is the current step and one either side,** so a clock a little off still works; two steps away is refused. Every candidate step's code is compared with **`Plug.Crypto.secure_compare/2`**, in constant time each.

**Input is normalized** (`Macaw.Auth.Native.Totp.normalize/1`): spaces and dashes removed, letters upper case. Anything not a binary, or longer than 64 bytes, is `""`. After normalizing, **six digits is a TOTP code, ten characters of the recovery alphabet is a recovery code** (§6), and anything else is refused like a wrong code.

```test:totp-window
for offsets -1, 0 and 1 steps from now, an enrolled user's code is accepted; for -2, 2, -3 and 3, {:error, :invalid_code}
```

```test:totp-normalize
" 123 456 " and "123-456" (a valid code split) are accepted; "", "12345", "1234567", "abcdef", nil, 123456 and 100 ones are each {:error, :invalid_code}
```

```test:totp-secure-compare
Macaw.Auth.Native.Totp imports Plug.Crypto.secure_compare/2
```

## 2. A code works once {#auth-totp-replay}

**The step a code was accepted for is stored** (`totp_last_step`), and a code is accepted **only for a later step**. Of the window's steps that match, the earliest later than the stored one is taken.

**The claim is a conditional update,** `Macaw.Auth.Native.Totp.claim_step/3` (`repo`, `user_id`, `step`): `UPDATE … SET totp_last_step = step WHERE id = user AND totp_enabled_at IS NOT NULL AND (totp_last_step IS NULL OR totp_last_step < step)`. A write that changes no row is a refusal (`:replayed`, a wrong code to the caller). So of two submissions of one code racing each other, **the database lets exactly one through.** exio's guard was the same; a read-then-write would let both through.

**The confirming code can't sign in:** enrollment records the step its confirming code was accepted for (§3).

```test:totp-replay
a code accepted at a step is refused again, and so is the previous step's code; totp_last_step is the accepted step
```

```test:totp-claim-step
claim_step at step s is :ok, then :replayed at s and at s - 1, then :ok at s + 1
```

```test:totp-concurrent
eight concurrent verifications of one code: exactly one :ok and seven {:error, :invalid_code}
```

```test:totp-confirming-code
the code that confirmed an enrollment at t0 is refused at t0
```

## 3. Enrollment {#auth-totp-enroll}

**Nothing unconfirmed is stored.** An enrollment begun is a fresh secret sealed into an **enrollment ticket** (§3.1) that the client holds; no table is written until a code confirms it, so an abandoned enrollment leaves nothing behind and a pending secret is never at rest. Until then, nothing changes at sign-in. There are two ways in, by the ticket's purpose:
- **owed at sign-in** (`:owed`): a user whom policy requires to enroll (`:required`, §7) gets **no session** at sign-in, but a ticket, and enrolls from the ticket alone (§3.2);
- **chosen** (`:chosen`): a signed-in user chooses to enroll, on a page of the host's (its account page). `Macaw.Auth.Native.enroll_begin/2` (`user`, `opts`) begins: `{:ok, %{ticket, secret, uri}}`, the ticket for the page to keep, the secret, and the `otpauth://` URI for the page's QR code, its label `<issuer>:<username>` and its `issuer` the configured `totp_issuer`; `{:error, :already_enrolled}` for an enrolled user, `:disabled` for a disabled one, `:not_found` for no such user. `Macaw.Auth.Native.enroll_confirm/4` (`user`, `ticket`, `code`, `opts`) confirms behind the throttle: `{:ok, recovery_codes}`, or `{:error, :invalid_code | :throttled | :invalid_ticket}`, the ticket refused as §3.1 refuses one, and also when it is **another account's** than `user`'s.

**What a page shows.** `Macaw.Auth.Native.enrollment/2` (`ticket`, `opts`) gives `{:ok, %{secret, uri}}` for a ticket of either purpose, so a reload shows the same secret and QR code (the holder of a ticket already holds its secret), or `{:error, :invalid_ticket}` (§3.1).

**Confirming** (`Macaw.Auth.Native.Totp.enroll_confirm/3`, behind the throttle in both ways in) checks the code against the ticket's secret (the window, §1) and then, in one transaction, **writes the ticket's sealed secret to the row as it is**, with `totp_enabled_at` and the confirming code's step (so the code can't then sign in, §2), and makes ten recovery codes, shown once and never retrievable again (§6). **The write is conditional** on the account being neither enrolled nor disabled (`UPDATE … WHERE id = ? AND totp_enabled_at IS NULL AND disabled_at IS NULL`): of two confirmations of one ticket racing each other, exactly one enrolls, and the other, like a confirmation of an account disabled meanwhile, is `{:error, :invalid_ticket}`. A wrong code is `{:error, :invalid_code}`, and changes nothing.

The issuer is checked when the configuration is read ([05 §2](05-native-config.md#auth-native-config)): it prefixes the label, so a colon in it is a fault.

```test:totp-issuer-setting
Config.parse with totp_issuer "a:b" is {:error, "totp_issuer: …"}
```

```test:totp-enroll
enroll_begin gives a 20-byte secret and a ticket, which enrollment/2 shows again with the same secret and uri; the uri is "otpauth://totp/Test%20App:<user>?secret=<base32>&issuer=Test%20App"; the user is still :none; a code an hour off is :invalid_code; the right code gives ten codes and makes the user :enrolled; then begin is :already_enrolled and confirming the same ticket again :invalid_ticket
```

```test:totp-not-started
enroll_confirm with no ticket, "", junk, or another user's ticket is {:error, :invalid_ticket}, and the user stays :none
```

```test:ticket-nothing-stored
after enroll_begin and enrollment_ticket, every row of the users, sessions, recovery-codes and throttle tables is as before; totp_secret_sealed stays nil; no stored value contains either secret, its Base32, or the ticket's sealed secret
```

```test:totp-enrolled-owes
an enrolled user's new session owes :second_factor
```

### 3.1 The enrollment ticket {#auth-totp-ticket}

`Macaw.Auth.Native.Ticket` is what carries an enrollment between its pages.
- **Its internal form is a term,** `%{account_id, purpose, issued_at, secret}`: the account's id, the purpose (`:owed` or `:chosen`), the issue time in unix seconds (the `:now` option's, else the clock's), and **the pending secret, sealed as it would be at rest** (§4, bound to the account), so a confirmation writes it to the row unchanged.
- **Sealed at the edge.** The term is encoded (`:erlang.term_to_binary/1`) and sealed with `Macaw.Auth.Native.Seal` (§4) under the key derived from the configured `sealing_key`, its associated data **`"macaw_auth enrollment_ticket"`**: those sealed bytes are the ticket, and **only they ever leave the process.** The associated data sets it apart from every other sealed value, so a stored TOTP secret, or anything else sealed under the same key, never passes for a ticket.
- **Ten minutes, a constant.** `Macaw.Auth.Native.Ticket.ttl_seconds/0` is 600; no setting changes it. A ticket is refused from 600 seconds after its issue time.
- **Refused** (`{:error, :invalid_ticket}`, the one refusal, whatever was wrong): a ticket that doesn't authenticate (tampered, truncated, sealed under another key or with other associated data, not a binary); expired; **of another purpose** than the call takes (an `:owed` ticket at `enroll_confirm/4`, a `:chosen` one at `enroll_second_factor/3`); or whose account is **gone, disabled, or enrolled since** (`Macaw.Auth.Native.Totp.open_ticket/3`), and for an `:owed` ticket, one that policy **no longer requires** to enroll (a role change: signing in again gives a session).
- **A ticket is spent by the enrollment it completes:** confirming enrolls the account, and a ticket of an enrolled account is refused, so the same ticket confirms once, and the conditional write (§3) settles two confirmations racing. Nothing records a ticket's use; the account's own state does.

```test:ticket-term
enrollment_ticket's answer is a binary that unseals under the derived key with "macaw_auth enrollment_ticket" to a term of exactly account_id (the user's), purpose :owed, issued_at (now's unix seconds) and secret, which unseals with "macaw_auth totp_secret <id>" to the secret enrollment/2 shows; the ticket's bytes contain neither the secret, its Base32 nor its Base64
```

```test:ticket-ttl
ttl_seconds() is 600; a ticket issued at t0 shows its secret at t0 + 599 s and is {:error, :invalid_ticket} at t0 + 600 s, for enrollment/2 and enroll_second_factor/3 alike, by the :now option; at t0 + 599 s it enrolls
```

```test:ticket-tampered
a ticket with its last byte flipped, its term sealed with the totp_secret associated data, its term sealed under another key, its first 20 bytes, "", nil and 42 are each {:error, :invalid_ticket} for enrollment/2 and enroll_second_factor/3, and the account stays unenrolled
```

```test:ticket-purpose
an :owed ticket at enroll_confirm/4 and a :chosen one at enroll_second_factor/3, each with a valid code, are {:error, :invalid_ticket} and enroll nothing; enrollment/2 shows either
```

```test:ticket-spent
after an owed ticket enrolls its account, the same ticket is {:error, :invalid_ticket} for enrollment/2 and for enroll_second_factor/3 with the next step's code, and enrollment_ticket for the account is {:error, :invalid}
```

```test:ticket-account
a ticket whose account was disabled, deleted, or moved to a role policy doesn't require, during its lifetime, is {:error, :invalid_ticket}; enrollment_ticket of a disabled user, of a user owing nothing, and of an unknown id is {:error, :invalid}
```

### 3.2 Enrollment owed at sign-in {#auth-totp-owed}

**An account that must enroll a second factor gets no session when its password is accepted** (apu §4.8.4 #totp-enrol, dco-tek/macaw/macaw#101). It gets a ticket that can do nothing but enroll it, and only a confirmed second factor lets a session start, so a password alone never holds a session. The backend callbacks ([01 §2.10](01-contract.md#auth-backend-enroll)):
- `Macaw.Auth.Native.enrollment_ticket/2` (`user`, `opts`): `{:ok, ticket}`, purpose `:owed`, for an enabled account that policy requires to enroll and that hasn't; `{:error, :invalid}` for any other (gone, disabled, enrolled, not required). `Macaw.Auth.Plug.log_in/3` asks for it in place of a session ([02 §7](02-plugs.md#auth-plug-log-in));
- `Macaw.Auth.Native.enrollment/2`, as above, for the page's QR code;
- `Macaw.Auth.Native.enroll_second_factor/3` (`ticket`, `code`, `opts`): completes the enrollment **from the ticket alone**, behind the throttle on the account's second-factor key and the client's address ([10 §4](10-native-throttle.md#auth-throttle-second-factor)), counted only once the ticket is accepted (a refused ticket is no code check): `{:ok, user, recovery_codes}`, the user now `:enrolled`, or `{:error, :invalid_code | :throttled | :invalid_ticket}`. It starts no session: the caller does, its second factor passed (`Macaw.Auth.Plug.enroll_second_factor/2`, [02 §8.1](02-plugs.md#auth-plug-enroll)). Options: `:remote_ip`, `:now`.

```test:ticket-from-alone
a user owing enrollment gets {:error, :enrollment_required} from create_session; from its ticket and a valid code, enroll_second_factor gives the user :enrolled and ten codes, and no session row exists before or after; the confirming code then fails a session's second factor
```

```test:ticket-throttle
a refused ticket counts nothing; five wrong codes on an owed ticket count 5 on {:second_factor, id} and on the address; the right code is then {:error, :throttled}, and a second later enrolls and clears the account's key
```

## 4. Sealing the secret {#auth-totp-seal}

`Macaw.Auth.Native.Seal` seals what must not be read back from the table, the TOTP secret, and what leaves the process to come back, the enrollment ticket (§3.1, under its own associated data), with **AES-256-GCM** (OTP's `:crypto`):
- **the key** is the configured `sealing_key` ([05 §2](05-native-config.md#auth-native-config)): a binary of at least 32 bytes, or `{module, function, args}` returning one, **called at each use** (so a host can keep it in its data directory, or derive it from its `secret_key_base`, without this library depending on how; no dependency on macaw_host). `Macaw.Auth.Native.Seal.min_bytes/0` is 32;
- **derived, not used as is:** `Macaw.Auth.Native.Seal.key!/1` gives the AES key as **HMAC-SHA256 of a fixed label (`"macaw_auth sealing v1"`) under the configured key,** so a host may pass a longer secret it also uses elsewhere and the two uses never share a key;
- **bound to its row:** the associated data is `"macaw_auth totp_secret "` followed by **the user's id,** so a sealed secret copied onto another user's row does not unseal there;
- **the format:** `<<1, iv::12 bytes, tag::16 bytes, ciphertext>>`, the first byte a version so a later scheme can be told apart, and **a fresh random IV for every seal** (`Macaw.Auth.Native.Seal.seal/3`);
- `Macaw.Auth.Native.Seal.unseal/3` gives `{:ok, plaintext}`, or `{:error, :wrong_key}` for anything that fails to authenticate: a different key, a tampered value, another row's value, garbage.

**A key fault is loud, never a refusal.** `Macaw.Auth.Native.SealingKeyError` is raised, its message naming the fault and **never the key:**
- **a missing key** at first use: `"… sealing_key is not set; …"`;
- **a function's result** that isn't a binary of 32 bytes: `"… sealing_key <Module>.<function>/<arity> did not return a binary of at least 32 bytes"` (its arguments are never shown: they may hold a secret);
- **a short literal key** would be raised too, but the configuration already refuses it ([05 §2](05-native-config.md#auth-native-config));
- **a stored secret that doesn't unseal** with the configured key: `"a stored TOTP secret does not unseal with the configured sealing_key: the key has changed since it was sealed, or the row was altered"`. An operator's fault, not a wrong code: raised, so it is seen, rather than every enrolled user being silently refused.

The secret leaves `Macaw.Auth.Native.Totp` only from `enroll_begin/3` and `enrollment/2`, for the enrollment page; between the pages it travels only sealed, inside the ticket (§3.1).

```test:seal-never-stored
property: for up to five users, after beginning enrollment the stored column is nil, and after confirming it contains neither the secret nor its Base32 or Base64, and no column of their row contains the secret or its Base32
```

```test:seal-fresh-iv
sealing "secret" twice under one key gives two different values, each unsealing to "secret"
```

```test:seal-wrong-key
a value sealed for "user a" doesn't unseal under another key, nor for "user b", and "garbage" doesn't either, each {:error, :wrong_key}; after the configured key changes, verifying an enrolled user's code raises SealingKeyError "does not unseal with the configured sealing_key"
```

```test:seal-row-bound
alice's sealed secret copied onto enrolled bob's row raises SealingKeyError when bob's code is verified
```

```test:seal-short-key-config
Config.parse with sealing_key "too short a key" is {:error, "sealing_key: must be at least 32 bytes"} and with 42 "sealing_key: must be a binary…"; a parsed configuration's inspection shows neither the key nor "sealing_key"
```

```test:seal-key-missing
with no sealing_key, enroll_begin raises "sealing_key is not set"; with an MFA returning a short key, "sealing_key Macaw.Auth.Native.TotpTest.key/1 did not return"; with an MFA returning 44 bytes, enrollment begins
```

## 5. Verifying a code {#auth-totp-verify}

`Macaw.Auth.Native.verify_second_factor/3` (`session_id`, `code`, `opts`) is the backend callback ([01 §2.7](01-contract.md#auth-backend-verify)): it resolves the session by id **without touching it** (a refusal is the session's own: `:invalid`, `:expired`, `:disabled`), checks the code for its user behind the throttle ([10 §4](10-native-throttle.md#auth-throttle-second-factor)), and on success completes the session's `:second_factor` step. `:ok`, or `{:error, :invalid_code | :throttled}`.

`Macaw.Auth.Native.Totp.verify/3` checks a TOTP code (§1, §2) or an unspent recovery code (§6) of an **enrolled** user. `:ok` spends it: the step, or the recovery code, never works again. Otherwise **`{:error, :invalid_code}`, the same whatever was wrong:** not enrolled, a wrong code, a replayed one, junk.

```test:totp-recovery-on-session
a recovery code passes an enrolled user's session's second factor through verify_second_factor/3, and the session then owes nothing
```

## 6. Recovery codes {#auth-totp-recovery}

- **Ten codes,** each **ten characters of an alphabet without look-alikes** (`23456789ABCDEFGHJKLMNPQRSTUVWXYZ`: no 0, O, 1 or I), 32 symbols so a random byte's low five bits pick one without bias (50 bits a code). They are shown in two groups of five, `ABCDE-FGHJK`, and accepted in any case and spacing (§1).
- **Stored only as SHA-256** of the normalized code, one row each in `macaw_auth_recovery_codes` (`Macaw.Auth.Native.RecoveryCodeRecord`), `(user_id, code_hash)` unique. The codes are random, so an unsalted hash is as strong as the code; a copy of the table spends nothing.
- **A code is spent by deleting its row, conditionally** (`DELETE … WHERE user_id = ? AND code_hash = ?`): it either happens or doesn't, so two submissions of one code can't both find it. A table rather than a list in a column, which would need a read, a change and a compare-and-set write of the whole list.
- `Macaw.Auth.Native.recovery_codes_left/1` (`Macaw.Auth.Native.Totp.recovery_codes_left/1`) counts the unspent ones (0 for an id that isn't a UUID).
- `Macaw.Auth.Native.regenerate_recovery_codes/2` (`Macaw.Auth.Native.Totp.regenerate_recovery_codes/2`) replaces an enrolled user's codes, in one transaction: `{:ok, codes}` (shown once; the old ones no longer work), or `{:error, :not_enrolled}`.

```test:recovery-codes
enrollment gives ten distinct codes matching [2-9A-HJ-NP-Z]{5}-[2-9A-HJ-NP-Z]{5}, ten left; no stored value contains a code with or without its dash; the stored hashes are the SHA-256 of the codes without dashes
```

```test:recovery-once
a recovery code is accepted once (nine left), then refused; another, lower-cased with its dash a space, is accepted (eight left)
```

```test:recovery-regenerate
regenerating gives ten new codes, ten left; every old one is refused and a new one accepted; a user not enrolled gets {:error, :not_enrolled}
```

## 7. Policy {#auth-totp-policy}

`totp_required` ([05 §2](05-native-config.md#auth-native-config)) decides `Macaw.Auth.Native.Totp.status/2`, a user's `second_factor` in the contract ([01 §7.1](01-contract.md#auth-user)):
- **`:enrolled`** once an enrollment is confirmed (`totp_enabled_at` set);
- else **`:required`** when policy requires one (`Macaw.Auth.Native.Totp.required?/2`): `true` requires it of everyone, a list of roles of a user with any of them;
- else **`:none`**.

A `:required` user owes enrollment at sign-in, and **gets no session until they enroll** (§3.2; `Macaw.Auth.create_session/2` refuses them, [01 §5](01-contract.md#auth-create-session)): an enrollment ticket instead. Once the ticket's enrollment is confirmed they are `:enrolled`, and the session that then starts has its second factor passed and owes nothing more for it.

The setting is checked when the configuration is read ([05 §2](05-native-config.md#auth-native-config)): `false`, `true`, or a non-empty list of role names; anything else is a fault naming `totp_required`.

```test:totp-policy-setting
Config.parse with totp_required [] or "yes" is {:error, "totp_required: …"}
```

```test:totp-policy-roles
with totp_required ["admin"]: an admin not enrolled is :required, gets {:error, :enrollment_required} from create_session and no session, and a ticket; a viewer is :none, owes nothing, and gets no ticket; after enrolling from the ticket, the admin is :enrolled and a session with its second factor passed owes nothing
```

```test:totp-policy-everyone
with totp_required true, a new user is :required
```

## 8. Turning it off {#auth-totp-disable}

- **The user** turns it off with `Macaw.Auth.Native.disable/3`, which puts `Macaw.Auth.Native.Totp.disable/3` behind the throttle, proving it with a current code or a recovery code (which is spent): `:ok`, the sealed secret, enabled time, last step and recovery codes all deleted, in one transaction. **Refused with `{:error, :required}` while policy requires one** (an administrator's reset then); `{:error, :invalid_code}` for a wrong code or a user not enrolled.
- **An administrator** clears it with `Macaw.Auth.Native.admin_reset/2` (`Macaw.Auth.Native.Totp.admin_reset/2`; a lost device), **and revokes every session of theirs** with reason `:second_factor_reset` (`Macaw.Auth.Native.Sessions.revoke_all/3`, [09 §5](09-native-sessions.md#auth-sessions-revoke)), so their open pages disconnect: they sign in again, and enroll again if policy requires. `:ok`, also for an id that isn't a UUID (nothing happens). With option `announce: false` the sessions are revoked without the push, for a process that is not the app's node; `mix macaw_auth.user reset-second-factor` and its release entry point run it so ([13 §1](13-native-users.md#auth-users-api)).

```test:totp-disable
"abcdef" doesn't disable; a current code does: the user is :none, the sealed secret nil, no recovery codes left; an admin under totp_required ["admin"] gets {:error, :required}
```

```test:totp-admin-reset
admin_reset of an enrolled user with a session: :ok, the token no longer resolves, a subscriber hears {:sessions_revoked, [_]}, the user is :none with no recovery codes
```

## 9. Telemetry {#auth-totp-telemetry}

`[:macaw_auth, :native, :second_factor]`, measurements `%{count: 1}`, metadata exactly `%{event, user_id}`, the event one of `:enrollment_started`, `:enrolled`, `:verified`, `:recovery_code_used`, `:refused`, `:disabled`, `:reset`, `:recovery_codes_regenerated`. **Never a secret or a code.**

```test:totp-telemetry
an enrollment then a verification emit :enrollment_started, :enrolled and then an event whose metadata keys are exactly [:event, :user_id]
```
