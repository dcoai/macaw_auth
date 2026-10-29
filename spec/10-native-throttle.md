# 10 — Native: the throttle {#auth-throttle}

`Macaw.Auth.Native.Throttle` slows guessing: sign-in failures, and second-factor code failures, back off per account and per client address. It is ported from exio's and macaw's `Accounts.Throttle`, which are the same mechanism; four of the eight adopters had no login throttling at all (macaw_compose#32). **Its counts are rows in the host's database** (§6), so a restart, a crash or a deploy gives a guesser no fresh budget, and **an account is counted by its id**, so renaming it keeps its count (macaw#101, which apu's sign-in guarantees needed).

**Not a request rate limit.** `Macaw.Plug.RateLimit` limits requests per window; this is a different policy (backoff after failures, reset by success), so it is its own small table rather than a configuration of that one (macaw_compose#34, decided at evaluation).

**Its values are constants:** five free failures, `2^(n-5)` seconds, a 15-minute cap, a day's memory. They are mechanism, not a host's policy, so nothing configures them (macaw_compose#32, policy surface).

## 1. Keys {#auth-throttle-keys}

Failures are counted per key. A key is a term; its columns in the table are an encoding at the database's edge (§6).
- **the user,** `{:user, user}`, where `user` is what `Macaw.Auth.Native.Throttle.user_key/1` gives for the typed username, normalized as the users table stores it ([06 §5](06-native-sources.md#auth-user-record)), so `Alice`, `alice ` and `ALICE` share a count:
  - **`{:account, id}`** when the name is an account's: the account's id, not its name, so **renaming the account keeps its count**;
  - **`{:name, name}`** when no account has the name;
  - **`:invalid`** for anything that can't be a username: one shared key (it can never sign in, so nobody is slowed by sharing it).

  It slows guessing one account from many addresses;
- **the address,** `{:ip, address}`: the `:remote_ip` the caller passed, as a string ([02 §5](02-plugs.md#auth-plug-authenticate)). It slows one address trying many accounts;
- **no address, no address key:** a caller that passes no `:remote_ip` (a console task) is throttled by username alone, rather than sharing one "unknown address" key with every other such caller;
- **the second factor's own user key,** `{:user, {:second_factor, id}}`, the account's (§4).

**An unknown name costs what a known one does.** A name no account has is counted on its own key with the same curve (§2), so failures against it get the same waits and the same `:throttled` as failures against an account: the throttle answers nothing about which names exist. `user_key/1` is one indexed look-up of the users table whether the name is found or not. Not counting unknown names, or counting them all on one key, would each tell a guesser which names are accounts.

A name's count is its own, and an account's is its own: an account made later with a name that has failures, or renamed to it, starts from the account's count, not the name's; after a rename, the old name is a name no account has. A directory user who has not signed in yet has no row ([06](06-native-sources.md)), so is counted by name until their first sign-in makes one.

`Macaw.Auth.Native.Throttle.check/3` (`user`, `ip`, `now`) gives `:ok`, or `{:delay, ms}` left before the attempt may be checked: **the longer of the two keys' waits.** `Macaw.Auth.Native.Throttle.failure/3` (`user`, `ip`, `now`) counts a failure on both. `now` is milliseconds of the system clock (`Macaw.Auth.Native.Throttle.now/0`), passed by every caller, so tests drive it without sleeping.

```test:throttle-per-address
five failures from 198.51.100.1 at five usernames: mia's right password from that address is throttled, and from 198.51.100.2 signs in
```

```test:throttle-per-username
five failures at ned from five addresses: ned's right password from a sixth address is throttled; oli's from that address signs in
```

```test:throttle-normalized
failures as "Pat", " PAT ", "pat", "pAt" and "pat " throttle "pat"
```

```test:throttle-no-address
five failures at five usernames with no address: a sixth username's attempt is checked (:invalid_credentials), not throttled
```

```test:throttle-rename
five failures at nia, then her account renamed nina: nina's right password is throttled, user_key("nina") is {:account, her id}; "nia" is then {:name, "nia"}, checked and refused (:invalid_credentials); nina signs in a second later
```

```test:throttle-unknown-name
for every n from 0 to 16 failures, an account and a name no account has wait the same, 0 for n < 5, then 1 000, 2 000 … 512 000, then 900 000 (§2's table), and the next wrong password gets the same answer for both
```

## 2. The backoff {#auth-throttle-backoff}

`Macaw.Auth.Native.Throttle.delay_ms/1` is the wait after `n` consecutive failures:
- **the first five are free:** fewer than five failures wait nothing;
- **from the fifth, `2^(n-5)` seconds:** 1 s after five, 2 s after six, 4, 8, 16 …;
- **capped at 15 minutes** (900 000 ms), which `n` = 15 and beyond reach.

**The wait runs from the key's last failure:** the latest failure's time, whichever order failures are recorded in (§6). An attempt inside it is refused, `:throttled`, **without checking the password** ([05 §1.2](05-native-config.md#auth-native-throttled)), and is not counted; an attempt after it is checked as usual, and another failure doubles the next wait.

**Nothing is ever locked for good:** the right password succeeds once the wait has passed, so a guesser can't lock a user out for longer than the cap.

| Failures | 0–4 | 5 | 6 | 7 | 8 | 9 | 14 | 15 | 1 000 000 |
|---|---|---|---|---|---|---|---|---|---|
| Wait (ms) | 0 | 1 000 | 2 000 | 4 000 | 8 000 | 16 000 | 512 000 | 900 000 | 900 000 |

```test:throttle-delays
delay_ms/1 gives each column of the table
```

```test:throttle-wait
five failures at 0: the right password is throttled at 0 and at 999 ms; a wrong one at 1 000 is checked; then the right one is throttled at 2 999 and signs in at 3 000
```

```test:throttle-cap
after 40 failures at 0, check gives {:delay, 900 000} at 0, {:delay, 1} one millisecond before the cap, and :ok at the cap
```

## 3. Resets {#auth-throttle-reset}

`Macaw.Auth.Native.Throttle.success/1` (`user`) forgets the user key's count (a sign-in resets the key it was checked on): **a success resets the user key only, never the address.** Resetting the address too would let a guesser who holds one valid account clear their address's count between guesses at others (as exio).

```test:throttle-success-resets-user
five failures at kim, then her success from another address after the wait: four more failures leave her free to sign in at once (five free failures again)
```

```test:throttle-success-keeps-address
five failures from 192.0.2.9 at other names: lee is throttled from it at 0; signs in at 1 000; one more failure from it then throttles lee again at 1 001
```

## 4. The second factor's key {#auth-throttle-second-factor}

Code attempts (`Macaw.Auth.Native.verify_second_factor/3`, `enroll_second_factor/3` and `enroll_confirm/4`, the enrollment ticket's account's, `disable/3`, [11](11-native-totp.md)) go through the same throttle: refused unchecked (`{:error, :throttled}`) while a key waits; **a wrong code is a failure,** with the same backoff as a wrong password, so six digits can't be guessed; an accepted code resets the user's key. Other refusals (an enrollment ticket refused, which is checked before any code, or a policy that requires one) are not counted.

- **The user key is the second factor's own,** `{:second_factor, id}`, the account's id. On the sign-in key, every correct password would reset the count and grant a guesser who has the password five more free guesses at the code.
- **The address key is the one sign-in uses,** so code failures from an address slow sign-ins from it, and the reverse.

A blocked code attempt spends no hash's time: a code check is cheap, and the refusal costs about as much.

```test:throttle-code-backoff
five wrong codes for one session from 192.0.2.7: the right code is throttled; a password sign-in doesn't clear that; one second later the right code is accepted
```

```test:throttle-code-address
wrong codes from 192.0.2.8 for five different users: a sixth user's right code from that address is throttled
```

```test:throttle-code-enroll
five wrong confirmation codes on a ticket: enroll_confirm with the right code is {:error, :throttled}
```

## 5. A block takes a hash's time {#auth-throttle-timing}

While blocked, a sign-in still spends the hasher's `no_user_verify/0` ([05 §1.2](05-native-config.md#auth-native-throttled)), so a blocked attempt takes as long as a checked one: the response time doesn't tell a guesser when the block starts or ends.

```test:throttle-timing-work
with a counting hasher, a blocked attempt spends no_user_verify and no verify
```

```test:throttle-timing-measured
at bcrypt cost 9, the medians of nine blocked and nine checked attempts are within a factor of three
```

## 6. The table and its sweep {#auth-throttle-table}

The counts are rows of **`macaw_auth_throttle`** (`Macaw.Auth.Native.ThrottleRecord`) in the configured repo, made by its migration ([12 §2](12-native-migrations.md#auth-migrations-files)). **Nothing is held in memory, so a restart forgets nothing:** a guesser who crashes or outlasts the app, or waits for a deploy, finds every count where it was. `Macaw.Auth.Native.Throttle.rows/0` gives every row as `{key, failures, last_failure_ms}`, sorted (for an operator, and the tests).

- **The columns:** `kind` and `subject`, the key's encoding (`ThrottleRecord.columns/1`, and `ThrottleRecord.key/2` back): `"account"` and the id, `"second_factor"` and the id, `"name"` and the name, `"invalid"` and `""`, `"address"` and the address. `(kind, subject)` is unique; nothing else reads them. Then `failures` and `last_failure_ms`.
- **No foreign key to the users.** An address or a name has no row to reference, and a deleted account's row is swept within a day (§6, the sweep).
- **The address counts are in the table too.** Kept in memory, a restart would hand one address a fresh budget across every account, which is the guarantee this section exists for, and nothing about them needs memory: a failure writes both keys' rows in its one statement.

**A failure is one statement,** an upsert of its keys' rows (`INSERT … ON CONFLICT (kind, subject) DO UPDATE`): a new row holds one failure at the failure's `now`; an existing row gets one more failure and **the later of its time and `now`** (a `CASE`, which Postgres and SQLite both have, where `max` and `GREATEST` are each one database's). The database applies it to each row atomically, so concurrent failures each count, and the row holds the latest failure's time whichever is recorded last. A sign-in takes `now` before it hashes, so a failure with an earlier `now` can be recorded second. Its rows are written in key order, so two concurrent failures never lock rows in opposite orders. A check reads its keys' rows in one query; a success deletes the user key's row.

The throttle first counted, then wrote the failure's own `now` in a second call (`:ets.update_element/3`, when the table was ETS). The model (§7) found two ways that shortened a wait: a failure recorded second overwrote a later time with its earlier one, and a check between the two calls read the new count from the old time. Both were fixed by one atomic update (macaw_compose#67), which the upsert keeps.

```test:throttle-failure-order
five failures at 0, then one at 2 000 and one at 1 000, recorded in that order: both rows hold 7 failures at 2 000; check gives {:delay, 1} at 5 999 and :ok at 6 000
```

```test:throttle-failure-concurrent
400 failures at shuffled times 1-400 from concurrent tasks: each row holds 400 failures at 400
```

**Idle keys are swept.** `Macaw.Auth.Native.Throttle.sweep/1` (`now`) deletes every row whose last failure is more than a day old (`last_failure_ms` is indexed for it), and returns how many it deleted. So the table holds recent failures only, whatever an attacker sends. A day is longer than the cap, so a swept key had no wait left.

**The process only sweeps.** `Macaw.Auth.Native.Throttle`, which the `macaw_auth` application starts whichever backend is configured ([00 §3](00-overview.md#auth-dependencies)), holds no counts: it runs the sweep every `:sweep_every_ms` (default ten minutes) on its `:clock` (default the system clock), both options of `Macaw.Auth.Native.Throttle.start_link/1`. With no native configuration (`Macaw.Auth.Native.Config.fetch/0` refuses one), there is no table, and it sweeps nothing; a native configuration with a fault is boot's to refuse, or the first sign-in's ([05 §2](05-native-config.md#auth-native-config)). So stopping it, or its crash, loses nothing.

`Macaw.Auth.Native.Throttle.reset/0` deletes every row (tests, and an operator's reset).

```test:throttle-restart
five failures at nell from 192.0.2.120, then the application's throttle process stopped and started again: the rows are unchanged; nell is throttled from another address and someone else from 192.0.2.120 at 999 ms, and nell signs in at 1 000
```

```test:throttle-sweep
uma's five failures at 0 and vic's one at a day: sweep at a day deletes nothing; a millisecond later it deletes uma's two rows and keeps vic's, and uma is :ok again
```

```test:throttle-sweep-owner
a failure two days old and one now: a :sweep sent to the application's throttle process deletes the first row and keeps the second
```

## 7. The model {#auth-throttle-model}

`Macaw.Auth.Specs.Throttle` (`specs/throttle_spec.ex`, compiled in dev and test only) is an [extla](https://github.com/dcoai/extla) model of the throttle: the table as a state machine shared by every sign-in in flight. extla checks it over every interleaving, and a test drives the real table through the model's behaviors.

**State.** `table`, the rows of `macaw_auth_throttle`, `{key, failures, last}`; `now`; `proc`, each sign-in in flight (idle, admitted at `ts` and verifying, or part-way through recording its failure); and `truth`, a ghost: the failures counted on each key since its last reset, and the latest of their times. Two history variables record a broken rule: `early_admit` and `address_lowered`. A user `u` stands for a user key, an account's or a name's alike: the throttle counts both the same way (§1), and which one a username resolves to is `user_key/1`'s, tested in §1.

**Actions.** `attempt(p, u, a)`: `check/3` at `now` admits a sign-in (`a` = `:none` is a caller with no address). `succeed(p)`: `success/1`. `fail(p)`: `failure/3` with the admission's time, which may be older than another sign-in's failure. `tick(d)`, `sweep`, and `restart`: the node restarts (a crash, a deploy), every sign-in in flight dies uncounted, and the table, in the database, stays. A restart is no reset: `truth` keeps every failure counted, so every invariant holds across one only if the table does too.

**Invariants**, over 8 988 reachable states (a restart reaches no state the others don't: with the table kept, it changes nothing the rules can see):
- `no_early_admit`: an attempt is admitted only once each of its keys' waits has passed since its last failure (by `truth`);
- `failures_each_count`: a key no failure is part-way through counts every failure since its last reset;
- `last_is_latest`: such a key holds the latest of its failures' times;
- `success_keeps_address`: a success never lowers an address's count, whoever's failures built it;
- `wait_capped`: no key waits longer than the cap.

**What is abstracted.** A failure upserts its two keys in one statement, which the database applies row by row; the model updates them in one step: every operation reads and writes one key alone, so the order across keys changes nothing a key's own history shows. Within a key, the steps are the code's. A check and the failure after it are separate steps, so concurrent sign-ins can all be admitted before any failure is counted. A restart falls between statements, never inside one, and not between a defect's two steps (the design has none, and the defects are found without it).

**Constants.** The code's (five free failures, 1 000 ms, a 15-minute cap, a day's memory) when the model is run against the code; a scaled instance when it is checked exhaustively (one free failure, waits of 1 and 2, a sweep after 3, a clock to 4, at most three failures a key, two usernames, one address, two sign-ins in flight). The rules are the same; the scaled waits keep the state space small. Four constants select a defect instead of the design, and the checker finds each:
- `atomic_stamp: false`, the throttle as it shipped (count, then write the time): `no_early_admit` and `last_is_latest` fail, and `failures_each_count` when a sweep falls between the two calls;
- `atomic_increment: false`, a lookup then an insert: `failures_each_count` fails;
- `success_resets_address: true`: `success_keeps_address` and `no_early_admit` fail;
- `persistent: false`, the table in memory as it was before macaw_auth#4 (a restart empties it): `no_early_admit` and `failures_each_count` fail after a restart.

**Running it.** `mix auth.verify` runs `mix extla.check` on every model (here, the one), and is the CI `models` job. It warns that `stamp` and `write` are never enabled: they are the defects' second steps. `mix test` runs the defects' checks (`test/macaw/auth/specs/throttle_spec_test.exs`) and the conformance check (`throttle_conformance_test.exs`).

**Conformance.** Behaviors are drawn from the model at the code's constants, weighted toward failures so that a walk reaches the cap. Each step is applied to the real table, the test repo's, in the test's sandbox (a `restart` stops the application's throttle process and starts it again), and after every step the table must hold the model's rows, and `check/3` must give the model's wait for every username and address. It found the shipped throttle's out-of-order time at once, and finds a `success/1` that also forgets addresses, and a table that a restart empties.

```test:throttle-model
mix auth.verify: Macaw.Auth.Specs.Throttle verifies, every invariant over every interleaving; with no address too
```

```test:throttle-model-defects
each defect's constant set: the checker finds a counterexample to the invariant it breaks (atomic_stamp: false, no_early_admit and last_is_latest; atomic_increment: false, failures_each_count; success_resets_address: true, success_keeps_address and no_early_admit; persistent: false, no_early_admit and failures_each_count, each after a restart)
```

```test:throttle-model-conformance
behaviors drawn from the model at the code's constants, two sign-ins in flight, restarts among them: after every step the real table holds the model's rows, and check/3 gives the model's wait for every username and address; the shipped two-step failure, a success that forgets addresses, or a table a restart empties, fails it
```
