# 10 — Native: the throttle {#auth-throttle}

`Macaw.Auth.Native.Throttle` slows guessing: sign-in failures, and second-factor code failures, back off per username and per client address. It is ported from exio's and macaw's `Accounts.Throttle`, which are the same mechanism; four of the eight adopters had no login throttling at all (macaw_compose#32).

**Not a request rate limit.** `Macaw.Plug.RateLimit` limits requests per window; this is a different policy (backoff after failures, reset by success), so it is its own small table rather than a configuration of that one (macaw_compose#34, decided at evaluation).

**Its values are constants:** five free failures, `2^(n-5)` seconds, a 15-minute cap, a day's memory. They are mechanism, not a host's policy, so nothing configures them (macaw_compose#32, policy surface).

## 1. Keys {#auth-throttle-keys}

Failures are counted per key:
- **the username,** `{:user, name}`: the username normalized as the users table stores it ([06 §5](06-native-sources.md#auth-user-record)), so `Alice`, `alice ` and `ALICE` share a count; anything that can't be a username shares the one key `{:user, :invalid}` (it can never sign in, so nobody is slowed by sharing it). It slows guessing one account from many addresses;
- **the address,** `{:ip, address}`: the `:remote_ip` the caller passed, as a string ([02 §5](02-plugs.md#auth-plug-authenticate)). It slows one address trying many accounts;
- **no address, no address key:** a caller that passes no `:remote_ip` (a console task) is throttled by username alone, rather than sharing one "unknown address" key with every other such caller;
- **the second factor's own username key,** `{:user, {:second_factor, username}}` (§4).

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

`Macaw.Auth.Native.Throttle.success/1` (`user`) forgets the username key's count: **a success resets the username only, never the address.** Resetting the address too would let a guesser who holds one valid account clear their address's count between guesses at others (as exio).

```test:throttle-success-resets-user
five failures at kim, then her success from another address after the wait: four more failures leave her free to sign in at once (five free failures again)
```

```test:throttle-success-keeps-address
five failures from 192.0.2.9 at other names: lee is throttled from it at 0; signs in at 1 000; one more failure from it then throttles lee again at 1 001
```

## 4. The second factor's key {#auth-throttle-second-factor}

Code attempts (`Macaw.Auth.Native.verify_second_factor/3`, `enroll_confirm/3`, `disable/3`, [11](11-native-totp.md)) go through the same throttle: refused unchecked (`{:error, :throttled}`) while a key waits; **a wrong code is a failure,** with the same backoff as a wrong password, so six digits can't be guessed; an accepted code resets the user's key. Other refusals (an enrollment not started, a policy that requires one) are not counted.

- **The username key is the second factor's own,** `{:second_factor, username}`. On the sign-in key, every correct password would reset the count and grant a guesser who has the password five more free guesses at the code.
- **The address key is the one sign-in uses,** so code failures from an address slow sign-ins from it, and the reverse.

A blocked code attempt spends no hash's time: a code check is cheap, and the refusal costs about as much.

```test:throttle-code-backoff
five wrong codes for one session from 192.0.2.7: the right code is throttled; a password sign-in doesn't clear that; one second later the right code is accepted
```

```test:throttle-code-address
wrong codes from 192.0.2.8 for five different users: a sixth user's right code from that address is throttled
```

```test:throttle-code-enroll
five wrong confirmation codes: enroll_confirm with the right code is {:error, :throttled}
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

The counts live in a named, public ETS table, `Macaw.Auth.Native.Throttle`, owned by the throttle's process, which the `macaw_auth` application starts ([00 §3](00-overview.md#auth-dependencies)). A row is `{key, failures, last_failure_ms}`. **A failure updates it in one atomic step:** one `:ets.update_counter/4` call adds one to the count and sets the time to the later of the row's and the failure's own (operations on the time: minus one, raised to `now - 1` if below it, plus one). So concurrent failures each count, and the row holds the latest failure's time whichever is recorded last. A sign-in takes `now` before it hashes, so a failure with an earlier `now` can be recorded second.

The throttle first counted, then wrote the failure's own `now` in a second call, `:ets.update_element/3`. The model (§7) found two ways that shortened a wait: a failure recorded second overwrote a later time with its earlier one, and a check between the two calls read the new count from the old time. Both are fixed by the one update (macaw_compose#67).

```test:throttle-failure-order
five failures at 0, then one at 2 000 and one at 1 000, recorded in that order: both rows hold 7 failures at 2 000; check gives {:delay, 1} at 5 999 and :ok at 6 000
```

```test:throttle-failure-concurrent
400 failures at shuffled times 1-400 from concurrent tasks: each row holds 400 failures at 400
```

**Idle keys are swept.** `Macaw.Auth.Native.Throttle.sweep/1` (`now`) forgets every key whose last failure is more than a day old, and returns how many it forgot. The owner runs it every `:sweep_every_ms` (default ten minutes) on its `:clock` (default the system clock), both options of `Macaw.Auth.Native.Throttle.start_link/1`. So the table holds recent failures only, whatever an attacker sends. A day is longer than the cap, so a swept key had no wait left.

`Macaw.Auth.Native.Throttle.reset/0` forgets everything (tests, and an operator's reset).

```test:throttle-sweep
uma's five failures at 0 and vic's one at a day: sweep at a day forgets nothing; a millisecond later it forgets uma's two keys and keeps vic's, and uma is :ok again
```

```test:throttle-sweep-owner
a failure two days old and one now: a :sweep sent to the owner forgets the first and keeps the second
```

## 7. The model {#auth-throttle-model}

`Macaw.Auth.Specs.Throttle` (`specs/throttle_spec.ex`, compiled in dev and test only) is an [extla](https://github.com/dcoai/extla) model of the throttle: the table as a state machine shared by every sign-in in flight. extla checks it over every interleaving, and a test drives the real table through the model's behaviors.

**State.** `table`, the rows, `{key, failures, last}`; `now`; `proc`, each sign-in in flight (idle, admitted at `ts` and verifying, or part-way through recording its failure); and `truth`, a ghost: the failures counted on each key since its last reset, and the latest of their times. Two history variables record a broken rule: `early_admit` and `address_lowered`.

**Actions.** `attempt(p, u, a)`: `check/3` at `now` admits a sign-in (`a` = `:none` is a caller with no address). `succeed(p)`: `success/1`. `fail(p)`: `failure/3` with the admission's time, which may be older than another sign-in's failure. `tick(d)`, and `sweep`.

**Invariants**, over 8 988 reachable states:
- `no_early_admit`: an attempt is admitted only once each of its keys' waits has passed since its last failure (by `truth`);
- `failures_each_count`: a key no failure is part-way through counts every failure since its last reset;
- `last_is_latest`: such a key holds the latest of its failures' times;
- `success_keeps_address`: a success never lowers an address's count, whoever's failures built it;
- `wait_capped`: no key waits longer than the cap.

**What is abstracted.** A failure updates its two keys in one step: every operation reads and writes one key alone, so the order across keys changes nothing a key's own history shows. Within a key, the steps are the code's. A check and the failure after it are separate steps, so concurrent sign-ins can all be admitted before any failure is counted.

**Constants.** The code's (five free failures, 1 000 ms, a 15-minute cap, a day's memory) when the model is run against the code; a scaled instance when it is checked exhaustively (one free failure, waits of 1 and 2, a sweep after 3, a clock to 4, at most three failures a key, two usernames, one address, two sign-ins in flight). The rules are the same; the scaled waits keep the state space small. Three constants select a defect instead of the design, and the checker finds each:
- `atomic_stamp: false`, the throttle as it shipped (count, then write the time): `no_early_admit` and `last_is_latest` fail, and `failures_each_count` when a sweep falls between the two calls;
- `atomic_increment: false`, a lookup then an insert: `failures_each_count` fails;
- `success_resets_address: true`: `success_keeps_address` and `no_early_admit` fail.

**Running it.** `mix auth.verify` runs `mix extla.check` on every model (here, the one), and is the CI `models` job. It warns that `stamp` and `write` are never enabled: they are the defects' second steps. `mix test` runs the defects' checks (`test/macaw/auth/specs/throttle_spec_test.exs`) and the conformance check (`throttle_conformance_test.exs`).

**Conformance.** Behaviors are drawn from the model at the code's constants, weighted toward failures so that a walk reaches the cap. Each step is applied to the real table, and after every step the table must hold the model's rows, and `check/3` must give the model's wait for every username and address. It found the shipped throttle's out-of-order time at once, and finds a `success/1` that also forgets addresses.

```test:throttle-model
mix auth.verify: Macaw.Auth.Specs.Throttle verifies, every invariant over every interleaving; with no address too
```

```test:throttle-model-defects
each defect's constant set: the checker finds a counterexample to the invariant it breaks (atomic_stamp: false, no_early_admit and last_is_latest; atomic_increment: false, failures_each_count; success_resets_address: true, success_keeps_address and no_early_admit)
```

```test:throttle-model-conformance
behaviors drawn from the model at the code's constants, two sign-ins in flight: after every step the real table holds the model's rows, and check/3 gives the model's wait for every username and address; the shipped two-step failure, or a success that forgets addresses, fails it
```
