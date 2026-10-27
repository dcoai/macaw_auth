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

**The wait runs from the key's last failure.** An attempt inside it is refused, `:throttled`, **without checking the password** ([05 §1.2](05-native-config.md#auth-native-throttled)), and is not counted; an attempt after it is checked as usual, and another failure doubles the next wait.

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

The counts live in a named, public ETS table, `Macaw.Auth.Native.Throttle`, owned by the throttle's process, which the `macaw_auth` application starts ([00 §3](00-overview.md#auth-dependencies)). A row is `{key, failures, last_failure_ms}`. **A failure updates it atomically:** the count by `:ets.update_counter/4`, then the last-failure time, so concurrent failures each count.

**Idle keys are swept.** `Macaw.Auth.Native.Throttle.sweep/1` (`now`) forgets every key whose last failure is more than a day old, and returns how many it forgot. The owner runs it every `:sweep_every_ms` (default ten minutes) on its `:clock` (default the system clock), both options of `Macaw.Auth.Native.Throttle.start_link/1`. So the table holds recent failures only, whatever an attacker sends. A day is longer than the cap, so a swept key had no wait left.

`Macaw.Auth.Native.Throttle.reset/0` forgets everything (tests, and an operator's reset).

```test:throttle-sweep
uma's five failures at 0 and vic's one at a day: sweep at a day forgets nothing; a millisecond later it forgets uma's two keys and keeps vic's, and uma is :ok again
```

```test:throttle-sweep-owner
a failure two days old and one now: a :sweep sent to the owner forgets the first and keeps the second
```
