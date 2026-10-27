# 08 — Native: hashers {#auth-hasher}

How `Macaw.Auth.Native` hashes passwords: a behavior with two implementations, bcrypt (six of the adopters) and argon2 (exio and macaw). The proposal had to pick one or make it pluggable with a migration path; it is pluggable, and a host moves between them without a flag day (macaw_compose#32).

## 1. The behavior {#auth-hasher-behavior}

`Macaw.Auth.Native.Hasher` is what a hasher implements:
- `hash(password)`: a new hash, with the parameters configured now;
- `verify(password, hash)`: whether they match, in constant time;
- `no_user_verify()`: spends a verification's time and returns false, so refusing an unknown user takes as long as refusing a wrong password;
- `needs_rehash?(hash)`: whether one of this algorithm's hashes was made with other parameters than now;
- `owns?(hash)`: whether a hash is this algorithm's, by its prefix.

**Each library is an optional dependency, and each implementation is compiled only when its library is,** so a host carries only the NIF it chose.

`Macaw.Auth.Native.Hasher.check/1` is how the configuration checks its `hasher` ([05 §2](05-native-config.md#auth-native-config)), so a missing library is refused when the configuration is read (at boot), never at the first sign-in:
- **`:ok`** for a loaded module that exports `hash/1`;
- **`Bcrypt` or `Argon2` without its library:** `"hasher: Macaw.Auth.Native.Hasher.Bcrypt needs its library; add {:bcrypt_elixir, \"~> 3.2\"} to the host's deps"` (argon2: `{:argon2_elixir, "~> 4.1"}`);
- **any other module:** `"hasher: <module> is not a Macaw.Auth.Native.Hasher"`; **a non-module:** `"hasher: must be a module, got <value>"`.

The check looks for `hash/1`, not the whole behavior ([00 §6](00-overview.md#auth-gaps)).

```test:hasher-check
check(Bcrypt) is :ok; check(String) is {:error, "hasher: String is not a Macaw.Auth.Native.Hasher"}; check("bcrypt") is {:error, "hasher: must be a module" <> _}
```

## 2. The two algorithms {#auth-hasher-algorithms}

- **`Macaw.Auth.Native.Hasher.Bcrypt`** (`bcrypt_elixir`): it owns hashes beginning `$2a$`, `$2b$` or `$2y$`. Its cost is bcrypt_elixir's own setting, `config :bcrypt_elixir, log_rounds:` (default 12); a hash at another cost (the two digits after the second `$`), or one it can't read, needs a rehash.
- **`Macaw.Auth.Native.Hasher.Argon2`** (`argon2_elixir`): it owns hashes beginning `$argon2`. Its parameters are argon2_elixir's own settings (`argon2_type` default 2, argon2id; `m_cost` 16, so `m=65536`; `t_cost` 3; `parallelism` 4); a hash whose type or `m=…,t=…,p=…` differ, or one it can't read, needs a rehash.

```test:hasher-own
for each algorithm: a hash of "secret" is owned, verifies "secret", not "other", needs no rehash, and no_user_verify/0 is false; neither owns the other's hash
```

```test:hasher-params
a bcrypt hash made at log_rounds 4 needs a rehash at 5; an argon2 hash made at t_cost 1 needs a rehash at t_cost 2
```

## 3. Rehashing at sign-in {#auth-hasher-rehash}

`Macaw.Auth.Native.Hasher.verify/3` (`configured`, `password`, `hash`) **verifies with whichever available algorithm made the hash:** the configured one first, then any other whose library is loaded. A hash no available algorithm owns, or none at all, spends the configured hasher's no-user time and is false.

`Macaw.Auth.Native.Hasher.needs_rehash?/2` (`configured`, `hash`) is true when **the configured algorithm doesn't own the hash, or does and its parameters changed.**

**A stored hash is replaced at a successful sign-in** when it needs a rehash ([06 §3](06-native-sources.md#auth-source-password)), with the configured hasher. So:
- **a raised cost** reaches each user at their next sign-in;
- **moving from bcrypt to argon2 needs no flag day:** a bcrypt hash still verifies with bcrypt (while `bcrypt_elixir` is still loaded) and is rehashed with argon2 at that user's next sign-in.

A wrong password changes nothing.

```test:hasher-cross
with Argon2 configured: a bcrypt hash of "secret" verifies "secret" and not "wrong", and needs a rehash; with Bcrypt configured it doesn't; "not a hash" and nil verify false
```

```test:hasher-rehash-cost
a user hashed at cost 4 signs in after log_rounds becomes 5: the stored hash is now "$2b$05$…" and verifies the password; a wrong password at cost 5 leaves the old hash
```

```test:hasher-rehash-algorithm
a bcrypt user signs in with Argon2 configured: their stored hash becomes argon2, and the next sign-in leaves it unchanged
```
