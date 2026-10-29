# 07 — Native: LDAP {#auth-ldap}

`Macaw.Auth.Native.Source.Ldap` is a directory as a sign-in source ([06 §1](06-native-sources.md#auth-source-behavior)), over OTP's `:eldap`, with no external LDAP library: every adopter wrapped `:eldap` directly, and no LDAP library is maintained (macaw_compose#32). It is ported from exio's copy, the one with the security fixes, plus macaw's `allow_plaintext: false`, with three further fixes: usernames go into search filters as data (§5.3), DN escaping decides its trailing space by position (§5.1), and values reach `:eldap` as UTF-8 bytes (§3).

```elixir
%{type: :ldap, name: "nas", host: "nas.example.test", port: 389,
  ssl: false, starttls: true, cacertfile: "/etc/ssl/nas-ca.pem",
  user_dn_template: "uid={username},cn=users,dc=example,dc=test",
  groups: %{base_dn: "cn=groups,dc=example,dc=test", member_attr: "memberUid"},
  required_group: "macaw", role_mapping: %{"macaw-admin" => "admin"},
  default_role: "viewer"}
```

The `:ldap` tests run against macaw's OpenLDAP fixture directory (users under `cn=users`, posixGroup groups under `cn=groups`, alice also in the groupOfNames `staff`, two entries for dave), StartTLS on 389 and LDAPS on 636, with its CA in `test/fixtures/ldap/`.

## 1. Configuration {#auth-ldap-config}

A source's configuration is `Macaw.Auth.Native.Source.Ldap.Config`'s: `Macaw.Auth.Native.Source.Ldap.Config.parse/2` (which `Macaw.Auth.Native.Source.Ldap.parse/2` is) validates a source's map and fills its defaults, refusing a bad one by the source's name and the key ([06 §1.1](06-native-sources.md#auth-source-settings)). The known keys are exactly those below, plus `type` and `name` (required).

**Connection:**

| Key | Default | Checked |
|---|---|---|
| `host` | required | a non-empty string |
| `port` | 636 | an integer in 1..65535 |
| `ssl` | true | a boolean |
| `starttls` | false | a boolean |
| `allow_plaintext` | false | a boolean |
| `verify_peer` | true | a boolean |
| `cacertfile` | nil: the system's CAs | a path to a regular file (`"sources[nas].cacertfile: <path> is not a readable file"`) |
| `timeout_ms` | 5000 | an integer in 1..600000 |

```test:ldap-config-defaults
an LDAP source with only name, host, port 389, starttls and a template parses with allow_plaintext false, verify_peer true, timeout_ms 5000, id_attr "entryUUID", username_attr "uid", role_mapping [] and default_role nil
```

### 1.1 Transport {#auth-ldap-transport}

- **`ssl` and `starttls` together** are refused: `"sources[nas].starttls: can't be used with ssl: true"`.
- **Neither, without `allow_plaintext: true`,** is refused, because the bind would send passwords in the clear: `"sources[nas].ssl: is false: set starttls: true, or allow_plaintext: true to send passwords unencrypted"`. Setting it true is an explicit, visible decision (macaw's guard, which no other copy had).
- **The guard holds again at connect:** a source struct made without this check, with neither `ssl` nor `starttls` and `allow_plaintext` false, never connects (`:plaintext_refused`, §2).

```test:ldap-plaintext
starttls: false without allow_plaintext is refused naming sources[nas].ssl; with allow_plaintext: true it parses and signs bob in over plain LDAP; a struct with starttls flipped off after parsing is refused :plaintext_refused, which it doesn't know
```

### 1.2 Finding the user {#auth-ldap-finding}

**Exactly one of two ways:**
- **`user_dn_template`**, a direct bind: a DN containing `{username}` (`uid={username},cn=users,dc=example,dc=test`). Without the placeholder: `"…user_dn_template: must contain {username}"`;
- **`search: %{base_dn, filter, bind_dn, bind_password}`**, a search for the user's entry: `base_dn` required; `filter` an LDAP filter containing `{username}` (§5.3), default `(uid={username})`; `bind_dn` and `bind_password` (a secret, [06 §1.1](06-native-sources.md#auth-source-settings)) **set together**, the service account the search binds as. With neither, the search is anonymous, and allowed **only with `allow_anonymous_search: true`** (a top-level key); otherwise `"…search.bind_dn: and bind_password are required (or allow_anonymous_search: true)"`. One without the other: `"…search.bind_dn: and bind_password must be set together"`.

Neither way: `"…user_dn_template: or search is required"`; both: `"…search: can't be set with user_dn_template: choose one"`.

```test:ldap-config-finding
neither template nor search, both, a template without {username}, a filter "(uid=x" and a search with only base_dn are each refused by name; base_dn alone with allow_anonymous_search: true parses with bind_dn nil
```

### 1.3 Attributes {#auth-ldap-attributes}

`id_attr` (`entryUUID`; the entry's DN is used when it is absent), `username_attr` (`uid`), `email_attr` (`mail`), `display_name_attr` (`cn`): each a non-empty string, or `"…<key>: must be an attribute name"`.

### 1.4 Groups {#auth-ldap-groups-config}

`groups` is absent (no groups), or one of:
- **`%{from: :member_of}`** (or `"member_of"`): the entry's own `memberOf` values;
- **`%{base_dn, member_attr}`**, a search under `base_dn` for groups naming the user in `member_attr`: `member` (groupOfNames, the default), `uniqueMember`, or `memberUid` (posixGroup, which names the user by username). Another is `"…groups.member_attr: must be member, uniqueMember or memberUid"`.

Anything else: `"…groups: must be %{from: :member_of} or %{base_dn: …, member_attr: …}"`.

**A groups service account** (`groups: %{base_dn, member_attr, bind_dn, bind_password}`), for a directory that lets a user read only their own entry: `bind_dn` and `bind_password` (a secret, [06 §1.1](06-native-sources.md#auth-source-settings)) are the account a **direct-bind** source binds as, after the user's own bind succeeded, to search for the groups (§4). Without them the user's own bind reads the groups, as it always did; the group search's map then has `bind_dn: nil`. They are refused:
- **with `from: :member_of`:** `"…groups.bind_dn: and bind_password can't be used with from: :member_of (memberOf is read from the user's own entry)"`;
- **in search mode:** `"…groups.bind_dn: is for a direct bind (user_dn_template): search mode reads the groups as search.bind_dn"`, a source having one service account;
- **one without the other** (or an empty `bind_dn`): `"…groups.bind_dn: and bind_password must be set together"`; a reference that can't be read names `groups.bind_password` (`"…groups.bind_password: the environment variable GROUPS_PW is not set"`).

The source keeps one service password, its `bind_password`: the search's, or the groups'.

```test:ldap-group-account-config
groups %{base_dn: "cn=g", bind_dn: "cn=svc", bind_password: "hunter2-groups"} on a direct-bind source parses to groups %{from: :search, base_dn: "cn=g", member_attr: "member", bind_dn: "cn=svc"} and bind_password "hunter2-groups", inspecting without "hunter2", string keys alike; without them bind_dn is nil; {:env, "GROUPS_PW"} resolves from :env and unset names groups.bind_password; with from: :member_of either key is refused, in search mode the pair is refused, one without the other is refused; no fault holds the password
```

### 1.5 Access {#auth-ldap-access}

- **`required_group`**, a group's CN or DN, which a user must be in to sign in at all;
- **`role_mapping`**, a map of group (CN or DN) to a role or a list of roles; it is kept as a list of `{group, [role]}`;
- **`default_role`**, a role or a list, for a user no mapping matched; kept as a list.

**Roles are strings:** an atom role is written as its name, never the reverse. A mapping value that isn't a role or a non-empty list of them is `"…role_mapping: must map group names to a role or a list of roles"`; an empty `default_role` is `"…default_role: must be a role or a list of roles"`.

```test:ldap-config-strings
a source with string keys and type "ldap", a search with a literal bind password, groups with member_attr "memberUid", role_mapping %{"admins" => ["admin", "operator"], "staff" => "viewer"} and default_role "guest" parses to search %{base_dn, filter: "(uid={username})", bind_dn}, groups %{from: :search, …}, mapping [{"admins", ["admin", "operator"]}, {"staff", ["viewer"]}] and default_role ["guest"]
```

### 1.6 The service password stays hidden {#auth-ldap-secret}

`bind_password`, the search's or the groups' (§1.4), is resolved when the configuration is read; **no error message contains it, no log line, answer or diagnostic step holds it, and the source's inspection leaves it out.**

```test:ldap-secret-hidden
a search source with bind_password "hunter2-secret" inspects without "hunter2"
```

## 2. Connecting {#auth-ldap-connect}

- **LDAPS** (`ssl: true`): `:eldap.open` with TLS. `:eldap` reports every LDAPS failure as a failed connect, so a plain TCP connect to the same port tells them apart: reachable is **`:tls_failed`**, unreachable **`:connect_failed`**.
- **StartTLS** (`starttls: true`): a plain connect (failing, `:connect_failed`), then `:eldap.start_tls/3` (failing, the connection closed and **`:tls_failed`**).
- **Plain LDAP** only with `allow_plaintext: true`; otherwise **`:plaintext_refused`**, before any connection.

**TLS verifies the certificate chain and the hostname** (`verify: :verify_peer`, the HTTPS hostname match, SNI with the configured host, `depth: 3`), against `cacertfile` or, without one, the system's CAs (`:public_key.cacerts_get/0`). **`verify_peer: false`** turns that off (`verify: :verify_none`), and `diagnose/3` says so (§7).

A directory that can't be reached, whose TLS fails, or that refuses a search is **logged as a warning naming the source**, `"LDAP source nas: <explanation> (<host>:<port>)"`. Passwords are never logged.

```test:ldap-tls
LDAPS with the test CA signs bob in; LDAPS by IP address (the certificate names "ldap" and "localhost") is :tls_failed; StartTLS without the CA is :tls_failed; port 1 is :connect_failed; without the CA but verify_peer: false, bob signs in
```

## 3. The sign-in flow {#auth-ldap-flow}

`Macaw.Auth.Native.Source.Ldap.authenticate/4` (`source`, `username`, `password`, `opts`), each failure its own reason (§6), for the log and the check task, never for the visitor:
1. **An empty password (or nil) is refused before connecting,** `:empty_password`: LDAP treats it as an anonymous bind, which "succeeds".
2. **Connect** (§2). The username is trimmed.
3. **Find the user's DN.** An empty username is `:user_not_found`. With a template, the username **RFC 4514-escaped** (§5.1) in place of `{username}`. With a search: the service bind (when `bind_dn` is set; refused, `:search_failed`), then a subtree search under `base_dn` with the filter built with the username as data (§5.3): no entry is `:user_not_found`, two or more `:ambiguous_user`, a refused search `:search_failed` (a base that doesn't exist is no entry).
4. **Bind as that DN with the password;** refused, `:invalid_credentials`.
5. **Read the entry:** a base-object search of the DN for the id, username, email and display-name attributes and `memberOf`. Not exactly one entry is `:user_not_found`; a refused search `:search_failed`.
6. **The username** is the entry's first `username_attr` value, normalized as the users table requires ([06 §5](06-native-sources.md#auth-user-record)); not a valid one, `:invalid_username`. So the row's username is the directory's spelling, not what was typed.
7. **The groups** (§4; refused, `:group_search_failed`, as is a refused bind as the groups' service account), then **`required_group`** (`:not_in_group`), then **the roles** (`:no_role`).

The connection is closed after, whatever the outcome. **Every value sent to `:eldap`** (DN, password, filter value) **goes as its UTF-8 bytes,** so a non-ASCII password binds as the directory stored it (the old charlist conversion broke them).

An accepted user is `{:ok, attrs}` for the chain to provision ([06 §4](06-native-sources.md#auth-provision)): `username`, `display_name` (the first `display_name_attr` value), `roles`, and `extra`:
- `"dn"`: the user's DN;
- `"external_id"`: the first `id_attr` value, as it is when printable, else as lower-case hex; the DN when the entry has none;
- `"email"`: the first `email_attr` value;
- `"groups"`: the DNs of the user's groups.

```test:ldap-direct-bind
on the fixture directory over StartTLS: alice signs in with roles ["admin"], display name "Alice Admin", email, DN and a 36-character external id; bob with ["viewer"]; carol is :not_in_group; a wrong password and an unknown user are :invalid_credentials; "" is :empty_password; "Bad User" is :invalid_username; without default_role, bob is :no_role
```

```test:ldap-search
search mode: alice signs in with ["admin"]; a wrong password is :invalid_credentials; dave (two entries) is :ambiguous_user; an anonymous search under cn=users signs bob in; a wrong service password is :search_failed
```

```test:ldap-injection
"alice,cn=users" and "alice;x" in direct-bind mode are :invalid_credentials; "*", "a*)(uid=*" and "alice)(|(uid=*" in search mode are :user_not_found
```

## 4. Groups and roles {#auth-ldap-groups}

The user's groups, each a DN and a CN:
- **`from: :member_of`:** the entry's `memberOf` values, each group's CN read from the DN's leading `cn=` (escaped characters kept);
- **a search:** for `memberUid`, the entry's `username_attr` value **as the directory spells it**; for `member` and `uniqueMember`, the user's DN. The filter is an equality match with that value **as data**, a subtree search under the groups' `base_dn` for each group's `cn`. **In search mode, the service account binds again** first, to read the groups. **In direct-bind mode, the groups' service account** (§1.4), when there is one, **binds** after the user's bind succeeded (refused, `:group_search_failed`, logged naming the source and never the password), and the group search runs as it; without one, the user's own bind reads them. A wrong user password never reaches the service bind.

**A group matches a name** (`Macaw.Auth.Native.Source.Ldap.member?/2`) when the name equals the group's DN or its CN, **ignoring case**.
- **`required_group`,** when set, must match one of the user's groups, or the user is refused (`:not_in_group`).
- **The roles are every role every matching `role_mapping` group maps to,** each once. With none, the `default_role`; with no default either, the user is refused (`:no_role`).

```test:ldap-group-account
against a directory that lets only cn=svc read the groups: a direct-bind source with groups bind_dn cn=svc signs alice in with ["admin"] and both her groups, binding as alice, then as cn=svc with its password, the group search run as cn=svc; a wrong user password is :invalid_credentials with no service bind
```

```test:ldap-group-account-absent
the same directory, without a groups account: the group search runs as alice and finds nothing, so alice is :not_in_group, with no service bind; where any bind may read the groups, alice signs in with ["admin"], the groups read as alice
```

```test:ldap-group-account-secret
a wrong groups bind_password is :group_search_failed, with no group search made, and the log line names the source and its explanation; neither password is in the log, the answer of a sign-in that succeeded, the source's inspection, or the diagnostic steps
```

```test:ldap-group-account-fixture
on the fixture directory, a direct-bind source whose groups bind as cn=svc with svc-test-password signs alice in with ["admin"] and bob with ["viewer"]; a wrong user password is :invalid_credentials; a wrong service password is :group_search_failed, logged without it
```

```test:ldap-roles
alice in macaw and macaw-admin, with mapping %{"macaw-admin" => ["admin", "operator"], "macaw" => "viewer"}, gets exactly admin, operator and viewer
```

```test:ldap-member-of
with groups from: :member_of, required_group "staff" and mapping %{"staff" => "admin"}: alice (in the groupOfNames staff) gets ["admin"]; bob is :not_in_group
```

```test:ldap-member-match
member?([%{dn: "cn=Admins,dc=x", cn: "Admins"}], "admins") and member?(…, "CN=ADMINS,DC=X") are true; member?(…, "staff") is false
```

## 5. Escaping {#auth-ldap-escape}

`Macaw.Auth.Native.Source.Ldap.Escape` escapes values placed in DNs and filters, so a username can never change a DN or widen a search. Ported from exio's, with two fixes. The search filter itself never has a username spliced into its text (§5.3); `filter_value/1` is for showing a filter as text (`diagnose/3`) and for hosts that write their own.

### 5.1 DN values (RFC 4514) {#auth-ldap-escape-dn}

`Macaw.Auth.Native.Source.Ldap.Escape.dn_value/1` escapes an attribute value for a DN, byte by byte:
- **`, + " \ < > ; =`** are escaped with a backslash **wherever they are**;
- **`#` at the start** and **a space at the start or at the end** are escaped with a backslash; elsewhere they stay;
- **NUL** is `\00`;
- every other byte is kept.

**The `;` regression.** The eesidai-lineage copies (apu, eesidai, mdview) wrote `"\;"`, which in Elixir is just `";"`, so a `;` went unescaped. Here every special is a character literal, and a property proves no special survives unescaped.

**The trailing-space fix.** exio decided the trailing space on the *escaped* text, so a value ending in a backslash and a space (`a\ `) kept its space bare. Here it is decided **by position in the original value.**

| Value | Escaped |
|---|---|
| `a;b` | `a\;b` |
| `,` `+` `"` `\` `<` `>` `=` | `\,` `\+` `\"` `\\` `\<` `\>` `\=` |
| NUL | `\00` |
| `#a` | `\#a` |
| `a#` | `a#` |
| ` a` | `\ a` |
| `a ` | `a\ ` |
| `a b` | `a b` |
| ` ` | `\ ` |
| `alice,cn=users` | `alice\,cn\=users` |
| `a\ ` | `a\\\ ` |

`Macaw.Auth.Native.Source.Ldap.Escape.dn_unescape/1` inverts it: `\hh` (two hex digits) is that byte, `\c` is `c`; `{:ok, value}`, or `:error` for a dangling backslash.

```test:escape-dn-table
each row of the table, dn_value/1 of the left gives the right
```

```test:escape-dn-property
property: for any bytes, and strings dense in , + " \ < > ; = # * space ( ) and NUL, dn_unescape(dn_value(v)) is {:ok, v} and no special, leading # or space, or trailing space appears unescaped
```

```test:escape-dn-dangling
dn_unescape("a\\") is :error
```

### 5.2 Filter values (RFC 4515) {#auth-ldap-escape-filter}

`Macaw.Auth.Native.Source.Ldap.Escape.filter_value/1` escapes an assertion value for a filter's text: **`*` `(` `)` `\` and NUL become `\2a` `\28` `\29` `\5c` `\00`;** every other byte is kept (`;,+` stay). `Macaw.Auth.Native.Source.Ldap.Escape.filter_unescape/1` inverts it: `\hh` is that byte; a backslash not followed by two hex digits is `:error`.

```test:escape-filter
filter_value("a*)(uid=*") is "a\\2a\\29\\28uid=\\2a"; each of * ( ) \ NUL alone gives its pair; ";,+" is unchanged
```

```test:escape-filter-property
property: filter_unescape(filter_value(v)) is {:ok, v}, and no * ( ) \ or NUL survives unescaped; "(uid=" <> filter_value(v) <> ")" builds the same filter as the template "(uid={username})" with v
```

### 5.3 Filters as data {#auth-ldap-filter}

`:eldap` takes a filter as a term, not a string, so a configured `search.filter` is parsed by `Macaw.Auth.Native.Source.Ldap.Filter`. exio and macaw escaped the username into the filter's *text* and then parsed the result, so the escaping was all that stood between a username and the filter's structure. **Here the template is parsed with `{username}` as a placeholder, and the username's bytes go straight into the assertion value of the term:** a `*`, `(` or `\` in a username is a byte of the value, never syntax, whatever the escaping would have done.

`Macaw.Auth.Native.Source.Ldap.Filter.build/2` (`template`, `username`) gives `{:ok, eldap_filter}` or `:error`:
- **supported:** `&`, `|`, `!`, equality, presence (`attr=*`), substrings, `>=`, `<=` and `~=`; **extensible matches are not;**
- **`\hh` escapes in the template decode to their bytes,** so an escaped `*` is a literal asterisk, never a wildcard; a backslash not followed by two hex digits is malformed;
- **substrings split on the template's own asterisks,** before the username goes in, so an asterisk in the username is never a wildcard; an empty middle part is malformed;
- the template is trimmed, and must be one filter with nothing after it.

`Macaw.Auth.Native.Source.Ldap.Filter.valid_template?/1` is true for a string that contains `{username}` and builds.

```test:filter-data-property
property: for any username, build("(uid={username})", u) is an equalityMatch on uid whose value is exactly u's bytes
```

```test:filter-literal
"*" in (uid={username}) is the value "*"; "a*)(uid=*" in (&(objectClass=person)(uid={username})) is an and of two equality matches, the second's value "a*)(uid=*"
```

```test:filter-template
(cn=a*{username}) with "*b" is substrings initial "a", final "*b"; (mail=*) is presence; (cn={username}\2a) with "x" is equality "x*"
```

```test:filter-valid-template
valid_template? is true for (uid={username}) and an and/or over uid and mail; false for (uid=alice), uid={username}, (uid={username}, (uid={username}\zz) and nil
```

## 6. Whether it knows the user {#auth-ldap-knows}

`Macaw.Auth.Native.Source.Ldap.knows?/2` decides whether a refusal is final in the chain ([06 §2](06-native-sources.md#auth-chain)):
- **it doesn't know the user** after `:empty_password`, `:user_not_found`, `:plaintext_refused`, `:connect_failed`, `:tls_failed` or `:search_failed`: a directory that wasn't reached or found no such entry passes the attempt on, **so an unreachable directory never locks a local user out;**
- **a direct-bind source's `:invalid_credentials` passes on too:** it can't tell a wrong password from a missing entry, both fail the bind, so "knows" comes from the refusal reason, as in exio;
- **in search mode the entry was found, so a failed bind is final;** and every other reason (`:ambiguous_user`, `:group_search_failed`, `:not_in_group`, `:no_role`, `:invalid_username`) is final.

`Macaw.Auth.Native.Source.Ldap.explain/1` gives each reason a sentence, for logs and diagnostics:

| Reason | Explanation |
|---|---|
| `:empty_password` | an empty password was refused before connecting (LDAP treats it as an anonymous bind) |
| `:invalid_credentials` | the directory refused the password for that DN |
| `:plaintext_refused` | neither ssl nor starttls is set, and allow_plaintext is false: passwords are not sent unencrypted |
| `:connect_failed` | the directory could not be reached |
| `:tls_failed` | TLS failed: the certificate did not verify (chain, cacertfile or hostname), or the server refused TLS |
| `:search_failed` | the search failed: the service bind was refused, or the directory refused the search |
| `:user_not_found` | no entry matched the username |
| `:ambiguous_user` | more than one entry matched the username |
| `:group_search_failed` | the group search failed: the service bind was refused, or the directory refused the search |
| `:not_in_group` | the user is not in the required group |
| `:no_role` | no role_mapping matched the user's groups and there is no default_role |
| `:invalid_username` | the directory's username attribute is not a valid username (1–64 of a-z 0-9 . _ @ + -) |

```test:ldap-chain-unreachable
with [directory on port 1, local], the local root signs in and a directory-only user is :invalid_credentials
```

```test:ldap-chain-search-final
with [search-mode directory, local], the local bob's local password is refused (the directory found bob, and its bind failure is final)
```

```test:ldap-chain-provision
through the chain, alice is provisioned with source "nas", no hash and ["admin"]; "Alice" signs in as the same user; roles edited to ["viewer"] are back to ["admin"] at the next sign-in
```

## 7. Diagnostics {#auth-ldap-check}

`Macaw.Auth.Native.Source.Ldap.diagnose/3` (`source`, `username`, `password`) runs the sign-in flow without signing in and says how each step went: `[{step, :ok | :error, detail}]`, **ending at the first failure.** The steps, in order: `"connect"` (a TCP connect to host and port), `"TLS"` (the transport: `"LDAPS, certificate and hostname verified"`, `"StartTLS, …"`, `"certificate NOT verified (verify_peer: false)"`, or plain LDAP's warning that passwords go unencrypted), `"find the user's DN"` (direct bind's DN, or `"searched <base> for <filter> as <bind_dn>"` / `"anonymously"`, the filter shown with the username filter-escaped), `"bind as the user"`, `"read attributes"`, `"username"`, **`"bind for the groups"`** (only for a direct bind with a groups service account, §1.4: `"bound as <bind_dn>"`, or the explanation of `:group_search_failed`), `"groups"` (read as that account when there is one), `"required group"` and `"roles"`. A failed step's detail is its reason's explanation (§6). **An empty password** is the single step `{"password", :error, …}`. **The password is used for the bind and appears nowhere in the result,** nor does the service account's.

`mix macaw_auth.ldap.check SOURCE USERNAME` (`Mix.Tasks.MacawAuth.Ldap.Check`) prints it, a line a step (`ok     <step>: <detail>`, `FAILED <step>: <detail>`), and exits non-zero when a step failed:
- **the password comes from `MACAW_AUTH_CHECK_PASSWORD`,** never the command line, where `ps` and shell history would show it; unset, the task stops: `"set MACAW_AUTH_CHECK_PASSWORD to the user's password (it is never read from argv)"`;
- `SOURCE` is an LDAP source of the configured `sources`, by name; another name stops the task, naming the configured ones;
- it reads the configuration as the backend does, a fault stopping it with the fault named, and starts `:ssl` and `:eldap` itself;
- other arguments: `"usage: mix macaw_auth.ldap.check SOURCE USERNAME"`.

```test:ldap-diagnose
diagnose(nas, "alice", "alice-password") gives the nine steps all :ok, TLS "StartTLS, certificate and hostname verified", roles "admin", and nothing containing the password; a wrong password ends at "bind as the user"; carol ends at "required group"; search mode's DN step reads "searched … (uid=alice) as cn=svc,…"; without the CA it ends at TLS; on port 1 at connect
```

```test:ldap-group-account-diagnose
diagnose of a direct-bind source with groups bind_dn cn=svc gives ten steps all :ok, "bind for the groups" "bound as cn=svc,…" between "username" and "groups", roles "admin", and neither password in the result; a wrong service password ends at "bind for the groups"; without the account there is no such step
```

```test:ldap-check-task
the task with MACAW_AUTH_CHECK_PASSWORD unset raises naming the variable; with an unknown source name, raises listing the configured LDAP sources; with one argument, raises the usage
```
