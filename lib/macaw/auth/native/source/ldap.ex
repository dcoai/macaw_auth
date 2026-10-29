defmodule Macaw.Auth.Native.Source.Ldap do
  @moduledoc """
  A directory as a sign-in source, over OTP's `:eldap` (no external LDAP
  library). Ported from exio's, the copy with the security fixes, plus
  macaw's `allow_plaintext: false`. The configuration is
  `Macaw.Auth.Native.Source.Ldap.Config`'s:

      %{type: :ldap, name: "nas", host: "nas.example.test", port: 389,
        ssl: false, starttls: true, cacertfile: "/etc/ssl/nas-ca.pem",
        user_dn_template: "uid={username},cn=users,dc=example,dc=test",
        groups: %{base_dn: "cn=groups,dc=example,dc=test", member_attr: "memberUid"},
        required_group: "macaw", role_mapping: %{"macaw-admin" => "admin"},
        default_role: "viewer"}

  A directory that lets a user read only their own entry gives the group
  search a service account: `groups: %{base_dn: …, member_attr: …,
  bind_dn: "cn=svc,dc=example,dc=test", bind_password: {:env, "LDAP_PW"}}`.

  The flow, each failure its own reason (`explain/1`), for the log and
  `mix macaw_auth.ldap.check`, never for the visitor:

  1. An empty password is refused before connecting (`:empty_password`):
     LDAP treats it as an anonymous bind, which "succeeds".
  2. Connect: LDAPS, or StartTLS, verifying the certificate chain (`depth:
     3`) and the hostname, with SNI, unless `verify_peer: false`
     (`:connect_failed`, `:tls_failed`). Without either, only with
     `allow_plaintext: true` (`:plaintext_refused`).
  3. Find the user's DN: the template with the username RFC 4514-escaped
     (`Macaw.Auth.Native.Source.Ldap.Escape`), or a search whose filter is
     built with the username as data (`Macaw.Auth.Native.Source.Ldap.Filter`)
     (`:search_failed`, `:user_not_found`, `:ambiguous_user`).
  4. Bind as that DN with the password (`:invalid_credentials`).
  5. Read the attributes, then the groups, binding first as the service
     account when there is one (`:group_search_failed`).
  6. Apply `required_group` (`:not_in_group`) and derive the roles
     (`:no_role`); the directory's username must be a valid one
     (`:invalid_username`).

  Every value sent to `:eldap` (DN, password, filter value) goes as its
  UTF-8 bytes, so a non-ASCII password binds as the directory stored it.
  Passwords (the user's and the service account's) are never logged; a directory that can't be reached or
  searched is logged as a warning, naming the source.

  **Whether it knows the user** (`knows?/2`): a directory that wasn't
  reached, or found no such entry, doesn't, and the chain moves on. A
  direct-bind source can't tell a wrong password from a missing entry (both
  fail the bind), so its `:invalid_credentials` passes on too; in search
  mode the entry was found, so a failed bind is final.
  """

  @behaviour Macaw.Auth.Native.Source

  require Logger

  alias Macaw.Auth.Native.UserRecord
  alias Macaw.Auth.Native.Source.Ldap.{Config, Escape, Filter}

  @derive {Inspect, except: [:bind_password]}
  @enforce_keys [:name, :host]
  defstruct [
    :name,
    :host,
    :cacertfile,
    :user_dn_template,
    :search,
    :bind_password,
    :groups,
    :required_group,
    :default_role,
    port: 636,
    ssl: true,
    starttls: false,
    allow_plaintext: false,
    verify_peer: true,
    timeout_ms: 5000,
    id_attr: "entryUUID",
    username_attr: "uid",
    email_attr: "mail",
    display_name_attr: "cn",
    role_mapping: []
  ]

  @type t :: %__MODULE__{}

  @type reason ::
          :empty_password
          | :invalid_credentials
          | :plaintext_refused
          | :connect_failed
          | :tls_failed
          | :search_failed
          | :user_not_found
          | :ambiguous_user
          | :group_search_failed
          | :not_in_group
          | :no_role
          | :invalid_username

  @impl true
  def parse(config, context), do: Config.parse(config, context)

  @impl true
  @spec authenticate(t(), String.t(), String.t(), keyword()) ::
          {:ok, Macaw.Auth.Native.Source.attrs()} | {:error, reason()}
  def authenticate(source, username, password, opts \\ [])

  def authenticate(_source, _username, password, _opts) when password in [nil, ""],
    do: {:error, :empty_password}

  def authenticate(%__MODULE__{} = source, username, password, _opts) do
    username = String.trim(username || "")

    with {:ok, conn} <- connect(source) do
      result = signed_in(conn, source, username, password)
      :eldap.close(conn)
      result
    end
  end

  defp signed_in(conn, source, username, password) do
    with {:ok, dn} <- find_dn(conn, source, username),
         :ok <- bind(conn, dn, password),
         {:ok, entry} <- read_entry(conn, source, dn),
         {:ok, name} <- username(source, entry),
         {:ok, groups} <- groups(conn, source, dn, entry),
         :ok <- required_group(source, groups),
         {:ok, roles} <- roles(source, groups) do
      {:ok,
       %{
         username: name,
         display_name: first(entry, source.display_name_attr),
         roles: roles,
         extra: %{
           "dn" => dn,
           "external_id" => external_id(source, entry, dn),
           "email" => first(entry, source.email_attr),
           "groups" => Enum.map(groups, & &1.dn)
         }
       }}
    end
  end

  @impl true
  def knows?(_source, reason)
      when reason in [
             :empty_password,
             :user_not_found,
             :plaintext_refused,
             :connect_failed,
             :tls_failed,
             :search_failed
           ],
      do: false

  def knows?(%__MODULE__{user_dn_template: t}, :invalid_credentials) when is_binary(t),
    do: false

  def knows?(_source, _reason), do: true

  @impl true
  def explain(:empty_password),
    do: "an empty password was refused before connecting (LDAP treats it as an anonymous bind)"

  def explain(:invalid_credentials), do: "the directory refused the password for that DN"

  def explain(:plaintext_refused),
    do:
      "neither ssl nor starttls is set, and allow_plaintext is false: passwords are not sent unencrypted"

  def explain(:connect_failed), do: "the directory could not be reached"

  def explain(:tls_failed),
    do:
      "TLS failed: the certificate did not verify (chain, cacertfile or hostname), or the server refused TLS"

  def explain(:search_failed),
    do: "the search failed: the service bind was refused, or the directory refused the search"

  def explain(:user_not_found), do: "no entry matched the username"
  def explain(:ambiguous_user), do: "more than one entry matched the username"

  def explain(:group_search_failed),
    do:
      "the group search failed: the service bind was refused, or the directory refused the search"

  def explain(:not_in_group), do: "the user is not in the required group"

  def explain(:no_role),
    do: "no role_mapping matched the user's groups and there is no default_role"

  def explain(:invalid_username),
    do: "the directory's username attribute is not a valid username (1–64 of a-z 0-9 . _ @ + -)"

  # ── Connecting ─────────────────────────────────────────────────────────

  @doc false
  def connect(%__MODULE__{ssl: false, starttls: false, allow_plaintext: false}),
    do: {:error, :plaintext_refused}

  def connect(source) do
    host = String.to_charlist(source.host)
    base = [port: source.port, timeout: source.timeout_ms]

    if source.ssl do
      case :eldap.open([host], base ++ [ssl: true, sslopts: tls_options(source)]) do
        {:ok, conn} -> {:ok, conn}
        {:error, _} -> {:error, warn(source, connect_or_tls(source))}
      end
    else
      case :eldap.open([host], base) do
        {:ok, conn} -> starttls(conn, source)
        {:error, _} -> {:error, warn(source, :connect_failed)}
      end
    end
  end

  defp starttls(conn, %{starttls: false}), do: {:ok, conn}

  defp starttls(conn, source) do
    case :eldap.start_tls(conn, tls_options(source), source.timeout_ms) do
      :ok ->
        {:ok, conn}

      {:error, _} ->
        :eldap.close(conn)
        {:error, warn(source, :tls_failed)}
    end
  end

  # eldap reports every LDAPS failure as a failed connect: a plain TCP
  # connect tells a TLS failure from an unreachable server.
  defp connect_or_tls(source) do
    case reachable(source) do
      :ok -> :tls_failed
      {:error, _} -> :connect_failed
    end
  end

  defp reachable(source) do
    host = String.to_charlist(source.host)

    case :gen_tcp.connect(host, source.port, [:binary, active: false], source.timeout_ms) do
      {:ok, socket} -> :gen_tcp.close(socket)
      {:error, _} -> {:error, :connect_failed}
    end
  end

  @doc false
  def tls_options(%{verify_peer: false}), do: [verify: :verify_none]

  def tls_options(source) do
    cacerts =
      case source.cacertfile do
        nil -> [cacerts: :public_key.cacerts_get()]
        path -> [cacertfile: String.to_charlist(path)]
      end

    [
      verify: :verify_peer,
      server_name_indication: String.to_charlist(source.host),
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)],
      depth: 3
    ] ++ cacerts
  end

  # ── The DN and the password ────────────────────────────────────────────

  defp find_dn(_conn, _source, ""), do: {:error, :user_not_found}

  defp find_dn(_conn, %{user_dn_template: template}, username) when is_binary(template),
    do: {:ok, String.replace(template, "{username}", Escape.dn_value(username))}

  defp find_dn(conn, %{search: search} = source, username) do
    # The template was checked when the configuration was read, and the
    # username is data in the term, so it can't make the filter malformed.
    {:ok, filter} = Filter.build(search.filter, username)

    with :ok <- service_bind(conn, search.bind_dn, source, :search_failed),
         {:ok, entries} <- search(conn, source, search.base_dn, filter, ["dn"], :search_failed) do
      case entries do
        [] -> {:error, :user_not_found}
        [{dn, _attrs}] -> {:ok, dn}
        [_, _ | _] -> {:error, :ambiguous_user}
      end
    end
  end

  # The source's one service account: the search's, or the groups'.
  defp service_bind(_conn, nil, _source, _reason), do: :ok

  defp service_bind(conn, bind_dn, source, reason) do
    case :eldap.simple_bind(conn, bytes(bind_dn), bytes(source.bind_password)) do
      :ok -> :ok
      {:error, _} -> {:error, warn(source, reason)}
    end
  end

  defp bind(conn, dn, password) do
    case :eldap.simple_bind(conn, bytes(dn), bytes(password)) do
      :ok -> :ok
      {:error, _} -> {:error, :invalid_credentials}
    end
  end

  defp bytes(binary), do: :binary.bin_to_list(binary)

  # ── Attributes and groups ──────────────────────────────────────────────

  defp read_entry(conn, source, dn) do
    attrs = [
      source.id_attr,
      source.username_attr,
      source.email_attr,
      source.display_name_attr,
      "memberOf"
    ]

    present = :eldap.present(~c"objectClass")

    case search(conn, source, dn, present, attrs, :search_failed, :eldap.baseObject()) do
      {:ok, [{_dn, entry}]} -> {:ok, entry}
      {:ok, _} -> {:error, :user_not_found}
      error -> error
    end
  end

  defp username(source, entry) do
    case UserRecord.normalize_username(first(entry, source.username_attr)) do
      {:ok, name} -> {:ok, name}
      {:error, _} -> {:error, :invalid_username}
    end
  end

  defp groups(_conn, %{groups: nil}, _dn, _entry), do: {:ok, []}

  defp groups(_conn, %{groups: %{from: :member_of}}, _dn, entry),
    do: {:ok, for(dn <- Map.get(entry, "memberof", []), do: %{dn: dn, cn: cn(dn)})}

  defp groups(conn, source, dn, entry) do
    with :ok <- group_bind(conn, source), do: search_groups(conn, source, dn, entry)
  end

  # Search mode re-binds as its service account to read the groups; a
  # direct bind as the groups' account when it has one, else the user's own
  # bind reads them.
  defp group_bind(conn, %{search: %{bind_dn: bind_dn}} = source),
    do: service_bind(conn, bind_dn, source, :group_search_failed)

  defp group_bind(conn, %{groups: %{from: :search, bind_dn: bind_dn}} = source),
    do: service_bind(conn, bind_dn, source, :group_search_failed)

  defp group_bind(_conn, _source), do: :ok

  # posixGroup's memberUid holds the uid as the directory spells it;
  # groupOfNames' member holds the DN.
  defp search_groups(conn, %{groups: %{base_dn: base, member_attr: attr}} = source, dn, entry) do
    value = if attr == "memberUid", do: first(entry, source.username_attr) || "", else: dn
    filter = :eldap.equalityMatch(String.to_charlist(attr), bytes(value))

    with {:ok, entries} <- search(conn, source, base, filter, ["cn"], :group_search_failed) do
      {:ok,
       for {gdn, attrs} <- entries do
         %{dn: gdn, cn: List.first(Map.get(attrs, "cn", [])) || cn(gdn)}
       end}
    end
  end

  defp required_group(%{required_group: nil}, _groups), do: :ok

  defp required_group(%{required_group: group}, groups),
    do: if(member?(groups, group), do: :ok, else: {:error, :not_in_group})

  # Every role every matched group maps to, else the default.
  defp roles(source, groups) do
    mapped =
      for {group, roles} <- source.role_mapping,
          member?(groups, group),
          role <- roles,
          uniq: true,
          do: role

    case {mapped, source.default_role} do
      {[], nil} -> {:error, :no_role}
      {[], default} -> {:ok, default}
      {roles, _} -> {:ok, roles}
    end
  end

  @doc "Whether `groups` include `name`, a CN or a DN, ignoring case."
  @spec member?([%{dn: String.t(), cn: String.t() | nil}], String.t()) :: boolean()
  def member?(groups, name) do
    name = String.downcase(name)

    Enum.any?(groups, fn g ->
      String.downcase(g.dn) == name or (g.cn != nil and String.downcase(g.cn) == name)
    end)
  end

  defp external_id(source, entry, dn) do
    case Map.get(entry, String.downcase(source.id_attr)) do
      [value | _] ->
        if String.printable?(value), do: value, else: Base.encode16(value, case: :lower)

      _ ->
        dn
    end
  end

  defp first(entry, attr), do: entry |> Map.get(String.downcase(attr), []) |> List.first()

  defp cn(dn) do
    case Regex.run(~r/^cn=((?:[^,\\]|\\.)*)/i, dn) do
      [_, cn] -> cn
      nil -> nil
    end
  end

  # ── Diagnostics (mix macaw_auth.ldap.check) ────────────────────────────

  @doc """
  Runs the sign-in flow for `username` without signing in, and says how
  each step went: `[{step, :ok | :error, detail}]`, ending at the first
  failure. The steps: connect, TLS, find the user's DN (the search), bind,
  read attributes, username, the bind for the groups (a direct bind with a
  groups account only), groups, required group, roles. The passwords, the
  user's and the service account's, appear nowhere in the result.
  """
  @spec diagnose(t(), String.t(), String.t() | nil) :: [{String.t(), :ok | :error, String.t()}]
  def diagnose(_source, _username, password) when password in [nil, ""],
    do: [{"password", :error, explain(:empty_password)}]

  def diagnose(%__MODULE__{} = source, username, password) do
    username = String.trim(username || "")
    where = "#{source.host}:#{source.port}"

    with {:connect, :ok} <- {:connect, reachable(source)},
         {:tls, {:ok, conn}} <- {:tls, connect(source)} do
      steps =
        [
          {"connect", :ok, "#{where} is reachable"},
          {"TLS", :ok, transport(source)} | diagnosed(conn, source, username, password)
        ]

      :eldap.close(conn)
      steps
    else
      {:connect, {:error, reason}} ->
        [{"connect", :error, "#{where}: #{explain(reason)}"}]

      {:tls, {:error, reason}} ->
        [{"connect", :ok, "#{where} is reachable"}, {"TLS", :error, explain(reason)}]
    end
  end

  defp transport(source) do
    verify =
      if source.verify_peer,
        do: "certificate and hostname verified",
        else: "certificate NOT verified (verify_peer: false)"

    cond do
      source.ssl -> "LDAPS, #{verify}"
      source.starttls -> "StartTLS, #{verify}"
      true -> "plain LDAP: passwords are sent unencrypted (allow_plaintext: true)"
    end
  end

  defp diagnosed(conn, source, username, password) do
    user_steps = [
      {"find the user's DN", :dn, fn _ -> find_dn(conn, source, username) end,
       &"#{finding(source, username)}: DN #{&1}"},
      {"bind as the user", :bound,
       fn s -> with(:ok <- bind(conn, s.dn, password), do: {:ok, true}) end,
       fn _ -> "the password was accepted" end},
      {"read attributes", :entry, fn s -> read_entry(conn, source, s.dn) end,
       &describe_entry(source, &1)},
      {"username", :username, fn s -> username(source, s.entry) end, &"#{&1}"}
    ]

    access_steps = [
      {"required group", :required,
       fn s ->
         with :ok <- required_group(source, s.groups), do: {:ok, source.required_group}
       end, &if(&1, do: "member of #{&1}", else: "none required")},
      {"roles", :roles, fn s -> roles(source, s.groups) end, &Enum.join(&1, ", ")}
    ]

    (user_steps ++ group_steps(conn, source) ++ access_steps)
    |> Enum.reduce_while({[], %{}}, fn {label, key, run, describe}, {acc, state} ->
      case run.(state) do
        {:ok, value} ->
          {:cont, {[{label, :ok, describe.(value)} | acc], Map.put(state, key, value)}}

        {:error, reason} ->
          {:halt, {[{label, :error, explain(reason)} | acc], state}}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  # A direct bind's groups account is a step of its own, before the groups
  # are read with it.
  defp group_steps(conn, %{search: nil, groups: %{from: :search, bind_dn: bind_dn}} = source)
       when is_binary(bind_dn) do
    [
      {"bind for the groups", :group_bind,
       fn _ -> with(:ok <- group_bind(conn, source), do: {:ok, bind_dn}) end, &"bound as #{&1}"},
      {"groups", :groups, fn s -> search_groups(conn, source, s.dn, s.entry) end,
       &describe_groups/1}
    ]
  end

  defp group_steps(conn, source),
    do: [
      {"groups", :groups, fn s -> groups(conn, source, s.dn, s.entry) end, &describe_groups/1}
    ]

  defp describe_groups([]), do: "none"
  defp describe_groups(groups), do: Enum.map_join(groups, ", ", fn g -> g.cn || g.dn end)

  defp finding(%{user_dn_template: t}, _username) when is_binary(t), do: "direct bind"

  defp finding(%{search: search}, username) do
    filter = String.replace(search.filter, "{username}", Escape.filter_value(username))
    as = if search.bind_dn, do: "as #{search.bind_dn}", else: "anonymously"
    "searched #{search.base_dn} for #{filter} #{as}"
  end

  defp describe_entry(source, entry) do
    "id (#{source.id_attr}): #{first(entry, source.id_attr) || "absent, the DN is used"}; " <>
      "username: #{first(entry, source.username_attr)}; email: #{first(entry, source.email_attr)}; " <>
      "display name: #{first(entry, source.display_name_attr)}"
  end

  # ── eldap ──────────────────────────────────────────────────────────────

  # Entries as {dn, %{lower-case attribute => [binary values]}}.
  defp search(conn, source, base, filter, attrs, reason, scope \\ :eldap.wholeSubtree()) do
    opts = [
      base: bytes(base),
      filter: filter,
      scope: scope,
      attributes: Enum.map(attrs, &String.to_charlist/1),
      timeout: source.timeout_ms
    ]

    case :eldap.search(conn, opts) do
      {:ok, {:eldap_search_result, entries, _referrals, _controls}} ->
        {:ok, Enum.map(entries, &entry/1)}

      {:ok, {:eldap_search_result, entries, _referrals}} ->
        {:ok, Enum.map(entries, &entry/1)}

      {:error, :noSuchObject} ->
        {:ok, []}

      {:error, _} ->
        {:error, warn(source, reason)}
    end
  end

  defp entry({:eldap_entry, dn, attrs}) do
    {:erlang.list_to_binary(dn),
     Map.new(attrs, fn {name, values} ->
       {name |> to_string() |> String.downcase(), Enum.map(values, &:erlang.list_to_binary/1)}
     end)}
  end

  defp warn(source, reason) do
    Logger.warning(
      "LDAP source #{source.name}: #{explain(reason)} (#{source.host}:#{source.port})"
    )

    reason
  end
end
