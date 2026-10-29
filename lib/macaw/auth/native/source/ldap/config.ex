defmodule Macaw.Auth.Native.Source.Ldap.Config do
  @moduledoc """
  An LDAP source's configuration, validated with its defaults filled
  (ported from exio's and macaw's `LdapSource`), so a bad one is refused
  naming the source and the key: `sources[nas].host: is required`.

  - **Connection:** `host` (required), `port` (636), `ssl` (true),
    `starttls` (false), `allow_plaintext` (false), `verify_peer` (true),
    `cacertfile` (the system's CAs when absent), `timeout_ms` (5000).
    `allow_plaintext: false` refuses a source with neither `ssl` nor
    `starttls`, because its bind would send passwords in the clear;
    setting it true is an explicit, visible decision.
  - **Finding the user**, exactly one of: `user_dn_template` containing
    `{username}` (a direct bind: `uid={username},cn=users,dc=example,dc=test`),
    or `search: %{base_dn, filter, bind_dn, bind_password}` (filter default
    `(uid={username})`; an anonymous search only with
    `allow_anonymous_search: true`).
  - **Attributes:** `id_attr` (`entryUUID`; the DN when absent),
    `username_attr` (`uid`), `email_attr` (`mail`), `display_name_attr`
    (`cn`).
  - **Groups:** `groups: %{base_dn, member_attr, bind_dn, bind_password}`
    with `member_attr` one of `member` (groupOfNames, the default),
    `uniqueMember`, or `memberUid` (posixGroup, matched by the username),
    or `groups: %{from: :member_of}`. `bind_dn` and `bind_password`, set
    together and only with `user_dn_template`, are the service account a
    direct-bind source reads the groups as; without them the user's own
    bind reads them.
  - **Access:** `required_group` (a CN or DN), `role_mapping` (a map of
    group to a role or a list of roles; the user gets every mapped role of
    every group they are in) and `default_role` (a role, or a list, for a
    user no mapping matched). With neither a match nor a default, the user
    is refused (`:no_role`).

  A `bind_password` (the search's or the groups') is a literal,
  `{:env, "VAR"}` or `{:file, path}`, resolved here; no error message
  contains it, and the struct's inspection hides it. A source has at most
  one service account, so its password is the struct's one `bind_password`.
  """

  alias Macaw.Auth.Native.Settings
  alias Macaw.Auth.Native.Source.Ldap
  alias Macaw.Auth.Native.Source.Ldap.Filter

  @keys ~w(type name host port ssl starttls allow_plaintext verify_peer cacertfile timeout_ms
           user_dn_template search allow_anonymous_search id_attr username_attr email_attr
           display_name_attr groups required_group role_mapping default_role)a

  @search_keys ~w(base_dn filter bind_dn bind_password)a
  @group_keys ~w(from base_dn member_attr bind_dn bind_password)a

  @doc "`{:ok, %Ldap{}}` or `{:error, \"sources[<name>].<key>: …\"}`."
  @spec parse(map(), keyword()) :: {:ok, Ldap.t()} | {:error, String.t()}
  def parse(config, context) do
    s = Settings.normalize(config, @keys)

    with {:ok, name} <- Settings.name(s, nil),
         :ok <- Settings.known_keys(s, @keys, name),
         {:ok, host} <- Settings.required_string(s, :host, name),
         {:ok, port} <- Settings.int(s, :port, 636, 1..65_535, name),
         {:ok, ssl} <- Settings.bool(s, :ssl, true, name),
         {:ok, starttls} <- Settings.bool(s, :starttls, false, name),
         {:ok, plaintext} <- Settings.bool(s, :allow_plaintext, false, name),
         :ok <- transport(ssl, starttls, plaintext, name),
         {:ok, verify} <- Settings.bool(s, :verify_peer, true, name),
         {:ok, cacertfile} <- cacertfile(s, name),
         {:ok, timeout} <- Settings.int(s, :timeout_ms, 5000, 1..600_000, name),
         {:ok, finding} <- finding(s, name, context),
         {:ok, attrs} <- attrs(s, name),
         {:ok, groups, group_password} <- groups(s[:groups], finding, name, context),
         {:ok, required} <- Settings.optional_string(s, :required_group, name),
         {:ok, mapping} <- mapping(Map.get(s, :role_mapping, %{}), name),
         {:ok, default_role} <- default_role(s[:default_role], name) do
      {:ok,
       struct!(
         Ldap,
         Map.merge(
           %{
             name: name,
             host: host,
             port: port,
             ssl: ssl,
             starttls: starttls,
             allow_plaintext: plaintext,
             verify_peer: verify,
             cacertfile: cacertfile,
             timeout_ms: timeout,
             groups: groups,
             required_group: required,
             role_mapping: mapping,
             default_role: default_role
           },
           Map.merge(%{finding | bind_password: finding.bind_password || group_password}, attrs)
         )
       )}
    end
  end

  defp transport(true, true, _plain, name),
    do: Settings.fail(name, :starttls, "can't be used with ssl: true")

  defp transport(false, false, false, name),
    do:
      Settings.fail(
        name,
        :ssl,
        "is false: set starttls: true, or allow_plaintext: true to send passwords unencrypted"
      )

  defp transport(_ssl, _starttls, _plain, _name), do: :ok

  defp cacertfile(s, name) do
    case s[:cacertfile] do
      nil ->
        {:ok, nil}

      path when is_binary(path) ->
        if File.regular?(path),
          do: {:ok, path},
          else: Settings.fail(name, :cacertfile, "#{path} is not a readable file")

      _ ->
        Settings.fail(name, :cacertfile, "must be a path")
    end
  end

  # Exactly one of the two ways to find the user's DN.
  defp finding(s, name, context) do
    case {s[:user_dn_template], s[:search]} do
      {nil, nil} ->
        Settings.fail(name, :user_dn_template, "or search is required")

      {t, nil} when is_binary(t) ->
        if String.contains?(t, "{username}"),
          do: {:ok, %{user_dn_template: t, search: nil, bind_password: nil}},
          else: Settings.fail(name, :user_dn_template, "must contain {username}")

      {nil, %{} = search} ->
        search(Settings.normalize(search, @search_keys), s, name, context)

      {nil, _} ->
        Settings.fail(name, :search, "must be a map")

      {_, _} ->
        Settings.fail(name, :search, "can't be set with user_dn_template: choose one")
    end
  end

  defp search(search, s, name, context) do
    filter = Map.get(search, :filter, "(uid={username})")

    with :ok <- Settings.known_keys(search, @search_keys, name),
         {:ok, base} <- Settings.required_string(search, :base_dn, name, "search.base_dn"),
         :ok <- filter(filter, name),
         {:ok, anonymous} <- Settings.bool(s, :allow_anonymous_search, false, name),
         {:ok, password} <- bind_password(search, :"search.bind_password", name, context) do
      found = fn dn, pw ->
        {:ok,
         %{
           user_dn_template: nil,
           search: %{base_dn: base, filter: filter, bind_dn: dn},
           bind_password: pw
         }}
      end

      case {search[:bind_dn], password} do
        {nil, nil} when anonymous ->
          found.(nil, nil)

        {nil, nil} ->
          Settings.fail(
            name,
            :"search.bind_dn",
            "and bind_password are required (or allow_anonymous_search: true)"
          )

        {dn, pw} when is_binary(dn) and dn != "" and is_binary(pw) ->
          found.(dn, pw)

        _ ->
          Settings.fail(name, :"search.bind_dn", "and bind_password must be set together")
      end
    end
  end

  defp filter(filter, name) do
    if Filter.valid_template?(filter),
      do: :ok,
      else: Settings.fail(name, :"search.filter", "must be an LDAP filter containing {username}")
  end

  defp bind_password(map, label, name, context) do
    case Map.fetch(map, :bind_password) do
      :error ->
        {:ok, nil}

      {:ok, ref} ->
        case Settings.secret(ref, Keyword.get_lazy(context, :env, &System.get_env/0)) do
          {:ok, value} -> {:ok, value}
          {:error, why} -> Settings.fail(name, label, why)
        end
    end
  end

  defp attrs(s, name) do
    Enum.reduce_while(
      [id_attr: "entryUUID", username_attr: "uid", email_attr: "mail", display_name_attr: "cn"],
      {:ok, %{}},
      fn {key, default}, {:ok, acc} ->
        case Map.get(s, key, default) do
          v when is_binary(v) and v != "" -> {:cont, {:ok, Map.put(acc, key, v)}}
          _ -> {:halt, Settings.fail(name, key, "must be an attribute name")}
        end
      end
    )
  end

  # The groups, and the password of the service account that reads them
  # (direct bind only), `{:ok, groups, password}`.
  defp groups(nil, _finding, _name, _context), do: {:ok, nil, nil}

  defp groups(%{} = groups, finding, name, context) do
    g = Settings.normalize(groups, @group_keys)

    with :ok <- Settings.known_keys(g, @group_keys, name),
         {:ok, groups} <- group_source(g, name) do
      group_account(g, groups, finding, name, context)
    end
  end

  defp groups(_, _finding, name, _context), do: group_source(:bad, name)

  defp group_source(%{from: from}, _name) when from in [:member_of, "member_of"],
    do: {:ok, %{from: :member_of}}

  defp group_source(%{base_dn: base} = g, name) when is_binary(base) and base != "" do
    attr = Map.get(g, :member_attr, "member")

    if attr in ~w(member uniqueMember memberUid),
      do: {:ok, %{from: :search, base_dn: base, member_attr: attr}},
      else:
        Settings.fail(name, :"groups.member_attr", "must be member, uniqueMember or memberUid")
  end

  defp group_source(_, name),
    do:
      Settings.fail(
        name,
        :groups,
        "must be %{from: :member_of} or %{base_dn: …, member_attr: …}"
      )

  # The service account is for a group search after a direct bind: memberOf
  # is read from the user's own entry, and search mode already reads the
  # groups as search.bind_dn.
  defp group_account(g, groups, finding, name, context) do
    account? = Map.has_key?(g, :bind_dn) or Map.has_key?(g, :bind_password)

    cond do
      not account? and groups.from == :search ->
        {:ok, Map.put(groups, :bind_dn, nil), nil}

      not account? ->
        {:ok, groups, nil}

      groups.from == :member_of ->
        Settings.fail(
          name,
          :"groups.bind_dn",
          "and bind_password can't be used with from: :member_of (memberOf is read from the user's own entry)"
        )

      finding.search != nil ->
        Settings.fail(
          name,
          :"groups.bind_dn",
          "is for a direct bind (user_dn_template): search mode reads the groups as search.bind_dn"
        )

      true ->
        with {:ok, password} <- bind_password(g, :"groups.bind_password", name, context) do
          case {g[:bind_dn], password} do
            {dn, pw} when is_binary(dn) and dn != "" and is_binary(pw) ->
              {:ok, Map.put(groups, :bind_dn, dn), pw}

            _ ->
              Settings.fail(name, :"groups.bind_dn", "and bind_password must be set together")
          end
        end
    end
  end

  defp mapping(map, name) when is_map(map) do
    Enum.reduce_while(map, {:ok, []}, fn {group, roles}, {:ok, acc} ->
      with true <- is_binary(group) and group != "",
           {:ok, roles} <- roles(roles) do
        {:cont, {:ok, acc ++ [{group, roles}]}}
      else
        _ ->
          {:halt,
           Settings.fail(name, :role_mapping, "must map group names to a role or a list of roles")}
      end
    end)
  end

  defp mapping(_, name), do: Settings.fail(name, :role_mapping, "must be a map of group => role")

  defp default_role(nil, _name), do: {:ok, nil}

  defp default_role(roles, name) do
    case roles(roles) do
      {:ok, roles} -> {:ok, roles}
      :error -> Settings.fail(name, :default_role, "must be a role or a list of roles")
    end
  end

  # Roles are strings: an atom is written as its name, never the reverse.
  defp roles(role) when is_binary(role) and role != "", do: {:ok, [role]}

  defp roles(role) when is_atom(role) and role not in [nil, true, false],
    do: roles(Atom.to_string(role))

  defp roles([_ | _] = list) do
    Enum.reduce_while(list, {:ok, []}, fn role, {:ok, acc} ->
      case roles(role) do
        {:ok, [r]} -> {:cont, {:ok, acc ++ [r]}}
        _ -> {:halt, :error}
      end
    end)
  end

  defp roles(_), do: :error
end
