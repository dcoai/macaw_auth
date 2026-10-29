defmodule Macaw.Auth.Native.UserCommands do
  @moduledoc """
  The user commands of `mix macaw_auth.user` and of the release entry
  points (`Macaw.Auth.Native.Release`), one implementation for both:

      list
      add NAME --role R [--role R…]
      disable NAME
      enable NAME
      delete NAME
      password NAME
      roles NAME R…
      reset-second-factor NAME

  and the release's `bootstrap NAME --role R` (`bootstrap/3`).

  Each runs `Macaw.Auth.Native`'s own user functions and answers
  `{:ok, objects}`, printed one JSON object per line, or
  `{:error, message}`: a user's mistake is an answer, never a raise.

  **A password never comes from the command line,** where `ps` and shell
  history show it: `add`, `password` and `bootstrap` take it from an
  environment variable, named by the caller (`:password_var`), and refuse
  a `--password`, `--password=…` or `-p` among the arguments. No message
  repeats an argument it didn't understand, which may be a password typed
  in the wrong place; the only word a message repeats is a user's name.
  """

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Config, UserRecord}

  @usage "list | add NAME --role R [--role R…] | disable NAME | enable NAME | " <>
           "delete NAME | password NAME | roles NAME R… | reset-second-factor NAME"

  @doc "The commands' usage, as an error names it after `usage: `."
  @spec usage() :: String.t()
  def usage, do: @usage

  @doc """
  Runs one user command: `argv` its words, `password` the value of the
  password's environment variable (or nil). Options: `:password_var`,
  the variable's name, for messages; `:announce`, passed to the functions
  that revoke sessions (`false` in a process that is not the app's node).
  The repo is started first when it isn't running (`start/0`).
  """
  @spec run([String.t()], String.t() | nil, keyword()) ::
          {:ok, [map()]} | {:error, String.t()}
  def run(argv, password, opts) do
    with :ok <- no_password_in(argv, opts),
         {:ok, command} <- parse(argv),
         :ok <- start() do
      command(command, password, opts)
    end
  end

  @doc """
  `bootstrap NAME --role R`, the words after `bootstrap`: the first admin,
  made by `Macaw.Auth.Native.bootstrap_admin/1` only when no user exists.
  `{"ok": true, "created": NAME, "role": R}`, or, when any user exists,
  `{"ok": true, "created": null, "reason": "a user already exists"}`.
  """
  @spec bootstrap([String.t()], String.t() | nil, keyword()) ::
          {:ok, [map()]} | {:error, String.t()}
  def bootstrap(argv, password, opts) do
    with :ok <- no_password_in(argv, opts),
         {:ok, name, role} <- parse_bootstrap(argv),
         :ok <- start() do
      case Native.bootstrap_admin(%{username: name, password: password, role: role}) do
        {:ok, record} -> {:ok, [%{ok: true, created: record.username, role: role}]}
        :exists -> {:ok, [%{ok: true, created: nil, reason: "a user already exists"}]}
        {:error, :no_password} -> {:error, no_password(opts)}
        {:error, %Ecto.Changeset{} = changeset} -> {:error, errors(changeset)}
      end
    end
  end

  @doc """
  Makes ready what the commands need, in a process that has the app's
  configuration but runs nothing of it (a mix task, a release's `eval`):
  the native backend's configuration (`Macaw.Auth.Native.Config.fetch/0`;
  a fault is `{:error, message}`) and its repo, started without query
  logging, so nothing but the answer reaches stdout and no query's
  parameters (a password's hash) reach a log. A running repo is used as it
  is.
  """
  @spec start() :: :ok | {:error, String.t()}
  def start do
    with {:ok, %Config{repo: repo}} <- Config.fetch() do
      {:ok, _} = Application.ensure_all_started(:ecto_sql)
      {:ok, _} = repo.__adapter__().ensure_all_started(repo.config(), :temporary)

      case repo.start_link(pool_size: 2, log: false) do
        {:ok, _pid} -> :ok
        {:error, {:already_started, _pid}} -> :ok
      end
    end
  end

  # ── Parsing ───────────────────────────────────────────────────────────

  defp no_password_in(argv, opts) do
    if Enum.any?(argv, &password_flag?/1),
      do:
        {:error, "a password is never read from the command line: set #{var(opts)} to it instead"},
      else: :ok
  end

  defp password_flag?(arg), do: arg in ["-p", "--password"] or arg =~ ~r/\A--password=/

  defp parse(["list"]), do: {:ok, :list}

  defp parse(["add", name | rest]) do
    case roles_flags(rest, []) do
      {:ok, [_ | _] = roles} when name != "" -> {:ok, {:add, name, roles}}
      _ -> usage_error()
    end
  end

  defp parse(["disable", name]) when name != "", do: {:ok, {:disable, name}}
  defp parse(["enable", name]) when name != "", do: {:ok, {:enable, name}}
  defp parse(["delete", name]) when name != "", do: {:ok, {:delete, name}}
  defp parse(["password", name]) when name != "", do: {:ok, {:password, name}}

  defp parse(["reset-second-factor", name]) when name != "",
    do: {:ok, {:reset_second_factor, name}}

  defp parse(["roles", name | [_ | _] = roles]) do
    if name != "" and Enum.all?(roles, &role?/1),
      do: {:ok, {:roles, name, roles}},
      else: usage_error()
  end

  defp parse(_argv), do: usage_error()

  defp parse_bootstrap([name, "--role", role]) when name != "" do
    if role?(role), do: {:ok, name, role}, else: bootstrap_usage()
  end

  defp parse_bootstrap(_argv), do: bootstrap_usage()

  defp roles_flags([], roles), do: {:ok, Enum.reverse(roles)}

  defp roles_flags(["--role", role | rest], roles) do
    if role?(role), do: roles_flags(rest, [role | roles]), else: :usage
  end

  defp roles_flags(_other, _roles), do: :usage

  # A role is a word, not a flag that slipped into its place.
  defp role?(role), do: role != "" and not String.starts_with?(role, "-")

  defp usage_error, do: {:error, "usage: " <> @usage}
  defp bootstrap_usage, do: {:error, "usage: bootstrap NAME --role R"}

  # ── The commands ──────────────────────────────────────────────────────

  defp command(:list, _password, _opts), do: {:ok, Enum.map(Native.list_users(), &listed/1)}

  defp command({:add, name, roles}, password, opts) do
    if is_binary(password) and password != "" do
      case Native.create_user(%{username: name, password: password, roles: roles}) do
        {:ok, record} -> {:ok, [%{ok: true, added: record.username, roles: record.roles}]}
        {:error, changeset} -> {:error, errors(changeset)}
      end
    else
      {:error, no_password(opts)}
    end
  end

  defp command({:disable, name}, _password, _opts) do
    with {:ok, record} <- answer(Native.disable_user(name), name, :disable),
         do: {:ok, [%{ok: true, disabled: record.username}]}
  end

  defp command({:enable, name}, _password, _opts) do
    with {:ok, record} <- answer(Native.enable_user(name), name, :enable),
         do: {:ok, [%{ok: true, enabled: record.username}]}
  end

  defp command({:delete, name}, _password, opts) do
    deleted = Native.delete_user(name, announce: Keyword.get(opts, :announce, true))

    with {:ok, record} <- answer(deleted, name, :delete),
         do: {:ok, [%{ok: true, deleted: record.username}]}
  end

  defp command({:password, name}, password, opts) do
    case Native.set_password(name, password, announce: Keyword.get(opts, :announce, true)) do
      {:ok, record} -> {:ok, [%{ok: true, password_set: record.username}]}
      {:error, :no_password} -> {:error, no_password(opts)}
      other -> answer(other, name, :password)
    end
  end

  defp command({:roles, name, roles}, _password, _opts) do
    with {:ok, record} <- answer(Native.set_roles(name, roles), name, :roles),
         do: {:ok, [%{ok: true, roles_set: record.username, roles: record.roles}]}
  end

  defp command({:reset_second_factor, name}, _password, opts) do
    case Native.get_user(name) do
      %UserRecord{} = record ->
        :ok = Native.admin_reset(record, announce: Keyword.get(opts, :announce, true))
        {:ok, [%{ok: true, second_factor_reset: record.username}]}

      nil ->
        {:error, "no user named #{name}"}
    end
  end

  defp listed(%UserRecord{} = record) do
    user = Native.to_user(record)

    %{
      username: user.username,
      display_name: user.display_name,
      source: user.source,
      roles: user.roles,
      disabled: user.disabled,
      must_change_password: user.must_change_password,
      second_factor: user.second_factor
    }
  end

  # ── Answers ───────────────────────────────────────────────────────────

  defp answer({:ok, record}, _name, _command), do: {:ok, record}
  defp answer({:error, :not_found}, name, _command), do: {:error, "no user named #{name}"}

  defp answer({:error, :not_local}, name, command) do
    %UserRecord{username: username, source: source} = Native.get_user(name)

    case command do
      :roles -> {:error, "#{username}'s roles come from the directory #{source}"}
      :password -> {:error, "#{username}'s password is checked by the directory #{source}"}
    end
  end

  defp no_password(opts),
    do: "set #{var(opts)} to the password (it is never read from the command line)"

  defp var(opts), do: Keyword.fetch!(opts, :password_var)

  # A changeset's errors on one line, `field: message; …`.
  defp errors(changeset) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {message, values} ->
      Regex.replace(~r/%\{(\w+)\}/, message, fn whole, key ->
        Enum.find_value(values, whole, fn {k, v} ->
          Atom.to_string(k) == key and (is_binary(v) or is_number(v) or is_atom(v)) and
            to_string(v)
        end)
      end)
    end)
    |> Enum.flat_map(fn {field, messages} -> Enum.map(messages, &"#{field}: #{&1}") end)
    |> Enum.join("; ")
  end
end
