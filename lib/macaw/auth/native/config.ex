defmodule Macaw.Auth.Native.Config do
  @moduledoc """
  The native backend's configuration, read once and parsed into structs,
  every fault named (exio's `AuthConfig` approach):

      config :macaw_auth, Macaw.Auth.Native,
        repo: MyApp.Repo,
        hasher: Macaw.Auth.Native.Hasher.Bcrypt,
        sources: [
          %{type: :password},
          %{type: :ldap, name: "nas", host: "nas.example.test", ...}
        ]

  - `repo` (required): the host's `Ecto.Repo`, holding `macaw_auth_users`.
  - `hasher`: `Macaw.Auth.Native.Hasher.Bcrypt` (the default) or
    `Macaw.Auth.Native.Hasher.Argon2`; refused when its library isn't a
    dependency.
  - `sources`: the chain, tried in order (`Macaw.Auth.Native.Source`);
    default `[%{type: :password}]`. Types: `:password`
    (`Macaw.Auth.Native.Source.Password`) and `:ldap`
    (`Macaw.Auth.Native.Source.Ldap.Config`). Names are unique: a name is
    the `source` of the rows it provisions.
  - `session_idle_days`: how long a session may go unused before it
    expires (`Macaw.Auth.Native.Sessions`), 1–3650; default 14.

  A source map may use string keys and a string `type`, as a JSON or
  `config.exs` file writes it; those become atoms only by lookup among the
  known ones. `load!/0` raises `Macaw.Auth.Native.ConfigError` with the
  fault (`sources[nas].host: is required`); it runs when the application
  starts with `backend: Macaw.Auth.Native`, so a bad configuration refuses
  boot rather than a sign-in, and the result is kept in
  `:persistent_term` for `get/0`.
  """

  alias Macaw.Auth.Native.{Hasher, Settings, Source}

  @enforce_keys [:repo, :hasher, :sources]
  defstruct [:repo, :hasher, :sources, session_idle_days: 14]

  @type t :: %__MODULE__{
          repo: module(),
          hasher: module(),
          sources: [Source.t()],
          session_idle_days: pos_integer()
        }

  @keys [:repo, :hasher, :sources, :session_idle_days]
  @types %{password: Source.Password, ldap: Source.Ldap}

  defmodule Error do
    @moduledoc "A fault in the native backend's configuration, named."
    defexception [:message]
  end

  @doc """
  Parses a configuration (a keyword list or map): `{:ok, config}` or
  `{:error, message}`. Options: `:env` (the environment for `{:env, VAR}`
  secrets, default the process's).
  """
  @spec parse(keyword() | map(), keyword()) :: {:ok, t()} | {:error, String.t()}
  def parse(config, opts \\ []) do
    config = Map.new(config)

    with :ok <- known(config),
         {:ok, repo} <- repo(config[:repo]),
         {:ok, hasher} <- hasher(Map.get(config, :hasher, Hasher.Bcrypt)),
         {:ok, sources} <-
           sources(
             Map.get(config, :sources, [%{type: :password}]),
             Keyword.merge(opts, repo: repo, hasher: hasher)
           ),
         {:ok, idle_days} <- idle_days(Map.get(config, :session_idle_days, 14)) do
      {:ok,
       %__MODULE__{
         repo: repo,
         hasher: hasher,
         sources: sources,
         session_idle_days: idle_days
       }}
    end
  end

  defp idle_days(days) when is_integer(days) and days in 1..3650, do: {:ok, days}

  defp idle_days(other),
    do: {:error, "session_idle_days: must be an integer in 1..3650, got #{inspect(other)}"}

  defp known(config) do
    case Enum.reject(Map.keys(config), &(&1 in @keys)) do
      [] -> :ok
      [key | _] -> {:error, "#{inspect(key)}: is not a Macaw.Auth.Native setting"}
    end
  end

  defp repo(repo) when is_atom(repo) and repo not in [nil, true, false], do: {:ok, repo}
  defp repo(nil), do: {:error, "repo: is required (the host's Ecto.Repo)"}
  defp repo(other), do: {:error, "repo: must be a module, got #{inspect(other)}"}

  defp hasher(module) do
    with :ok <- Hasher.check(module), do: {:ok, module}
  end

  defp sources([_ | _] = sources, context) do
    sources
    |> Enum.reduce_while({:ok, []}, fn source, {:ok, acc} ->
      with {:ok, module} <- type(source),
           {:ok, parsed} <- module.parse(source, context),
           :ok <- unique(parsed.name, acc) do
        {:cont, {:ok, [parsed | acc]}}
      else
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, parsed} -> {:ok, Enum.reverse(parsed)}
      error -> error
    end
  end

  defp sources(_, _context), do: {:error, "sources: must be a non-empty list of source maps"}

  defp type(%{} = source) do
    type = Map.get(source, :type, Map.get(source, "type"))
    found = Enum.find(@types, fn {t, _} -> t == type or Atom.to_string(t) == type end)

    case found do
      {_, module} -> {:ok, module}
      nil -> {:error, "sources: unknown type #{inspect(type)}; one of :password, :ldap"}
    end
  end

  defp type(other), do: {:error, "sources: each source must be a map, got #{inspect(other)}"}

  defp unique(name, parsed) do
    if Enum.any?(parsed, &(&1.name == name)),
      do: Settings.fail(name, :name, "is used by two sources"),
      else: :ok
  end

  @doc "Reads and parses the application's configuration; raises `Error` naming the fault."
  @spec load!() :: t()
  def load! do
    case parse(Application.get_env(:macaw_auth, Macaw.Auth.Native, [])) do
      {:ok, config} -> put(config)
      {:error, message} -> raise Error, "config :macaw_auth, Macaw.Auth.Native: " <> message
    end
  end

  @doc "Records a parsed configuration for this node (tests swap it)."
  @spec put(t()) :: t()
  def put(%__MODULE__{} = config) do
    :persistent_term.put(__MODULE__, config)
    config
  end

  @doc "The parsed configuration, read at first use when boot didn't."
  @spec get() :: t()
  def get do
    case :persistent_term.get(__MODULE__, nil) do
      nil -> load!()
      config -> config
    end
  end
end
