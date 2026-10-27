defmodule Macaw.Auth.Native do
  @moduledoc """
  The native backend: users in the host's database, passwords checked by
  a chain of sources (local password hashes, LDAP directories).

      config :macaw_auth, backend: Macaw.Auth.Native
      config :macaw_auth, Macaw.Auth.Native,
        repo: MyApp.Repo,
        sources: [%{type: :password}, %{type: :ldap, name: "nas", ...}]

  and `mix macaw_auth.gen.migration` for the users table. The pieces:

  - `Macaw.Auth.Native.Config`: the configuration, parsed once, every
    fault named;
  - `Macaw.Auth.Native.Source`: the chain (the first source that knows the
    user decides) and its two sources, `Password` and `Ldap`;
  - `Macaw.Auth.Native.Provision`: directory users' rows, made at their
    first sign-in and their roles re-derived at every one;
  - `Macaw.Auth.Native.Hasher`: bcrypt or argon2, rehashing at sign-in;
  - `Macaw.Auth.Native.UserRecord`: the `macaw_auth_users` schema.

  **In progress.** This module implements `authenticate/2` of
  `Macaw.Auth.Backend`; the session callbacks (hashed session tokens,
  idle expiry, steps) arrive in #51, and only then does it declare the
  behavior, so it never claims a contract it doesn't yet keep.

  **One refusal.** Whatever a source's reason, the caller sees
  `:invalid_credentials`, or `:disabled` for a disabled user who gave
  the right password. The specific reason, and the source, go to
  telemetry (`[:macaw_auth, :native, :authenticate]`) and to
  `mix macaw_auth.ldap.check`.
  """

  alias Macaw.Auth.Native.{Config, Source, UserRecord}
  alias Macaw.Auth.User

  @doc """
  Checks `%{username: _, password: _}` through the source chain:
  `{:ok, %Macaw.Auth.User{}}`, or `{:error, :invalid_credentials |
  :disabled}`.

  Emits `[:macaw_auth, :native, :authenticate]` with `%{count: 1}` and
  `%{result: :ok | :error, reason: atom | nil, source: name | nil,
  user_id: id | nil}`; never the username or password.
  """
  @spec authenticate(map(), keyword()) ::
          {:ok, User.t()} | {:error, :invalid_credentials | :disabled}
  def authenticate(credentials, opts \\ []) do
    config = Config.get()
    username = text(credentials[:username])
    password = text(credentials[:password])

    case Source.run(config.sources, config.repo, username, password, opts) do
      {:ok, record, source} ->
        event(:ok, nil, source, record.id)
        {:ok, to_user(record)}

      {:error, reason, source} ->
        event(:error, reason, source, nil)
        {:error, if(reason == :disabled, do: :disabled, else: :invalid_credentials)}
    end
  end

  defp text(value) when is_binary(value), do: value
  defp text(_), do: ""

  defp event(result, reason, source, user_id) do
    :telemetry.execute([:macaw_auth, :native, :authenticate], %{count: 1}, %{
      result: result,
      reason: reason,
      source: source && source.name,
      user_id: user_id
    })
  end

  @doc "A users row as the contract's `%Macaw.Auth.User{}`."
  @spec to_user(UserRecord.t()) :: User.t()
  def to_user(%UserRecord{} = r) do
    %User{
      id: r.id,
      username: r.username,
      display_name: r.display_name,
      source: r.source,
      roles: r.roles || [],
      disabled: r.disabled_at != nil,
      must_change_password: r.must_change_password,
      extra: r.extra || %{}
    }
  end

  @doc """
  Makes a local user (`:username`, `:password`, and optionally
  `:display_name`, `:roles`, `:must_change_password`, `:extra`), the
  password hashed with the configured hasher: `{:ok, record}` or
  `{:error, changeset}`.
  """
  @spec create_user(map()) :: {:ok, UserRecord.t()} | {:error, Ecto.Changeset.t()}
  def create_user(%{password: password} = attrs) when is_binary(password) and password != "" do
    config = Config.get()

    %UserRecord{}
    |> UserRecord.changeset(
      attrs
      |> Map.delete(:password)
      |> Map.merge(%{hashed_password: config.hasher.hash(password), source: local_name(config)})
    )
    |> config.repo.insert()
  end

  defp local_name(config),
    do: Enum.find_value(config.sources, "local", &(match?(%Source.Password{}, &1) && &1.name))
end
