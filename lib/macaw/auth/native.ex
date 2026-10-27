defmodule Macaw.Auth.Native do
  @moduledoc """
  The native backend: users and sessions in the host's database,
  passwords checked by a chain of sources (local password hashes, LDAP
  directories), sign-in failures throttled.

      config :macaw_auth, backend: Macaw.Auth.Native
      config :macaw_auth, Macaw.Auth.Native,
        repo: MyApp.Repo,
        sources: [%{type: :password}, %{type: :ldap, name: "nas", ...}],
        session_idle_days: 14

  and `mix macaw_auth.gen.migration` for the tables. The pieces:

  - `Macaw.Auth.Native.Config`: the configuration, parsed once, every
    fault named;
  - `Macaw.Auth.Native.Source`: the chain (the first source that knows the
    user decides) and its two sources, `Password` and `Ldap`;
  - `Macaw.Auth.Native.Provision`: directory users' rows, made at their
    first sign-in and their roles re-derived at every one;
  - `Macaw.Auth.Native.Hasher`: bcrypt or argon2, rehashing at sign-in;
  - `Macaw.Auth.Native.Throttle`: backoff after repeated failures, per
    username and per client address;
  - `Macaw.Auth.Native.Sessions`: hashed session tokens, idle expiry,
    steps;
  - `Macaw.Auth.Native.UserRecord` and `Macaw.Auth.Native.SessionRecord`:
    the `macaw_auth_users` and `macaw_auth_sessions` schemas.

  **One refusal.** Whatever a source's reason, the caller sees
  `:invalid_credentials`, or `:disabled` for a disabled user who gave
  the right password, or `:throttled` while a wait runs. The specific
  reason, and the source, go to telemetry
  (`[:macaw_auth, :native, :authenticate]`) and to
  `mix macaw_auth.ldap.check`.

  The second factor (`Macaw.Auth.User`'s `second_factor`) arrives with its
  work item (#52); until then every native user's is `:none`.
  """

  @behaviour Macaw.Auth.Backend

  alias Macaw.Auth.Native.{Config, Sessions, Source, Throttle, UserRecord}
  alias Macaw.Auth.User

  @doc """
  Checks `%{username: _, password: _}` through the source chain:
  `{:ok, %Macaw.Auth.User{}}`, or `{:error, :invalid_credentials |
  :disabled | :throttled}`. Options: `:remote_ip` (a string or an address
  tuple; the client's, for the throttle's address key), `:now` (a
  `DateTime`, for the throttle's clock).

  **Throttled.** While the username or the address waits
  (`Macaw.Auth.Native.Throttle`), the password is not checked, but a
  hash's time is still spent (the hasher's `no_user_verify/0`), so a
  blocked attempt takes as long as a checked one and the response time
  doesn't tell a guesser when the block starts or ends. Every refusal
  counts as a failure; a success resets the username's count.

  Emits `[:macaw_auth, :native, :authenticate]` with `%{count: 1}` and
  `%{result: :ok | :error, reason: atom | nil, source: name | nil,
  user_id: id | nil}`; never the username or password.
  """
  @impl Macaw.Auth.Backend
  @spec authenticate(map(), keyword()) ::
          {:ok, User.t()} | {:error, :invalid_credentials | :disabled | :throttled}
  def authenticate(credentials, opts \\ []) do
    config = Config.get()
    username = text(credentials[:username])
    password = text(credentials[:password])
    key = throttle_key(username)
    ip = address(Keyword.get(opts, :remote_ip))
    now = clock(opts)

    case Throttle.check(key, ip, now) do
      {:delay, _ms} ->
        config.hasher.no_user_verify()
        event(:error, :throttled, nil, nil)
        {:error, :throttled}

      :ok ->
        case Source.run(config.sources, config.repo, username, password, opts) do
          {:ok, record, source} ->
            Throttle.success(key)
            event(:ok, nil, source, record.id)
            {:ok, to_user(record)}

          {:error, reason, source} ->
            Throttle.failure(key, ip, now)
            event(:error, reason, source, nil)
            {:error, if(reason == :disabled, do: :disabled, else: :invalid_credentials)}
        end
    end
  end

  defp text(value) when is_binary(value), do: value
  defp text(_), do: ""

  # The username as the user table stores it, so `Alice` and `alice ` share
  # a count; anything that can't be a username shares one key (it can never
  # sign in, so nobody is slowed by sharing it).
  defp throttle_key(username) do
    case UserRecord.normalize_username(username) do
      {:ok, name} -> name
      {:error, :invalid_username} -> :invalid
    end
  end

  defp address(nil), do: nil
  defp address(ip) when is_binary(ip), do: ip
  defp address(ip) when is_tuple(ip), do: ip |> :inet.ntoa() |> to_string()

  defp clock(opts) do
    case Keyword.get(opts, :now) do
      %DateTime{} = now -> DateTime.to_unix(now, :millisecond)
      nil -> Throttle.now()
    end
  end

  defp event(result, reason, source, user_id) do
    :telemetry.execute([:macaw_auth, :native, :authenticate], %{count: 1}, %{
      result: result,
      reason: reason,
      source: source && source.name,
      user_id: user_id
    })
  end

  @impl Macaw.Auth.Backend
  defdelegate create_session(user, opts), to: Sessions, as: :create

  @impl Macaw.Auth.Backend
  defdelegate fetch_session(token, opts), to: Sessions, as: :fetch

  @impl Macaw.Auth.Backend
  defdelegate fetch_session_by_id(id, opts), to: Sessions, as: :fetch_by_id

  @impl Macaw.Auth.Backend
  defdelegate list_sessions(user_id, opts), to: Sessions, as: :list

  @impl Macaw.Auth.Backend
  defdelegate revoke_sessions(target, opts), to: Sessions, as: :revoke

  @impl Macaw.Auth.Backend
  defdelegate complete_step(session_id, step, opts), to: Sessions

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
