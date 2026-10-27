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
  - `Macaw.Auth.Native.Totp`: the second factor, TOTP and recovery codes,
    its secret sealed at rest (`Macaw.Auth.Native.Seal`);
  - `Macaw.Auth.Native.UserRecord`, `Macaw.Auth.Native.SessionRecord` and
    `Macaw.Auth.Native.RecoveryCodeRecord`: the `macaw_auth_users`,
    `macaw_auth_sessions` and `macaw_auth_recovery_codes` schemas.

  **One refusal.** Whatever a source's reason, the caller sees
  `:invalid_credentials`, or `:disabled` for a disabled user who gave
  the right password, or `:throttled` while a wait runs. The specific
  reason, and the source, go to telemetry
  (`[:macaw_auth, :native, :authenticate]`) and to
  `mix macaw_auth.ldap.check`.

  **The second factor.** A user's `second_factor` is `:enrolled` once they
  confirm a TOTP enrollment, else `:required` when policy
  (`totp_required`) requires one, else `:none`; `Macaw.Auth.pending_step/2`
  turns that into the step a session owes. The enrollment and
  verification functions here put every code check behind the throttle:
  a wrong code is a failure for the user's second-factor key and the
  client's address, with the same backoff as a wrong password, so six
  digits can't be guessed. The second factor's username key is its own
  (a password success doesn't reset it, or each sign-in would buy a
  guesser who has the password five more free guesses at the code); the
  address key is the one sign-in uses. Configure it with:

      config :macaw_auth, Macaw.Auth.Native,
        totp_issuer: "My App",
        totp_required: ["admin"],            # or true, or false (the default)
        sealing_key: {MyApp.Secrets, :sealing_key, []}
  """

  @behaviour Macaw.Auth.Backend

  alias Macaw.Auth.Native.{Config, Sessions, Source, Throttle, Totp, UserRecord}
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

  @doc "The idle limit, `session_idle_days` in seconds."
  @impl Macaw.Auth.Backend
  @spec session_idle_seconds(keyword()) :: pos_integer()
  def session_idle_seconds(_opts), do: Config.get().session_idle_days * 86_400

  @impl Macaw.Auth.Backend
  defdelegate list_sessions(user_id, opts), to: Sessions, as: :list

  @impl Macaw.Auth.Backend
  defdelegate revoke_sessions(target, opts), to: Sessions, as: :revoke

  @impl Macaw.Auth.Backend
  defdelegate complete_step(session_id, step, opts), to: Sessions

  # ── The second factor ─────────────────────────────────────────────────

  @doc """
  Checks a second-factor code (TOTP, or a recovery code) for the user of
  session `session_id`, behind the throttle; on success the session's
  `:second_factor` step is completed. `:ok`, or `{:error, :invalid_code |
  :throttled}`, or the session's own refusal (`:invalid | :expired |
  :disabled`). Options: `:remote_ip`, `:now`.
  """
  @impl Macaw.Auth.Backend
  @spec verify_second_factor(term(), term(), keyword()) ::
          :ok | {:error, :invalid_code | :throttled | :invalid | :expired | :disabled}
  def verify_second_factor(session_id, code, opts \\ []) do
    with {:ok, user, _session} <-
           Sessions.fetch_by_id(session_id, Keyword.put(opts, :touch, false)),
         :ok <- throttled(user, opts, fn -> Totp.verify(user, code, opts) end) do
      Sessions.complete_step(session_id, :second_factor, opts)
    end
  end

  @doc """
  Starts (or resumes) `user`'s TOTP enrollment: `{:ok, %{secret, uri}}`,
  the `otpauth://` URI for the page's QR code. Not active until
  `enroll_confirm/3`. See `Macaw.Auth.Native.Totp.enroll_begin/2`.
  """
  @spec enroll_begin(User.t(), keyword()) ::
          {:ok, %{secret: binary(), uri: String.t()}} | {:error, :already_enrolled | :not_found}
  def enroll_begin(%User{} = user, opts \\ []), do: Totp.enroll_begin(user, opts)

  @doc """
  Confirms the enrollment with a valid code, behind the throttle:
  `{:ok, recovery_codes}` to show once, or `{:error, :invalid_code |
  :throttled | :not_started | :already_enrolled}`. A session that owed
  `:second_factor_enroll` then completes it (`Macaw.Auth.Plug.complete_step/2`).
  """
  @spec enroll_confirm(User.t(), term(), keyword()) ::
          {:ok, [String.t()]}
          | {:error, :invalid_code | :throttled | :not_started | :already_enrolled}
  def enroll_confirm(%User{} = user, code, opts \\ []),
    do: throttled(user, opts, fn -> Totp.enroll_confirm(user, code, opts) end)

  @doc """
  The user turns their second factor off with a current code or a recovery
  code, behind the throttle: `:ok`, or `{:error, :invalid_code |
  :throttled | :required}`.
  """
  @spec disable(User.t(), term(), keyword()) ::
          :ok | {:error, :invalid_code | :throttled | :required}
  def disable(%User{} = user, code, opts \\ []),
    do: throttled(user, opts, fn -> Totp.disable(user, code, opts) end)

  @doc "An administrator clears a user's second factor and revokes their sessions."
  @spec admin_reset(User.t() | term(), keyword()) :: :ok
  defdelegate admin_reset(user, opts \\ []), to: Totp

  @doc "Replaces an enrolled user's recovery codes: `{:ok, codes}` or `{:error, :not_enrolled}`."
  @spec regenerate_recovery_codes(User.t(), keyword()) ::
          {:ok, [String.t()]} | {:error, :not_enrolled}
  defdelegate regenerate_recovery_codes(user, opts \\ []), to: Totp

  @doc "How many unspent recovery codes the user has."
  @spec recovery_codes_left(User.t() | term()) :: non_neg_integer()
  defdelegate recovery_codes_left(user), to: Totp

  # A code check behind the throttle: refused unchecked while the user's
  # second-factor key or the address waits; a wrong code is a failure, an
  # accepted one resets the user's key.
  defp throttled(%User{username: username}, opts, check) do
    key = {:second_factor, username}
    ip = address(Keyword.get(opts, :remote_ip))
    now = clock(opts)

    case Throttle.check(key, ip, now) do
      {:delay, _ms} ->
        {:error, :throttled}

      :ok ->
        case check.() do
          {:error, :invalid_code} = refused ->
            Throttle.failure(key, ip, now)
            refused

          {:error, _other} = error ->
            error

          success ->
            Throttle.success(key)
            success
        end
    end
  end

  @doc """
  A users row as the contract's `%Macaw.Auth.User{}`, its `second_factor`
  from the row and the configured policy.
  """
  @spec to_user(UserRecord.t()) :: User.t()
  def to_user(%UserRecord{} = r) do
    %User{
      second_factor: Totp.status(r, Config.get()),
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
