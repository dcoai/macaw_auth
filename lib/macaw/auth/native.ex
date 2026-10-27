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

  import Ecto.Query, only: [order_by: 2]

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
  doesn't tell a guesser when the block starts or ends. A throttled
  refusal is not counted; every checked refusal counts as a failure, and
  a success resets the username's count.

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

  @doc """
  Reads and checks the configuration, and keeps it
  (`Macaw.Auth.Native.Config.load!/0`): `:ok`, or
  `Macaw.Auth.Native.Config.Error` naming the fault. The application
  calls it at start, so a bad configuration refuses boot.
  """
  @impl Macaw.Auth.Backend
  @spec check_config!() :: :ok
  def check_config! do
    %Config{} = Config.load!()
    :ok
  end

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

  @doc """
  An administrator clears a user's second factor and revokes their sessions,
  telling their open pages unless option `announce: false`
  (`Macaw.Auth.Native.Totp.admin_reset/2`).
  """
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

  # ── Administering users ───────────────────────────────────────────────
  #
  # What `mix macaw_auth.user` and the release entry points
  # (`Macaw.Auth.Native.UserCommands`) run. Users are named by username, as
  # typed: trimmed and lower-cased like sign-in's.

  @doc """
  Makes the first user, a local one with role `:role`, **only when no user
  exists**: `{:ok, record}` when it made one, `:exists` when any user is
  there (local or a directory's, whoever it is), so it is safe to call at
  every boot. Takes `:username`, `:password` and `:role`, and optionally
  `:display_name` and `:must_change_password`.

  With no user yet, the password and the role are required:
  `{:error, :no_password}`, `{:error, :no_role}`, or `{:error, changeset}`
  (an invalid username). When users exist neither is looked at, so a host
  may stop providing the password once its admin exists.

  Two first boots at once with the same username make one user: the other
  call's insert meets the unique index and answers `:exists`.
  """
  @spec bootstrap_admin(map()) ::
          {:ok, UserRecord.t()} | :exists | {:error, :no_password | :no_role | Ecto.Changeset.t()}
  def bootstrap_admin(attrs) when is_map(attrs) do
    %Config{repo: repo} = Config.get()

    cond do
      repo.exists?(UserRecord) -> :exists
      not filled?(attrs[:password]) -> {:error, :no_password}
      not filled?(attrs[:role]) -> {:error, :no_role}
      true -> bootstrap_insert(attrs)
    end
  end

  defp bootstrap_insert(attrs) do
    user =
      attrs
      |> Map.take([:username, :password, :display_name, :must_change_password])
      |> Map.put(:roles, [attrs.role])

    case create_user(user) do
      {:ok, record} ->
        {:ok, record}

      {:error, changeset} ->
        if taken?(changeset), do: :exists, else: {:error, changeset}
    end
  end

  defp filled?(value), do: is_binary(value) and value != ""

  defp taken?(%Ecto.Changeset{errors: errors}) do
    case errors[:username] do
      {_message, opts} -> opts[:constraint] == :unique
      nil -> false
    end
  end

  @doc "Every user, local and directory, by username."
  @spec list_users() :: [UserRecord.t()]
  def list_users do
    %Config{repo: repo} = Config.get()
    repo.all(order_by(UserRecord, :username))
  end

  @doc """
  The user named `username` (trimmed and lower-cased, as sign-in matches
  it), or nil, also for a string that can't be a username.
  """
  @spec get_user(term()) :: UserRecord.t() | nil
  def get_user(username) do
    case UserRecord.normalize_username(username) do
      {:ok, name} -> Config.get().repo.get_by(UserRecord, username: name)
      {:error, :invalid_username} -> nil
    end
  end

  @doc """
  Disables a user: their sign-in is refused, and each of their sessions at
  its next look-up (`Macaw.Auth.Native.Sessions`), so open pages leave at
  their next re-check. A user already disabled keeps when it was first
  done. `{:ok, record}` or `{:error, :not_found}`.
  """
  @spec disable_user(String.t()) :: {:ok, UserRecord.t()} | {:error, :not_found}
  def disable_user(username) do
    with {:ok, record} <- fetch_user(username) do
      case record.disabled_at do
        nil -> update(record, %{disabled_at: DateTime.utc_now()})
        %DateTime{} -> {:ok, record}
      end
    end
  end

  @doc "Enables a disabled user again: `{:ok, record}` or `{:error, :not_found}`."
  @spec enable_user(String.t()) :: {:ok, UserRecord.t()} | {:error, :not_found}
  def enable_user(username) do
    with {:ok, record} <- fetch_user(username), do: update(record, %{disabled_at: nil})
  end

  @doc """
  Replaces a local user's password, hashed with the configured hasher, and
  revokes every session of theirs (reason `:password_changed`), so whoever
  held the old one is signed out. `{:ok, record}`, or `{:error, :not_found
  | :not_local | :no_password}`: a directory user's password is the
  directory's, and is never set here.

  Option `:announce` (default `true`): tell the user's open pages, which
  disconnect (`Macaw.Auth.announce_revoked/2`). A process that is not the
  app's node, such as a release's `eval` or a mix task, passes `false`:
  there is no page there to tell, and the pages leave at their next
  re-check.
  """
  @spec set_password(String.t(), term(), keyword()) ::
          {:ok, UserRecord.t()} | {:error, :not_found | :not_local | :no_password}
  def set_password(username, password, opts \\ []) do
    config = Config.get()

    with {:ok, record} <- fetch_user(username),
         :ok <- local(config, record),
         :ok <- if(filled?(password), do: :ok, else: {:error, :no_password}),
         {:ok, record} <- update(record, %{hashed_password: config.hasher.hash(password)}) do
      :ok = Sessions.revoke_all(record.id, :password_changed, opts)
      {:ok, record}
    end
  end

  @doc """
  Replaces a local user's roles with `roles`, a list of non-empty strings:
  `{:ok, record}`, or `{:error, :not_found | :not_local | :invalid_roles}`.
  A directory user's roles are re-derived from the directory at each
  sign-in (`Macaw.Auth.Native.Provision`), so they are never set here.
  """
  @spec set_roles(String.t(), [String.t()]) ::
          {:ok, UserRecord.t()} | {:error, :not_found | :not_local | :invalid_roles}
  def set_roles(username, roles) do
    with :ok <- if(roles?(roles), do: :ok, else: {:error, :invalid_roles}),
         {:ok, record} <- fetch_user(username),
         :ok <- local(Config.get(), record) do
      update(record, %{roles: roles})
    end
  end

  defp roles?(roles), do: is_list(roles) and Enum.all?(roles, &filled?/1)

  defp fetch_user(username) do
    case get_user(username) do
      %UserRecord{} = record -> {:ok, record}
      nil -> {:error, :not_found}
    end
  end

  defp local(config, %UserRecord{source: source}),
    do: if(source == local_name(config), do: :ok, else: {:error, :not_local})

  # A changeset of a row that loaded, with values checked above, can only
  # fail through a bug: raised.
  defp update(record, changes),
    do: {:ok, record |> Ecto.Changeset.change(changes) |> Config.get().repo.update!()}
end
