defmodule Macaw.Auth.Native.Totp do
  @moduledoc """
  The native backend's second factor: TOTP and recovery codes (ported from
  exio's and macaw's `Accounts.Totp`, which are the same rules), on the
  `macaw_auth_users` row and in `macaw_auth_recovery_codes`.

  Call these through `Macaw.Auth.Native` (`verify_second_factor/3`,
  `enroll_second_factor/3`, `enroll_confirm/4`, `disable/3`), which puts
  every code check behind the throttle; the functions here don't throttle.

  - **RFC 6238**, through `NimbleTOTP`: SHA-1, six digits, 30-second
    steps; a 160-bit (20-byte) random secret; a code is accepted for the
    current step and one either side, so a clock a little off still
    works.
  - **A code works once.** The step a code was accepted for is stored
    (`totp_last_step`), and a code is accepted only for a later step. The
    write is conditional (`UPDATE … WHERE totp_last_step < step`,
    `claim_step/3`), so of two submissions of one code racing each other,
    the database lets exactly one through; the other updates no row and
    is refused. Codes are compared with `Plug.Crypto.secure_compare/2`.
  - **The secret is sealed** (`Macaw.Auth.Native.Seal`, AES-256-GCM under
    the configured `sealing_key`, bound to the user's id). It leaves this
    module only from `enroll_begin/3` and `enrollment/2`, for the
    enrollment page's QR code.
  - **Nothing unconfirmed is stored.** `enroll_begin/3` seals a fresh
    secret into an enrollment ticket (`Macaw.Auth.Native.Ticket`), which
    the client holds for ten minutes and which `enrollment/2` shows again
    on a reload; `enroll_confirm/3` with a valid code writes the secret to
    the row, enables it and returns ten recovery codes, shown once. A
    ticket is spent by the enrollment it completes: the account is then
    enrolled, and `open_ticket/3` refuses a ticket of an enrolled account.
  - **Recovery codes**: ten, each ten characters of an alphabet without
    look-alikes (no 0, O, 1 or I), shown in two groups of five
    (`ABCDE-FGHJK`), stored only as SHA-256, each spent by deleting its
    row conditionally. Regenerating replaces them all.
  - **Input** is normalized: spaces and dashes removed, letters upper
    case.
  - **Policy** (`totp_required`, `Macaw.Auth.Native.Config`) decides
    `status/2`: `:enrolled`, else `:required` when policy requires one,
    else `:none`.

  Every function honors `:now` (a `DateTime`). Telemetry
  `[:macaw_auth, :native, :second_factor]`: `%{count: 1}` with
  `%{event: :enrollment_started | :enrolled | :verified |
  :recovery_code_used | :refused | :disabled | :reset |
  :recovery_codes_regenerated, user_id: id}`; never a secret or a code.
  """

  import Ecto.Query

  alias Macaw.Auth.Native.{Config, RecoveryCodeRecord, Seal, Sessions, Ticket, UserRecord}
  alias Macaw.Auth.User

  @step 30
  @window [-1, 0, 1]
  @recovery_count 10
  @recovery_length 10
  @alphabet "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
  @symbols String.to_charlist(@alphabet)
  @max_input 64

  @type user :: User.t() | UserRecord.t() | Ecto.UUID.t()

  @doc "The six-digit code for `secret` at `time` (unix seconds or a `DateTime`)."
  @spec code(binary(), integer() | DateTime.t()) :: String.t()
  def code(secret, time), do: NimbleTOTP.verification_code(secret, time: time, period: @step)

  @doc "The step (`div(unix seconds, 30)`) a time falls in."
  @spec step(integer() | DateTime.t()) :: integer()
  def step(%DateTime{} = time), do: time |> DateTime.to_unix() |> step()
  def step(seconds) when is_integer(seconds), do: div(seconds, @step)

  # ── Policy ────────────────────────────────────────────────────────────

  @doc "Whether policy (`totp_required`) requires a second factor of this user."
  @spec required?(UserRecord.t(), Config.t()) :: boolean()
  def required?(%UserRecord{}, %Config{totp_required: required}) when is_boolean(required),
    do: required

  def required?(%UserRecord{roles: roles}, %Config{totp_required: required}),
    do: Enum.any?(roles || [], &(&1 in required))

  @doc "The contract's `second_factor` for a row: `:enrolled`, `:required` or `:none`."
  @spec status(UserRecord.t(), Config.t()) :: :none | :enrolled | :required
  def status(%UserRecord{totp_enabled_at: %DateTime{}}, _config), do: :enrolled

  def status(record, config),
    do: if(required?(record, config), do: :required, else: :none)

  # ── Enrollment ────────────────────────────────────────────────────────

  @doc """
  Begins an enrollment: a fresh secret, sealed into a ticket
  (`Macaw.Auth.Native.Ticket`) and **stored nowhere**:
  `{:ok, %{ticket: binary, secret: binary, uri: otpauth}}` (the URI for a
  QR code, its label `issuer:username`). Nothing changes at sign-in, or
  in any table, until `enroll_confirm/3`; a reload shows the ticket's
  secret again (`enrollment/2`).

  `purpose` is `:owed` (an account that owes enrollment at sign-in: it
  must be enabled and `:required`, else `{:error, :not_required}`) or
  `:chosen` (a user choosing to enroll). Otherwise `{:error, :not_found |
  :disabled | :already_enrolled}`.
  """
  @spec enroll_begin(user(), Ticket.purpose(), keyword()) ::
          {:ok, %{ticket: binary(), secret: binary(), uri: String.t()}}
          | {:error, :not_found | :disabled | :already_enrolled | :not_required}
  def enroll_begin(user, purpose, opts \\ []) when purpose in [:owed, :chosen] do
    config = Config.get()

    with {:ok, record} <- eligible(config, load(config, user), purpose) do
      key = Seal.key!(config.sealing_key)
      secret = NimbleTOTP.secret(20)
      sealed = Seal.seal(secret, key, aad(record.id))
      ticket = Ticket.issue(key, purpose, record.id, sealed, now(opts))
      event(:enrollment_started, record.id)
      {:ok, Map.put(enrollment(config, record, secret), :ticket, ticket)}
    end
  end

  # Who may hold a ticket: an enabled account not enrolled, and for one
  # owed at sign-in, one that policy still requires to enroll.
  defp eligible(_config, nil, _purpose), do: {:error, :not_found}
  defp eligible(_config, %UserRecord{disabled_at: %DateTime{}}, _purpose), do: {:error, :disabled}

  defp eligible(_config, %UserRecord{totp_enabled_at: %DateTime{}}, _purpose),
    do: {:error, :already_enrolled}

  defp eligible(config, record, :owed),
    do: if(required?(record, config), do: {:ok, record}, else: {:error, :not_required})

  defp eligible(_config, record, :chosen), do: {:ok, record}

  @doc """
  Opens a ticket whose purpose is one of `purposes`: `{:ok, ticket,
  record}`, the ticket's term and its account's row, or
  `{:error, :invalid_ticket}` for one tampered, expired, of another
  purpose, or whose account is gone, disabled, enrolled since (a ticket is
  spent by the enrollment it completes) or, for `:owed`, no longer
  required to enroll. Option `:now`.
  """
  @spec open_ticket(term(), [Ticket.purpose()], keyword()) ::
          {:ok, Ticket.t(), UserRecord.t()} | {:error, :invalid_ticket}
  def open_ticket(ticket, purposes, opts \\ []) do
    config = Config.get()

    with {:ok, %{purpose: purpose} = term} <-
           Ticket.open(Seal.key!(config.sealing_key), ticket, now(opts)),
         true <- purpose in purposes,
         {:ok, record} <- eligible(config, load(config, term.account_id), purpose) do
      {:ok, term, record}
    else
      _refused -> {:error, :invalid_ticket}
    end
  end

  @doc """
  What an enrollment page shows of a ticket of either purpose:
  `{:ok, %{secret, uri}}`, or `{:error, :invalid_ticket}` as
  `open_ticket/3` refuses one. Option `:now`.
  """
  @spec enrollment(term(), keyword()) ::
          {:ok, %{secret: binary(), uri: String.t()}} | {:error, :invalid_ticket}
  def enrollment(ticket, opts \\ []) do
    config = Config.get()

    with {:ok, term, record} <- open_ticket(ticket, [:owed, :chosen], opts) do
      {:ok, enrollment(config, record, unseal!(config, record.id, term.secret))}
    end
  end

  defp enrollment(config, record, secret) do
    label = config.totp_issuer <> ":" <> record.username
    %{secret: secret, uri: NimbleTOTP.otpauth_uri(label, secret, issuer: config.totp_issuer)}
  end

  @doc """
  Confirms an opened ticket (`open_ticket/3`) with a valid code for its
  secret: `{:ok, recovery_codes}` (shown once; never retrievable again),
  the ticket's sealed secret written to the row with `totp_enabled_at`
  and the code's step, so the confirming code can't then sign in. Or
  `{:error, :invalid_code}`, or `{:error, :invalid_ticket}` when the
  account was enrolled or disabled meanwhile: the write is conditional on
  neither, so of two confirmations of one ticket racing, one enrolls.
  """
  @spec enroll_confirm({Ticket.t(), UserRecord.t()}, term(), keyword()) ::
          {:ok, [String.t()]} | {:error, :invalid_code | :invalid_ticket}
  def enroll_confirm({%{secret: sealed}, %UserRecord{} = record}, code, opts \\ []) do
    config = Config.get()

    with {:ok, step} <-
           matching_step(unseal!(config, record.id, sealed), totp(code), now(opts), nil) do
      confirm(config.repo, record, sealed, step, opts)
    end
  end

  defp confirm(repo, record, sealed, step, opts) do
    query =
      where(
        UserRecord,
        [u],
        u.id == ^record.id and is_nil(u.totp_enabled_at) and is_nil(u.disabled_at)
      )

    repo.transaction(fn ->
      case repo.update_all(query,
             set: [
               totp_secret_sealed: sealed,
               totp_enabled_at: timestamp(opts),
               totp_last_step: step
             ]
           ) do
        {1, _} -> replace_recovery_codes(repo, record.id, opts)
        {0, _} -> repo.rollback(:invalid_ticket)
      end
    end)
    |> case do
      {:ok, codes} ->
        event(:enrolled, record.id)
        {:ok, codes}

      {:error, :invalid_ticket} ->
        {:error, :invalid_ticket}
    end
  end

  # ── Verification ──────────────────────────────────────────────────────

  @doc """
  Checks a TOTP code or an unspent recovery code of an enrolled user. `:ok`
  spends it: the step, or the recovery code, never works again. Otherwise
  `{:error, :invalid_code}`, the same whatever was wrong (not enrolled, a
  wrong code, a replayed one).
  """
  @spec verify(user(), term(), keyword()) :: :ok | {:error, :invalid_code}
  def verify(user, code, opts \\ []) do
    %Config{repo: repo} = config = Config.get()

    case load(config, user) do
      %UserRecord{totp_enabled_at: %DateTime{}} = record ->
        result =
          case kind(code) do
            {:totp, code} -> verify_totp(config, record, code, now(opts))
            {:recovery, code} -> spend_recovery_code(repo, record.id, code)
            :invalid -> {:error, :invalid_code}
          end

        event(if(result == :ok, do: :verified, else: :refused), record.id)
        result

      _not_enrolled ->
        {:error, :invalid_code}
    end
  end

  defp verify_totp(config, record, code, now) do
    with {:ok, step} <-
           matching_step(
             unseal!(config, record.id, record.totp_secret_sealed),
             code,
             now,
             record.totp_last_step
           ),
         :ok <- claim_step(config.repo, record.id, step) do
      :ok
    else
      _ -> {:error, :invalid_code}
    end
  end

  @doc """
  Records `step` as the user's last accepted one, only if it is later than
  the one stored: `:ok`, or `:replayed` when it isn't (another submission
  of the same code, or of an earlier one, got there first). The guard is
  the update's own `WHERE`, so it holds however many callers race.
  """
  @spec claim_step(module(), Ecto.UUID.t(), integer()) :: :ok | :replayed
  def claim_step(repo, user_id, step) do
    query =
      from(u in UserRecord,
        where:
          u.id == ^user_id and not is_nil(u.totp_enabled_at) and
            (is_nil(u.totp_last_step) or u.totp_last_step < ^step)
      )

    case repo.update_all(query, set: [totp_last_step: step]) do
      {1, _} -> :ok
      {0, _} -> :replayed
    end
  end

  # The first step in the window, later than `last`, whose code matches.
  # Every candidate is compared, in constant time each.
  defp matching_step(_secret, :invalid, _now, _last), do: {:error, :invalid_code}

  defp matching_step(secret, code, now, last) do
    current = step(now)

    @window
    |> Enum.map(&(current + &1))
    |> Enum.filter(
      &(Plug.Crypto.secure_compare(code(secret, &1 * @step), code) and later?(&1, last))
    )
    |> case do
      [step | _] -> {:ok, step}
      [] -> {:error, :invalid_code}
    end
  end

  defp later?(_step, nil), do: true
  defp later?(step, last), do: step > last

  defp spend_recovery_code(repo, user_id, code) do
    query =
      where(RecoveryCodeRecord, [c], c.user_id == ^user_id and c.code_hash == ^hash(code))

    case repo.delete_all(query) do
      {1, _} ->
        event(:recovery_code_used, user_id)
        :ok

      {0, _} ->
        {:error, :invalid_code}
    end
  end

  # What a submission is, after normalizing: six digits, a recovery code,
  # or neither.
  defp kind(code) do
    code = normalize(code)

    cond do
      code =~ ~r/\A[0-9]{6}\z/ -> {:totp, code}
      byte_size(code) == @recovery_length and recovery?(code) -> {:recovery, code}
      true -> :invalid
    end
  end

  defp totp(code) do
    case kind(code) do
      {:totp, code} -> code
      _ -> :invalid
    end
  end

  defp recovery?(code), do: code |> :binary.bin_to_list() |> Enum.all?(&(&1 in @symbols))

  @doc "A submitted code with spaces and dashes removed and letters upper case."
  @spec normalize(term()) :: String.t()
  def normalize(code) when is_binary(code) and byte_size(code) <= @max_input,
    do: code |> String.replace(~r/[\s-]/u, "") |> String.upcase()

  def normalize(_), do: ""

  # ── Recovery codes ────────────────────────────────────────────────────

  @doc "How many unspent recovery codes the user has."
  @spec recovery_codes_left(user()) :: non_neg_integer()
  def recovery_codes_left(user) do
    %Config{repo: repo} = Config.get()

    case uuid(user) do
      {:ok, id} -> repo.aggregate(where(RecoveryCodeRecord, user_id: ^id), :count)
      :error -> 0
    end
  end

  @doc """
  Replaces an enrolled user's recovery codes: `{:ok, codes}` (the new
  ones, shown once; the old ones no longer work), or
  `{:error, :not_enrolled}`.
  """
  @spec regenerate_recovery_codes(user(), keyword()) ::
          {:ok, [String.t()]} | {:error, :not_enrolled}
  def regenerate_recovery_codes(user, opts \\ []) do
    %Config{repo: repo} = config = Config.get()

    case load(config, user) do
      %UserRecord{totp_enabled_at: %DateTime{}} = record ->
        {:ok, codes} = repo.transaction(fn -> replace_recovery_codes(repo, record.id, opts) end)
        event(:recovery_codes_regenerated, record.id)
        {:ok, codes}

      _ ->
        {:error, :not_enrolled}
    end
  end

  defp replace_recovery_codes(repo, user_id, opts) do
    repo.delete_all(where(RecoveryCodeRecord, user_id: ^user_id))
    at = timestamp(opts)
    codes = for _ <- 1..@recovery_count, do: recovery_code()

    {@recovery_count, _} =
      repo.insert_all(
        RecoveryCodeRecord,
        for(
          code <- codes,
          do: %{
            id: Ecto.UUID.generate(),
            user_id: user_id,
            code_hash: hash(code),
            inserted_at: at
          }
        )
      )

    Enum.map(codes, &(binary_part(&1, 0, 5) <> "-" <> binary_part(&1, 5, 5)))
  end

  # 32 symbols, so a random byte's low five bits pick one without bias.
  defp recovery_code do
    for <<byte <- :crypto.strong_rand_bytes(@recovery_length)>>,
      into: "",
      do: binary_part(@alphabet, rem(byte, 32), 1)
  end

  # ── Disabling ─────────────────────────────────────────────────────────

  @doc """
  The user turns their second factor off, proving it with a current code
  or a recovery code: `:ok` (the secret and recovery codes are deleted), or
  `{:error, :invalid_code | :required}`, `:required` when policy requires
  one (an administrator's `admin_reset/2` then).
  """
  @spec disable(user(), term(), keyword()) :: :ok | {:error, :invalid_code | :required}
  def disable(user, code, opts \\ []) do
    %Config{repo: repo} = config = Config.get()

    case load(config, user) do
      %UserRecord{totp_enabled_at: %DateTime{}} = record ->
        cond do
          required?(record, config) ->
            {:error, :required}

          verify(record.id, code, opts) == :ok ->
            clear(repo, record.id)
            event(:disabled, record.id)
            :ok

          true ->
            {:error, :invalid_code}
        end

      _not_enrolled ->
        {:error, :invalid_code}
    end
  end

  @doc """
  An administrator clears a user's second factor (a lost device) and
  revokes every session of theirs
  (`Macaw.Auth.Native.Sessions.revoke_all/3`, so their open pages
  disconnect): they sign in again, and enroll again if policy requires.
  `:ok`. Option `:announce` (default `true`): `false` revokes without
  telling open pages, for a process that is not the app's node.
  """
  @spec admin_reset(user(), keyword()) :: :ok
  def admin_reset(user, opts \\ []) do
    %Config{repo: repo} = Config.get()

    case uuid(user) do
      {:ok, id} ->
        clear(repo, id)
        :ok = Sessions.revoke_all(id, :second_factor_reset, opts)
        event(:reset, id)
        :ok

      :error ->
        :ok
    end
  end

  defp clear(repo, id) do
    {:ok, _} =
      repo.transaction(fn ->
        repo.update_all(where(UserRecord, id: ^id),
          set: [totp_secret_sealed: nil, totp_enabled_at: nil, totp_last_step: nil]
        )

        repo.delete_all(where(RecoveryCodeRecord, user_id: ^id))
      end)

    :ok
  end

  # ── Helpers ───────────────────────────────────────────────────────────

  defp load(%Config{repo: repo}, user) do
    case uuid(user) do
      {:ok, id} -> repo.get(UserRecord, id)
      :error -> nil
    end
  end

  defp uuid(%User{id: id}), do: Ecto.UUID.cast(id)
  defp uuid(%UserRecord{id: id}), do: Ecto.UUID.cast(id)
  defp uuid(id), do: Ecto.UUID.cast(id)

  defp aad(user_id), do: "macaw_auth totp_secret " <> user_id

  # A secret that doesn't unseal is an operator's fault (the key changed),
  # not a wrong code: raised, naming it, so it is seen rather than every
  # enrolled user being silently refused.
  defp unseal!(config, user_id, sealed) do
    case Seal.unseal(sealed, Seal.key!(config.sealing_key), aad(user_id)) do
      {:ok, secret} ->
        secret

      {:error, :wrong_key} ->
        raise Macaw.Auth.Native.SealingKeyError,
              "a stored TOTP secret does not unseal with the configured sealing_key: " <>
                "the key has changed since it was sealed, or the row was altered"
    end
  end

  defp hash(code), do: :crypto.hash(:sha256, code)

  defp now(opts) do
    case Keyword.get(opts, :now) do
      %DateTime{} = now -> DateTime.to_unix(now)
      nil -> System.os_time(:second)
    end
  end

  defp timestamp(opts) do
    %DateTime{microsecond: {us, _}} = now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)
    %{now | microsecond: {us, 6}}
  end

  defp event(event, user_id) do
    :telemetry.execute([:macaw_auth, :native, :second_factor], %{count: 1}, %{
      event: event,
      user_id: user_id
    })
  end
end
