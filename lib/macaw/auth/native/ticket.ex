defmodule Macaw.Auth.Native.Ticket do
  @moduledoc """
  The enrollment ticket: what carries a second-factor enrollment between
  its pages, so that nothing unconfirmed is stored and no session exists
  before the second factor does.

  - **Its internal form is a term,** `%{account_id, purpose, issued_at,
    secret}`: the account's id, the purpose (`:owed`, an account that owes
    enrollment at sign-in and has no session; `:chosen`, a signed-in user
    choosing to enroll), the issue time (unix seconds) and the pending
    TOTP secret, itself sealed as it would be at rest
    (`Macaw.Auth.Native.Seal`, bound to the account), so a confirmation
    writes it to the row as it is.
  - **Sealed at the edge.** Only `issue/5`'s sealed bytes leave the
    process: the term, as `:erlang.term_to_binary/1`, sealed with
    `Macaw.Auth.Native.Seal` under the key derived from the configured
    `sealing_key` (`Macaw.Auth.Native.Seal.key!/1`, the caller's), its
    associated data `"macaw_auth enrollment_ticket"`, so neither a stored
    TOTP secret nor any other sealed value passes for a ticket.
  - **Ten minutes** (`ttl_seconds/0`), a constant: `open/3` refuses a
    ticket issued that long ago or longer.

  `open/3` gives `{:error, :invalid_ticket}` for anything it doesn't
  accept: tampered, sealed under another key, expired, not a ticket. The
  purpose, and the account's state, are its callers' to check
  (`Macaw.Auth.Native.Totp`).
  """

  alias Macaw.Auth.Native.Seal

  @ttl 600
  @aad "macaw_auth enrollment_ticket"
  @purposes [:owed, :chosen]

  @type purpose :: :owed | :chosen
  @type t :: %{
          account_id: Ecto.UUID.t(),
          purpose: purpose(),
          issued_at: integer(),
          secret: binary()
        }

  @doc "How long a ticket is accepted, in seconds: 600, a constant."
  @spec ttl_seconds() :: pos_integer()
  def ttl_seconds, do: @ttl

  @doc """
  Seals a ticket for `account_id` with `purpose`, issued at `now` (unix
  seconds), carrying `sealed_secret`, under `key` (`Macaw.Auth.Native.Seal.key!/1`):
  the bytes the client holds.
  """
  @spec issue(binary(), purpose(), Ecto.UUID.t(), binary(), integer()) :: binary()
  def issue(key, purpose, account_id, sealed_secret, now)
      when purpose in @purposes and is_binary(account_id) and is_binary(sealed_secret) and
             is_integer(now) do
    %{account_id: account_id, purpose: purpose, issued_at: now, secret: sealed_secret}
    |> :erlang.term_to_binary()
    |> Seal.seal(key, @aad)
  end

  @doc """
  Opens a ticket under `key` at `now` (unix seconds): `{:ok, ticket}`, the term, or
  `{:error, :invalid_ticket}` when it doesn't authenticate, isn't a
  ticket, or was issued `ttl_seconds/0` or more before `now`.
  """
  @spec open(binary(), term(), integer()) :: {:ok, t()} | {:error, :invalid_ticket}
  def open(key, ticket, now) when is_binary(ticket) and is_integer(now) do
    with {:ok, plain} <- Seal.unseal(ticket, key, @aad),
         # Authenticated, so it is a term this module made: decoding it
         # can't meet a stranger's bytes.
         %{account_id: id, purpose: purpose, issued_at: at, secret: secret} = term
         when is_binary(id) and purpose in @purposes and is_integer(at) and is_binary(secret) <-
           :erlang.binary_to_term(plain, [:safe]),
         true <- now < at + @ttl do
      {:ok, term}
    else
      _refused -> {:error, :invalid_ticket}
    end
  end

  def open(_key, _ticket, _now), do: {:error, :invalid_ticket}
end
