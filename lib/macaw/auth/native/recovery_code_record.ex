defmodule Macaw.Auth.Native.RecoveryCodeRecord do
  @moduledoc """
  A row of `macaw_auth_recovery_codes`: one unspent recovery code of a
  user's second factor (`Macaw.Auth.Native.Totp`).

  - `code_hash` is the SHA-256 of the normalized code. The code itself is
    shown to the user once and never written: a copy of the table spends
    nothing. The codes are random (50 bits each), so an unsalted hash is
    as strong as the code.
  - A code is spent by deleting its row, conditionally (`DELETE … WHERE
    user_id = ? AND code_hash = ?`), so two submissions of one code can't
    both find it; `(user_id, code_hash)` is unique.
  - Deleting a user deletes their codes.

  A table rather than a column of the users row: spending one code is
  then a single-row delete that either happens or doesn't, where a list in
  a column would need a read, a change and a compare-and-set write of the
  whole list.
  """

  use Ecto.Schema

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec, updated_at: false]

  schema "macaw_auth_recovery_codes" do
    belongs_to(:user, Macaw.Auth.Native.UserRecord)
    field(:code_hash, :binary, redact: true)

    timestamps()
  end

  @type t :: %__MODULE__{}
end
