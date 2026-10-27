defmodule Macaw.Auth.Native.SessionRecord do
  @moduledoc """
  A row of `macaw_auth_sessions`, the native backend's sessions, in the
  host's repo (`mix macaw_auth.gen.migration` writes the table's
  migration, separate from the users').

  - `token_hash` is the SHA-256 of the session's token, unique. The token
    itself goes to the client and is never written anywhere: a copy of the
    table signs nobody in.
  - `user_id` references `macaw_auth_users`; deleting a user deletes their
    sessions.
  - `user_agent` is truncated to 255 characters, so a client can't make
    the row as large as it likes.
  - `completed_steps` holds step names as strings (`{:array, :string}`, a
    native array on Postgres and JSON text on SQLite). They become the
    contract's atoms only by lookup among `Macaw.Auth.steps/0`, so a row
    can never create an atom.
  - `last_used_at` is what idle expiry reads; a request writes it at most
    hourly (`Macaw.Auth.Native.Sessions`).
  """

  use Ecto.Schema

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "macaw_auth_sessions" do
    belongs_to(:user, Macaw.Auth.Native.UserRecord)
    field(:token_hash, :binary, redact: true)
    field(:remote_ip, :string)
    field(:user_agent, :string)
    field(:second_factor_passed, :boolean, default: true)
    field(:completed_steps, {:array, :string}, default: [])
    field(:last_used_at, :utc_datetime_usec)

    timestamps()
  end

  @type t :: %__MODULE__{}
end
