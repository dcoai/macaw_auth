defmodule Macaw.Auth.Native.UserRecord do
  @moduledoc """
  A row of `macaw_auth_users`, the native backend's users, in the host's
  repo (`mix macaw_auth.gen.migration` writes the table's migration).

  - `username` is stored normalized (`normalize_username/1`: trimmed,
    lower case), with a unique index, so `Alice` and `alice ` are one
    user on every database without a case-insensitive collation.
  - `hashed_password` is nil for a directory user: the directory checks
    their password, and the `Password` source does not know them.
  - `source` names where the identity came from: `"local"` (the
    `Password` source) or an LDAP source's name, which owns the row and
    re-derives its roles at each sign-in.
  - `roles` is `{:array, :string}`: a native array on Postgres, and on
    SQLite a JSON text column, which ecto_sqlite3 encodes and decodes for
    an array field itself. One migration serves both; no query needs to
    look inside the list.
  - `disabled_at` set means refused, whatever the password.
  - `external_id` is a directory user's id, the binary the directory
    gave, stored in one spelling (`Macaw.Auth.Native.ExternalId`, added
    by its own migration); nil for a local user. Only
    `Macaw.Auth.Native.Provision` writes it: `changeset/2` never casts it.
  - `extra` holds what a source knows beyond these (an LDAP DN, email)
    and the host's own fields.

  - `totp_secret_sealed`, `totp_enabled_at`, `totp_last_step`: the second
    factor (`Macaw.Auth.Native.Totp`), added by their own migration. The
    secret is sealed (`Macaw.Auth.Native.Seal`), never stored as it is;
    an enrollment is pending while `totp_enabled_at` is nil; the last
    accepted step is what makes a code single-use. None of them is cast
    by `changeset/2`: only `Totp` writes them, each by a conditional
    update.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @timestamps_opts [type: :utc_datetime_usec]

  schema "macaw_auth_users" do
    field(:username, :string)
    field(:display_name, :string)
    field(:hashed_password, :string, redact: true)
    field(:source, :string, default: "local")
    field(:roles, {:array, :string}, default: [])
    field(:disabled_at, :utc_datetime_usec)
    field(:must_change_password, :boolean, default: false)
    field(:extra, :map, default: %{})
    field(:external_id, Macaw.Auth.Native.ExternalId)
    field(:totp_secret_sealed, :binary, redact: true)
    field(:totp_enabled_at, :utc_datetime_usec)
    field(:totp_last_step, :integer)

    timestamps()
  end

  @type t :: %__MODULE__{}

  @username ~r/\A[a-z0-9][a-z0-9._@+-]{0,63}\z/

  @doc """
  A username trimmed and lower-cased: `{:ok, name}`, or
  `{:error, :invalid_username}` unless it is 1–64 characters of
  `[a-z0-9._@+-]`, starting with a letter or digit. Nothing else is
  rewritten, so two distinct inputs never become one user.
  """
  @spec normalize_username(term()) :: {:ok, String.t()} | {:error, :invalid_username}
  def normalize_username(input) when is_binary(input) do
    name = input |> String.trim() |> String.downcase()
    if name =~ @username, do: {:ok, name}, else: {:error, :invalid_username}
  end

  def normalize_username(_), do: {:error, :invalid_username}

  @doc "A changeset for a new or changed user; the username is normalized."
  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :username,
      :display_name,
      :hashed_password,
      :source,
      :roles,
      :disabled_at,
      :must_change_password,
      :extra
    ])
    |> validate_required([:username, :source])
    |> normalize()
    |> unique_constraint(:username)
  end

  defp normalize(changeset) do
    case get_change(changeset, :username) do
      nil ->
        changeset

      name ->
        case normalize_username(name) do
          {:ok, name} -> put_change(changeset, :username, name)
          {:error, _} -> add_error(changeset, :username, "must be 1–64 of a-z 0-9 . _ @ + -")
        end
    end
  end
end
