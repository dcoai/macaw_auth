defmodule Macaw.Auth.Native.ExternalId do
  @moduledoc """
  A directory user's external id at the Ecto edge: the `external_id`
  column of `macaw_auth_users` (`Macaw.Auth.Native.UserRecord`).

  The id is the binary the directory gave (an LDAP source's first
  `id_attr` value, or the entry's DN when it has none), whatever its
  bytes: an `entryUUID` is text, an `objectGUID` sixteen raw bytes. That
  binary is the id; the column holds one spelling of it, **lower-case
  hex of every byte, for every value**, so:

  - a value is never spelled two ways (raw when printable, hex otherwise
    could spell one id either way, and give `"00ff"` the directory's text
    and `<<0, 255>>` one spelling);
  - two distinct binaries never share a spelling, and reading one back
    (`decode/1`) gives exactly the directory's binary;
  - it is text every database stores, compares and indexes alike, needs
    no escaping in a query, and has no case or padding variants (as
    upper-case hex or Base64 would).

  Reading a spelling that isn't lower-case hex fails the load: a row
  written by anything else is a bug, surfaced, not a value guessed at.
  """

  use Ecto.Type

  @impl true
  def type, do: :string

  @impl true
  def cast(value) when is_binary(value), do: {:ok, value}
  def cast(_), do: :error

  @impl true
  def dump(value) when is_binary(value), do: {:ok, encode(value)}
  def dump(_), do: :error

  @impl true
  def load(spelling) when is_binary(spelling), do: decode(spelling)
  def load(_), do: :error

  @doc "The column's spelling of the directory's binary: lower-case hex."
  @spec encode(binary()) :: String.t()
  def encode(value) when is_binary(value), do: Base.encode16(value, case: :lower)

  @doc """
  The directory's binary from the column's spelling: `{:ok, binary}`, or
  `:error` for anything but lower-case hex.
  """
  @spec decode(String.t()) :: {:ok, binary()} | :error
  def decode(spelling) when is_binary(spelling), do: Base.decode16(spelling, case: :lower)
end
