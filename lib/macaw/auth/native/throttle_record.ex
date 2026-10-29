defmodule Macaw.Auth.Native.ThrottleRecord do
  @moduledoc """
  A row of `macaw_auth_throttle`: one key's sign-in failures
  (`Macaw.Auth.Native.Throttle`), in the host's repo, so a restart of the
  node forgets nothing.

  - A key is a term (`Macaw.Auth.Native.Throttle.key/0`); its columns are
    this module's encoding of it, `kind` and `subject`, and nothing reads
    them but `columns/1` and `key/2`. `(kind, subject)` is unique: what a
    check, a failure's upsert and a success look up.
  - `failures` is the count since the key's last reset, and
    `last_failure_ms` the latest failure's time, in milliseconds of the
    system clock; it is indexed, for the sweep.
  - An account's key holds its id, not its username, so a rename keeps
    the count. No foreign key: a deleted account's row is swept within a
    day, and an address or a name has no row to reference.
  """

  use Ecto.Schema

  @primary_key false

  schema "macaw_auth_throttle" do
    field(:kind, :string)
    field(:subject, :string)
    field(:failures, :integer)
    field(:last_failure_ms, :integer)
  end

  @type t :: %__MODULE__{}

  @doc "A key's `{kind, subject}` columns."
  @spec columns(Macaw.Auth.Native.Throttle.key()) :: {String.t(), String.t()}
  def columns({:user, {:account, id}}), do: {"account", id}
  def columns({:user, {:second_factor, id}}), do: {"second_factor", id}
  def columns({:user, {:name, name}}), do: {"name", name}
  def columns({:user, :invalid}), do: {"invalid", ""}
  def columns({:ip, address}), do: {"address", address}

  @doc "The key a row's `kind` and `subject` encode: `columns/1` reversed."
  @spec key(String.t(), String.t()) :: Macaw.Auth.Native.Throttle.key()
  def key("account", id), do: {:user, {:account, id}}
  def key("second_factor", id), do: {:user, {:second_factor, id}}
  def key("name", name), do: {:user, {:name, name}}
  def key("invalid", ""), do: {:user, :invalid}
  def key("address", address), do: {:ip, address}
end
