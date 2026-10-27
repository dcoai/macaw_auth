defmodule Macaw.Auth.Native.Source.Password do
  @moduledoc """
  Local users: a `macaw_auth_users` row with a password hash.

      %{type: :password}                 # named "local"
      %{type: :password, name: "staff"}

  It knows a user when their row has a password hash; a directory user's
  row (no hash) is not its to judge, and the attempt passes on.

  - An unknown user and a wrong password are one refusal,
    `:invalid_credentials`, and take the same time: an unknown user spends
    the hasher's `no_user_verify/0`, so the response time can't tell which
    usernames exist.
  - The password is checked before the account's state, so `:disabled` is
    only ever said to someone who knows the password.
  - A hash made with other parameters, or by the other algorithm, is
    replaced at a successful sign-in (`Macaw.Auth.Native.Hasher`).
  """

  @behaviour Macaw.Auth.Native.Source

  alias Macaw.Auth.Native.{Hasher, Settings, UserRecord}

  @enforce_keys [:name, :repo, :hasher]
  defstruct [:name, :repo, :hasher]

  @type t :: %__MODULE__{name: String.t(), repo: module(), hasher: module()}

  @keys [:type, :name]

  @impl true
  def parse(config, context) do
    config = Settings.normalize(config, @keys)

    with {:ok, name} <- Settings.name(config, "local"),
         :ok <- Settings.known_keys(config, @keys, name) do
      {:ok,
       %__MODULE__{
         name: name,
         repo: Keyword.fetch!(context, :repo),
         hasher: Keyword.fetch!(context, :hasher)
       }}
    end
  end

  @impl true
  def authenticate(%__MODULE__{} = source, username, password, _opts) do
    password = if is_binary(password), do: password, else: ""

    with {:ok, name} <- UserRecord.normalize_username(username),
         %UserRecord{hashed_password: hash} = record when is_binary(hash) <-
           source.repo.get_by(UserRecord, username: name) do
      cond do
        not Hasher.verify(source.hasher, password, hash) -> {:error, :invalid_credentials}
        record.disabled_at != nil -> {:error, :disabled}
        true -> {:ok, %{record: rehash(source, record, password)}}
      end
    else
      _unknown ->
        source.hasher.no_user_verify()
        {:error, :no_user}
    end
  end

  # The row loaded and the hash is new, so a failed update is a bug: raised.
  defp rehash(source, record, password) do
    if Hasher.needs_rehash?(source.hasher, record.hashed_password) do
      record
      |> Ecto.Changeset.change(hashed_password: source.hasher.hash(password))
      |> source.repo.update!()
    else
      record
    end
  end

  @impl true
  def knows?(_source, :no_user), do: false
  def knows?(_source, _reason), do: true

  @impl true
  def explain(:no_user), do: "no local user with a password has that username"
  def explain(:invalid_credentials), do: "the password is wrong"
  def explain(:disabled), do: "the user is disabled"
end
