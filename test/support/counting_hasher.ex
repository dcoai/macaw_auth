defmodule Macaw.Auth.Test.CountingHasher do
  @moduledoc """
  Bcrypt, telling the calling process each time it hashes, verifies, or
  spends a verification's time for no user: the timing guarantee checked
  as work done, which no scheduler can make flaky.
  """

  @behaviour Macaw.Auth.Native.Hasher

  alias Macaw.Auth.Native.Hasher.Bcrypt

  @impl true
  def hash(password), do: Bcrypt.hash(password)

  @impl true
  def verify(password, hash) do
    send(self(), {:hasher, :verify})
    Bcrypt.verify(password, hash)
  end

  @impl true
  def no_user_verify do
    send(self(), {:hasher, :no_user_verify})
    Bcrypt.no_user_verify()
  end

  @impl true
  def needs_rehash?(hash), do: Bcrypt.needs_rehash?(hash)

  @impl true
  def owns?(hash), do: Bcrypt.owns?(hash)
end
