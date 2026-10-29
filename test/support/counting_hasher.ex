defmodule Macaw.Auth.Test.CountingHasher do
  @moduledoc """
  Bcrypt, telling the calling process each time it hashes, verifies, or
  spends a verification's time for no user: the timing guarantee checked
  as work done, which no scheduler can make flaky.

  "Takes the same time" is checked by what runs, never by timing two runs
  (#15): elapsed time on a shared runner measures the runner. A
  verification (`verify/2`, one bcrypt at the stored hash's cost) and a
  verification against nothing (`no_user_verify/0`, one bcrypt hash at the
  configured cost) are the same bcrypt work when the stored hash was made
  at the configured cost, so two attempts that each do exactly one of them,
  and nothing else, cost the same.
  """

  @behaviour Macaw.Auth.Native.Hasher

  alias Macaw.Auth.Native.Hasher.Bcrypt

  @impl true
  def hash(password) do
    send(self(), {:hasher, :hash})
    Bcrypt.hash(password)
  end

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

  @doc """
  The hasher work `fun` does: every call it makes, in order. Calls made
  before `fun` runs are discarded first, so the list is `fun`'s alone.
  """
  @spec work((-> any())) :: [:hash | :verify | :no_user_verify]
  def work(fun) do
    calls()
    fun.()
    calls()
  end

  defp calls do
    receive do
      {:hasher, call} -> [call | calls()]
    after
      0 -> []
    end
  end
end
