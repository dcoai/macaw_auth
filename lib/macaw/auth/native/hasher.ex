defmodule Macaw.Auth.Native.Hasher do
  @moduledoc """
  How `Macaw.Auth.Native` hashes passwords: a behavior with two
  implementations, `Macaw.Auth.Native.Hasher.Bcrypt` and
  `Macaw.Auth.Native.Hasher.Argon2`. Each library is an optional
  dependency, and each implementation is compiled only when its library is,
  so a host carries only the NIF it chose.

      config :macaw_auth, Macaw.Auth.Native, hasher: Macaw.Auth.Native.Hasher.Argon2

  The default is Bcrypt. A configured hasher whose library is missing is
  refused when the configuration is read (`Macaw.Auth.Native.Config`),
  naming the dependency to add, never at the first sign-in.

  **Rehashing.** A stored hash is replaced at a successful sign-in when it
  `needs_rehash?/2`: made with other parameters (a raised bcrypt cost), or
  by the other algorithm. A hash carries its algorithm's prefix, so moving
  from bcrypt to argon2 needs no flag day: a bcrypt hash still verifies
  with bcrypt (when `:bcrypt_elixir` is still loaded) and is rehashed with
  argon2 on that user's next sign-in.

  **No enumeration.** `no_user_verify/0` spends a verification's time and
  returns false, so refusing an unknown user takes as long as refusing a
  wrong password.
  """

  @doc "A new hash of `password`, with the configured parameters."
  @callback hash(password :: String.t()) :: String.t()

  @doc "Whether `password` matches `hash` (constant time)."
  @callback verify(password :: String.t(), hash :: String.t()) :: boolean()

  @doc "Spends a verification's time and returns false."
  @callback no_user_verify() :: false

  @doc "Whether `hash`, one of this algorithm's, was made with other parameters than now."
  @callback needs_rehash?(hash :: String.t()) :: boolean()

  @doc "Whether `hash` is one of this algorithm's (by its prefix)."
  @callback owns?(hash :: String.t()) :: boolean()

  @known [Macaw.Auth.Native.Hasher.Bcrypt, Macaw.Auth.Native.Hasher.Argon2]

  @doc """
  Whether `module` can hash here: compiled (its library is loaded) and
  implementing this behavior, every callback of it. `:ok` or
  `{:error, message}`.
  """
  @spec check(module()) :: :ok | {:error, String.t()}
  def check(module) when is_atom(module) do
    cond do
      Code.ensure_loaded?(module) and hasher?(module) ->
        :ok

      module == Macaw.Auth.Native.Hasher.Bcrypt ->
        {:error, missing(module, ~s({:bcrypt_elixir, "~> 3.2"}))}

      module == Macaw.Auth.Native.Hasher.Argon2 ->
        {:error, missing(module, ~s({:argon2_elixir, "~> 4.1"}))}

      true ->
        {:error, "hasher: #{inspect(module)} is not a Macaw.Auth.Native.Hasher"}
    end
  end

  def check(other), do: {:error, "hasher: must be a module, got #{inspect(other)}"}

  # Every callback, not just `hash/1`: a module that only hashes would fail
  # at the first sign-in instead of at boot.
  defp hasher?(module) do
    Enum.all?(__MODULE__.behaviour_info(:callbacks), fn {name, arity} ->
      function_exported?(module, name, arity)
    end)
  end

  defp missing(module, dep),
    do: "hasher: #{inspect(module)} needs its library; add #{dep} to the host's deps"

  @doc """
  Verifies `password` against a stored `hash` with whichever available
  algorithm made it. A hash no available algorithm owns (or none at all)
  spends the configured hasher's time and is false.
  """
  @spec verify(module(), String.t(), String.t() | nil) :: boolean()
  def verify(configured, password, hash) when is_binary(hash) do
    case owner(configured, hash) do
      {:ok, module} -> module.verify(password, hash)
      :error -> configured.no_user_verify()
    end
  end

  def verify(configured, _password, nil), do: configured.no_user_verify()

  @doc "Whether `hash` should be replaced by a `configured` one."
  @spec needs_rehash?(module(), String.t()) :: boolean()
  def needs_rehash?(configured, hash),
    do: not configured.owns?(hash) or configured.needs_rehash?(hash)

  # The configured hasher first, then any other available one.
  defp owner(configured, hash) do
    case Enum.find([configured | @known], &(check(&1) == :ok and &1.owns?(hash))) do
      nil -> :error
      module -> {:ok, module}
    end
  end
end
