if Code.ensure_loaded?(Argon2) do
  defmodule Macaw.Auth.Native.Hasher.Argon2 do
    @moduledoc """
    Argon2 (`:argon2_elixir`), compiled only when that library is loaded.
    The parameters are argon2_elixir's own settings (`config :argon2_elixir,
    t_cost: 3, m_cost: 16, parallelism: 4, argon2_type: 2`); a hash made
    with others is rehashed at sign-in.
    """

    @behaviour Macaw.Auth.Native.Hasher

    @impl true
    def hash(password), do: Argon2.hash_pwd_salt(password)

    @impl true
    def verify(password, hash), do: Argon2.verify_pass(password, hash)

    @impl true
    def no_user_verify, do: Argon2.no_user_verify()

    # "$argon2id$v=19$m=65536,t=3,p=4$salt$hash": the type and parameters.
    @impl true
    def needs_rehash?(hash) do
      case String.split(hash, "$") do
        ["", type, _version, params | _] -> {type, params} != expected()
        _ -> true
      end
    end

    @impl true
    def owns?(hash), do: String.starts_with?(hash, "$argon2")

    defp expected do
      type = Enum.at(~w(argon2d argon2i argon2id), setting(:argon2_type, 2))

      params =
        "m=#{Integer.pow(2, setting(:m_cost, 16))},t=#{setting(:t_cost, 3)}," <>
          "p=#{setting(:parallelism, 4)}"

      {type, params}
    end

    defp setting(key, default), do: Application.get_env(:argon2_elixir, key, default)
  end
end
