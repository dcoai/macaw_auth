if Code.ensure_loaded?(Bcrypt) do
  defmodule Macaw.Auth.Native.Hasher.Bcrypt do
    @moduledoc """
    Bcrypt (`:bcrypt_elixir`), compiled only when that library is loaded.
    The cost is bcrypt_elixir's own setting, `config :bcrypt_elixir,
    log_rounds: 12`; a hash made at another cost is rehashed at sign-in.
    """

    @behaviour Macaw.Auth.Native.Hasher

    @impl true
    def hash(password), do: Bcrypt.hash_pwd_salt(password)

    @impl true
    def verify(password, hash), do: Bcrypt.verify_pass(password, hash)

    @impl true
    def no_user_verify, do: Bcrypt.no_user_verify()

    # "$2b$12$…": the cost is the two digits after the second dollar.
    @impl true
    def needs_rehash?(hash) do
      case hash do
        <<"$2", _variant, "$", cost::binary-size(2), "$", _::binary>> ->
          cost != cost() |> Integer.to_string() |> String.pad_leading(2, "0")

        _ ->
          true
      end
    end

    @impl true
    def owns?(hash), do: String.starts_with?(hash, ["$2a$", "$2b$", "$2y$"])

    defp cost, do: Application.get_env(:bcrypt_elixir, :log_rounds, 12)
  end
end
