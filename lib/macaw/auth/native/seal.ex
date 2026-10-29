defmodule Macaw.Auth.Native.Seal do
  @moduledoc """
  Sealing: what the native backend stores that must not be read back from
  the table (a TOTP secret), and what it hands the client to bring back
  (an enrollment ticket, `Macaw.Auth.Native.Ticket`), is sealed with
  AES-256-GCM, OTP's `:crypto`, under a key from the configuration
  (`sealing_key:`, `Macaw.Auth.Native.Config`).

  - **The key.** `sealing_key` is a binary of at least 32 bytes, or
    `{module, function, args}` returning one, called at each use (so a
    host can keep it in its data directory, or derive it from its
    `secret_key_base`, without this library depending on how). It is
    never logged and never in telemetry; the configuration's `inspect`
    leaves it out. A missing or short key is `Macaw.Auth.Native.SealingKeyError`
    at first use, naming the fault and never the value.
  - **Derived, not used as is.** The AES key is HMAC-SHA256 of a fixed
    label under the configured key, so a host may pass a longer secret it
    also uses elsewhere (its `secret_key_base`) and the two uses never
    share a key.
  - **Bound to its row.** Each sealed value carries associated data (the
    purpose and the user's id), so a sealed secret copied onto another
    user's row does not unseal there.
  - **The format.** `<<1, iv::12 bytes, tag::16 bytes, ciphertext>>`, the
    first byte a version, so a later scheme can be told apart. A fresh
    random IV for every seal.

  `unseal/3` returns `{:error, :wrong_key}` for anything that fails to
  authenticate: a different key, a tampered value, another row's value.
  """

  @version 1
  @label "macaw_auth sealing v1"
  @min_bytes 32

  @type key_source :: binary() | {module(), atom(), list()} | nil

  @doc "The smallest key accepted, in bytes."
  @spec min_bytes() :: pos_integer()
  def min_bytes, do: @min_bytes

  @doc """
  The AES key from the configured `sealing_key`; raises
  `Macaw.Auth.Native.SealingKeyError` when it is missing, short, or its
  function returns something that isn't a key.
  """
  @spec key!(key_source()) :: binary()
  def key!(nil) do
    raise Macaw.Auth.Native.SealingKeyError,
          "config :macaw_auth, Macaw.Auth.Native: sealing_key is not set; the second " <>
            "factor's secrets are sealed with it (a binary of at least #{@min_bytes} bytes, " <>
            "or {module, function, args} returning one)"
  end

  def key!({module, function, args} = source)
      when is_atom(module) and is_atom(function) and is_list(args) do
    case apply(module, function, args) do
      key when is_binary(key) and byte_size(key) >= @min_bytes ->
        derive(key)

      _ ->
        raise Macaw.Auth.Native.SealingKeyError,
              "config :macaw_auth, Macaw.Auth.Native: sealing_key #{describe(source)} " <>
                "did not return a binary of at least #{@min_bytes} bytes"
    end
  end

  def key!(key) when is_binary(key) and byte_size(key) >= @min_bytes, do: derive(key)

  def key!(_short) do
    raise Macaw.Auth.Native.SealingKeyError,
          "config :macaw_auth, Macaw.Auth.Native: sealing_key must be at least " <>
            "#{@min_bytes} bytes"
  end

  # The function's name, never its arguments: they may hold a secret.
  defp describe({module, function, args}),
    do: "#{inspect(module)}.#{function}/#{length(args)}"

  defp derive(key), do: :crypto.mac(:hmac, :sha256, key, @label)

  @doc "Seals `plaintext` under `key` (from `key!/1`), bound to `aad`."
  @spec seal(binary(), binary(), binary()) :: binary()
  def seal(plaintext, key, aad) when byte_size(key) == 32 do
    iv = :crypto.strong_rand_bytes(12)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, aad, true)
    <<@version, iv::binary-12, tag::binary-16, ciphertext::binary>>
  end

  @doc "Unseals: `{:ok, plaintext}`, or `{:error, :wrong_key}` when it doesn't authenticate."
  @spec unseal(binary(), binary(), binary()) :: {:ok, binary()} | {:error, :wrong_key}
  def unseal(<<@version, iv::binary-12, tag::binary-16, ciphertext::binary>>, key, aad)
      when byte_size(key) == 32 do
    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, aad, tag, false) do
      plaintext when is_binary(plaintext) -> {:ok, plaintext}
      :error -> {:error, :wrong_key}
    end
  end

  def unseal(_other, _key, _aad), do: {:error, :wrong_key}
end

defmodule Macaw.Auth.Native.SealingKeyError do
  @moduledoc """
  The sealing key is missing, too short, or not the one a stored value was
  sealed with. The message names the fault, never the key.
  """
  defexception [:message]
end
