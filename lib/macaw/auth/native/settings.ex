defmodule Macaw.Auth.Native.Settings do
  @moduledoc false
  # The small checks every source's `parse/2` makes (ported from exio's
  # AuthSources): each failure an `{:error, "sources[<name>].<key>: …"}`
  # naming the source and the key, and no message ever holding a secret.
  # Configuration may come with string keys (a JSON or `config.exs` map);
  # a known one becomes its atom by lookup, never by creating an atom, and
  # an unknown one stays a string for `known_keys/3` to name.

  @doc "The map with its known keys as atoms (by lookup in `keys`)."
  def normalize(map, keys) when is_map(map), do: Map.new(map, fn {k, v} -> {key(k, keys), v} end)

  defp key(k, _keys) when is_atom(k), do: k
  defp key(k, keys) when is_binary(k), do: Enum.find(keys, k, &(Atom.to_string(&1) == k))
  defp key(k, _keys), do: k

  @doc "The source's name, else `default`; 1–32 of `[a-z0-9_-]`."
  def name(config, default) do
    case Map.get(config, :name, default) do
      name when is_binary(name) ->
        if name =~ ~r/\A[a-z0-9][a-z0-9_-]{0,31}\z/,
          do: {:ok, name},
          else:
            {:error,
             "sources[#{inspect(name)}].name: must be 1–32 of a-z 0-9 _ -, starting with a letter or digit"}

      nil ->
        {:error, "sources: a source of type #{type(config)} needs a name"}

      other ->
        {:error, "sources[#{inspect(other)}].name: must be a string"}
    end
  end

  defp type(config), do: config |> Map.get(:type) |> to_string()

  @doc "`:ok`, or the first key that isn't one of `known`."
  def known_keys(config, known, name) do
    case Enum.reject(Map.keys(config), &(&1 in known)) do
      [] -> :ok
      [key | _] -> fail(name, key, "is not a known setting")
    end
  end

  def fail(name, key, message), do: {:error, "sources[#{name}].#{key}: #{message}"}

  def required_string(map, key, name, label \\ nil) do
    case Map.get(map, key) do
      v when is_binary(v) and v != "" -> {:ok, v}
      nil -> fail(name, label || key, "is required")
      _ -> fail(name, label || key, "must be a non-empty string")
    end
  end

  def optional_string(map, key, name) do
    case Map.get(map, key) do
      nil -> {:ok, nil}
      v when is_binary(v) and v != "" -> {:ok, v}
      _ -> fail(name, key, "must be a non-empty string")
    end
  end

  def string(map, key, default, name) do
    case Map.get(map, key, default) do
      v when is_binary(v) and v != "" -> {:ok, v}
      _ -> fail(name, key, "must be a non-empty string")
    end
  end

  def bool(map, key, default, name) do
    case Map.get(map, key, default) do
      v when is_boolean(v) -> {:ok, v}
      _ -> fail(name, key, "must be true or false")
    end
  end

  def int(map, key, default, first..last//_, name) do
    case Map.get(map, key, default) do
      v when is_integer(v) and v >= first and v <= last -> {:ok, v}
      v when is_integer(v) -> fail(name, key, "must be in #{first}..#{last}")
      _ -> fail(name, key, "must be an integer")
    end
  end

  @doc """
  A secret value: a literal string, `{:env, "VAR"}` or `{:file, path}`
  (a trailing newline trimmed), resolved now so a reference that can't be
  read is refused when the configuration is read, not at a sign-in.
  """
  def secret(value, _env) when is_binary(value) and value != "", do: {:ok, value}

  def secret({:env, var}, env) when is_binary(var) do
    case Map.get(env, var) do
      v when is_binary(v) and v != "" -> {:ok, v}
      _ -> {:error, "the environment variable #{var} is not set"}
    end
  end

  def secret({:file, path}, _env) when is_binary(path) do
    case File.read(path) do
      {:ok, text} when text != "" -> {:ok, String.trim_trailing(text, "\n")}
      {:ok, _} -> {:error, "#{path} is empty"}
      {:error, reason} -> {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  def secret(_other, _env), do: {:error, ~s(must be a string, {:env, "VAR"} or {:file, "/path"})}
end
