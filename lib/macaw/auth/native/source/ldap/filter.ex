defmodule Macaw.Auth.Native.Source.Ldap.Filter do
  @moduledoc """
  RFC 4515 search filters as `:eldap` terms, built with the username as
  data. Ported from exio's parser, with one change in how the username gets
  in.

  `:eldap` takes a filter as a term, not a string, so the configured
  `search.filter` (`(&(objectClass=person)(uid={username}))`) is parsed
  here. exio and macaw escaped the username into the filter's *text* and
  then parsed the result, so the escaping was all that stood between a
  username and the filter's structure. Here the template is parsed with
  `{username}` as a placeholder and the username's bytes go straight into
  the assertion value of the term: a `*`, `(` or `\\` in a username is a
  byte of the value, never syntax, whatever the escaping would have done.

  `\\hh` escapes in the template decode to their bytes, so an escaped `*`
  is a literal asterisk, never a wildcard. Supported: `&`, `|`, `!`,
  equality, presence (`attr=*`), substrings, `>=`, `<=` and `~=`.
  Extensible matches are not.
  """

  @placeholder "{username}"
  @hex ~c"0123456789abcdefABCDEF"

  @doc """
  Parses a filter template with `username` in place of `{username}`:
  `{:ok, eldap_filter}` or `:error`.
  """
  @spec build(String.t(), binary()) :: {:ok, term()} | :error
  def build(template, username) when is_binary(template) and is_binary(username) do
    case filter(String.trim(template), username) do
      {:ok, term, ""} -> {:ok, term}
      _ -> :error
    end
  end

  @doc "Whether `template` is a filter that uses `{username}`."
  @spec valid_template?(term()) :: boolean()
  def valid_template?(template) when is_binary(template),
    do: String.contains?(template, @placeholder) and build(template, "x") != :error

  def valid_template?(_), do: false

  defp filter("(" <> rest, u) do
    with {:ok, term, rest} <- comp(rest, u),
         ")" <> rest <- rest do
      {:ok, term, rest}
    else
      _ -> :error
    end
  end

  defp filter(_, _u), do: :error

  defp comp("&" <> rest, u), do: list(rest, u, &:eldap.and/1)
  defp comp("|" <> rest, u), do: list(rest, u, &:eldap.or/1)

  defp comp("!" <> rest, u) do
    with {:ok, term, rest} <- filter(rest, u), do: {:ok, :eldap.not(term), rest}
  end

  defp comp(rest, u), do: item(rest, u)

  defp list(rest, u, build) do
    case filters(rest, u, []) do
      {:ok, [_ | _] = terms, rest} -> {:ok, build.(terms), rest}
      _ -> :error
    end
  end

  defp filters("(" <> _ = rest, u, acc) do
    with {:ok, term, rest} <- filter(rest, u), do: filters(rest, u, [term | acc])
  end

  defp filters(rest, _u, acc), do: {:ok, Enum.reverse(acc), rest}

  # attr op value, up to the closing parenthesis (which a template value
  # can't hold unescaped).
  defp item(rest, u) do
    with [_, attr, op, value, rest] <-
           Regex.run(~r/^([A-Za-z0-9][A-Za-z0-9.;-]*)(=|>=|<=|~=)([^()]*)(.*)$/s, rest),
         {:ok, term} <- assertion(String.to_charlist(attr), op, value, u) do
      {:ok, term, rest}
    else
      _ -> :error
    end
  end

  defp assertion(attr, "=", "*", _u), do: {:ok, :eldap.present(attr)}

  # Split on the template's own asterisks, before the username goes in, so
  # an asterisk in the username is never a wildcard.
  defp assertion(attr, "=", value, u) do
    case String.split(value, "*") do
      [single] ->
        with {:ok, v} <- decode(single, u), do: {:ok, :eldap.equalityMatch(attr, v)}

      parts ->
        substrings(attr, parts, u)
    end
  end

  defp assertion(attr, op, value, u) do
    with {:ok, v} <- decode(value, u) do
      case op do
        ">=" -> {:ok, :eldap.greaterOrEqual(attr, v)}
        "<=" -> {:ok, :eldap.lessOrEqual(attr, v)}
        "~=" -> {:ok, :eldap.approxMatch(attr, v)}
      end
    end
  end

  # initial*any*…*final, the initial and final parts possibly empty.
  defp substrings(attr, [first | rest], u) do
    {middle, [last]} = Enum.split(rest, -1)

    with {:ok, first} <- decode(first, u),
         {:ok, last} <- decode(last, u),
         {:ok, middle} <- decode_all(middle, u),
         true <- Enum.all?(middle, &(&1 != [])) do
      subs =
        if(first == [], do: [], else: [{:initial, first}]) ++
          Enum.map(middle, &{:any, &1}) ++ if(last == [], do: [], else: [{:final, last}])

      if subs == [], do: :error, else: {:ok, :eldap.substrings(attr, subs)}
    else
      _ -> :error
    end
  end

  defp decode_all(parts, u) do
    Enum.reduce_while(parts, {:ok, []}, fn p, {:ok, acc} ->
      case decode(p, u) do
        {:ok, v} -> {:cont, {:ok, acc ++ [v]}}
        :error -> {:halt, :error}
      end
    end)
  end

  # A template value as the byte list eldap wants: `{username}` is the
  # username's bytes, `\hh` the byte, a lone backslash malformed.
  defp decode(value, u), do: decode(value, u, [])

  defp decode("", _u, acc),
    do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary() |> :binary.bin_to_list()}

  defp decode(@placeholder <> rest, u, acc), do: decode(rest, u, [u | acc])

  defp decode(<<?\\, h1, h2, rest::binary>>, u, acc) when h1 in @hex and h2 in @hex,
    do: decode(rest, u, [List.to_integer([h1, h2], 16) | acc])

  defp decode(<<?\\, _::binary>>, _u, _acc), do: :error
  defp decode(<<c, rest::binary>>, u, acc), do: decode(rest, u, [c | acc])
end
