defmodule Macaw.Auth.Native.Source.Ldap.Escape do
  @moduledoc """
  Escaping for values placed in LDAP distinguished names and search
  filters, so a username can never change a DN or widen a search. Ported
  from exio's, with two fixes.

  - `dn_value/1` (RFC 4514 §2.4): `, + " \\ < > ; =` are escaped with a
    backslash wherever they are, `#` and space at the start and space at
    the end likewise, and NUL is `\\00`. The older copies (eesidai, mdview)
    wrote `"\\;"`, which in Elixir is just `";"`, so a `;` went unescaped;
    here every special is a character literal, and a property test proves
    no special survives unescaped. exio's trailing-space rule looked at the
    *escaped* text, so a value ending in a backslash and a space (`a\\ `)
    kept its space bare; this decides by position in the *original* value.
  - `filter_value/1` (RFC 4515 §3): `* ( ) \\` and NUL become `\\2a \\28
    \\29 \\5c \\00`.

  The search filter itself never has a username spliced into its text:
  `Macaw.Auth.Native.Source.Ldap.Filter` builds the `:eldap` term with the
  username as data. `filter_value/1` is for showing that filter as text
  (`Macaw.Auth.Native.Source.Ldap.diagnose/3`) and for hosts that write
  their own. The `*_unescape` functions invert the escaping; the property
  tests round-trip through them.
  """

  @dn_specials ~c[,+"\\<>;=]
  @hex ~c"0123456789abcdefABCDEF"

  @doc "A value escaped for an RFC 4514 attribute value in a DN."
  @spec dn_value(binary()) :: binary()
  def dn_value(value) when is_binary(value) do
    last = byte_size(value) - 1

    for {c, i} <- Enum.with_index(:binary.bin_to_list(value)), into: "" do
      dn_char(c, i == 0, i == last)
    end
  end

  defp dn_char(0, _first, _last), do: "\\00"
  defp dn_char(c, _first, _last) when c in @dn_specials, do: <<?\\, c>>
  defp dn_char(?#, true, _last), do: "\\#"
  defp dn_char(?\s, first, last) when first or last, do: "\\ "
  defp dn_char(c, _first, _last), do: <<c>>

  @doc """
  Inverts RFC 4514 value escaping: `\\hh` is that byte, `\\c` is `c`.
  `{:ok, value}`, or `:error` for a dangling backslash or a bad hex pair.
  """
  @spec dn_unescape(binary()) :: {:ok, binary()} | :error
  def dn_unescape(text) when is_binary(text), do: dn_unescape(text, [])

  defp dn_unescape("", acc), do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}

  defp dn_unescape(<<?\\, h1, h2, rest::binary>>, acc) when h1 in @hex and h2 in @hex do
    dn_unescape(rest, [List.to_integer([h1, h2], 16) | acc])
  end

  defp dn_unescape(<<?\\, c, rest::binary>>, acc), do: dn_unescape(rest, [c | acc])
  defp dn_unescape(<<?\\>>, _acc), do: :error
  defp dn_unescape(<<c, rest::binary>>, acc), do: dn_unescape(rest, [c | acc])

  @doc "A value escaped for an RFC 4515 assertion value in a search filter."
  @spec filter_value(binary()) :: binary()
  def filter_value(value) when is_binary(value),
    do: for(<<c <- value>>, into: "", do: filter_char(c))

  defp filter_char(?*), do: "\\2a"
  defp filter_char(?(), do: "\\28"
  defp filter_char(?)), do: "\\29"
  defp filter_char(?\\), do: "\\5c"
  defp filter_char(0), do: "\\00"
  defp filter_char(c), do: <<c>>

  @doc """
  Inverts RFC 4515 value escaping: `\\hh` is that byte. `{:ok, value}`, or
  `:error` for a backslash not followed by two hex digits.
  """
  @spec filter_unescape(binary()) :: {:ok, binary()} | :error
  def filter_unescape(text) when is_binary(text), do: filter_unescape(text, [])

  defp filter_unescape("", acc), do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}

  defp filter_unescape(<<?\\, h1, h2, rest::binary>>, acc) when h1 in @hex and h2 in @hex,
    do: filter_unescape(rest, [List.to_integer([h1, h2], 16) | acc])

  defp filter_unescape(<<?\\, _::binary>>, _acc), do: :error
  defp filter_unescape(<<c, rest::binary>>, acc), do: filter_unescape(rest, [c | acc])
end
