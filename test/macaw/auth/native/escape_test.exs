defmodule Macaw.Auth.Native.Source.Ldap.EscapeTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Macaw.Auth.Native.Source.Ldap.{Escape, Filter}

  @dn_specials ~c[,+"\\<>;=]
  @filter_specials ~c[*()\\] ++ [0]

  # Any bytes at all, and strings dense in the characters that matter.
  defp values do
    one_of([
      binary(),
      string(:printable),
      ~c[,+"\\<>;=#* ()abc]
      |> Enum.map(&constant/1)
      |> one_of()
      |> list_of()
      |> map(&to_string/1),
      list_of(one_of([constant(0), integer(0..255)])) |> map(&:binary.list_to_bin/1)
    ])
  end

  # Walks an escaped DN value: every special must come as an escape pair,
  # and `#` or space only escaped where they would mean something.
  defp dn_safe?(<<?\\, h1, h2, rest::binary>>, at)
       when h1 in ~c"0123456789abcdefABCDEF" and h2 in ~c"0123456789abcdefABCDEF",
       do: dn_safe?(rest, at + 3)

  defp dn_safe?(<<?\\, _c, rest::binary>>, at), do: dn_safe?(rest, at + 2)
  defp dn_safe?(<<?\\>>, _at), do: false
  defp dn_safe?(<<c, _::binary>>, _at) when c in @dn_specials or c == 0, do: false
  defp dn_safe?(<<c, _::binary>>, 0) when c in [?#, ?\s], do: false
  defp dn_safe?(" ", _at), do: false
  defp dn_safe?(<<_c, rest::binary>>, at), do: dn_safe?(rest, at + 1)
  defp dn_safe?("", _at), do: true

  defp filter_safe?(<<?\\, h1, h2, rest::binary>>)
       when h1 in ~c"0123456789abcdefABCDEF" and h2 in ~c"0123456789abcdefABCDEF",
       do: filter_safe?(rest)

  defp filter_safe?(<<c, _::binary>>) when c in @filter_specials, do: false
  defp filter_safe?(<<_c, rest::binary>>), do: filter_safe?(rest)
  defp filter_safe?(""), do: true

  describe "DN values (RFC 4514)" do
    property "round-trip, and no special survives unescaped" do
      check all(value <- values(), max_runs: 500) do
        escaped = Escape.dn_value(value)
        assert Escape.dn_unescape(escaped) == {:ok, value}
        assert dn_safe?(escaped, 0), "unescaped special in #{inspect(escaped)}"
      end
    end

    test "each special, and the ; regression" do
      # eesidai and mdview wrote "\;", which Elixir reads as ";": unescaped.
      assert Escape.dn_value("a;b") == <<?a, ?\\, ?;, ?b>>
      assert Escape.dn_value(";") == <<?\\, ?;>>

      for {input, expected} <- [
            {",", "\\,"},
            {"+", "\\+"},
            {~s("), ~s(\\")},
            {"\\", "\\\\"},
            {"<", "\\<"},
            {">", "\\>"},
            {"=", "\\="},
            {<<0>>, "\\00"},
            {"#a", "\\#a"},
            {"a#", "a#"},
            {" a", "\\ a"},
            {"a ", "a\\ "},
            {"a b", "a b"},
            {" ", "\\ "},
            {"alice,cn=users", "alice\\,cn\\=users"}
          ] do
        assert Escape.dn_value(input) == expected, "#{inspect(input)}"
      end
    end

    test "a value ending in a backslash and a space keeps the space escaped" do
      # exio checked the escaped text for "\\ ", so this space went bare.
      assert Escape.dn_value("a\\ ") == "a\\\\\\ "
      assert Escape.dn_unescape(Escape.dn_value("a\\ ")) == {:ok, "a\\ "}
    end

    test "a dangling backslash doesn't unescape" do
      assert Escape.dn_unescape("a\\") == :error
    end
  end

  describe "filter values (RFC 4515)" do
    property "round-trip, and no special survives unescaped" do
      check all(value <- values(), max_runs: 500) do
        escaped = Escape.filter_value(value)
        assert Escape.filter_unescape(escaped) == {:ok, value}
        assert filter_safe?(escaped), "unescaped special in #{inspect(escaped)}"
      end
    end

    test "each special" do
      assert Escape.filter_value("*") == "\\2a"
      assert Escape.filter_value("(") == "\\28"
      assert Escape.filter_value(")") == "\\29"
      assert Escape.filter_value("\\") == "\\5c"
      assert Escape.filter_value(<<0>>) == "\\00"
      assert Escape.filter_value("a*)(uid=*") == "a\\2a\\29\\28uid=\\2a"
      assert Escape.filter_value(";,+") == ";,+"
    end

    property "an escaped value in a filter's text parses back to the value" do
      check all(value <- values(), max_runs: 300) do
        text = "(uid=" <> Escape.filter_value(value) <> ")"
        assert Filter.build(text, "") == Filter.build("(uid={username})", value)
      end
    end
  end

  describe "filters built with the username as data" do
    property "any username is the whole assertion value, never syntax" do
      check all(value <- values(), max_runs: 500) do
        assert {:ok, {:equalityMatch, {:AttributeValueAssertion, ~c"uid", bytes}}} =
                 Filter.build("(uid={username})", value)

        assert :binary.list_to_bin(bytes) == value
      end
    end

    test "a wildcard or a parenthesis in a username is a literal" do
      assert {:ok, {:equalityMatch, {:AttributeValueAssertion, ~c"uid", ~c"*"}}} =
               Filter.build("(uid={username})", "*")

      assert {:ok, {:and, [{:equalityMatch, _}, {:equalityMatch, {_, ~c"uid", value}}]}} =
               Filter.build("(&(objectClass=person)(uid={username}))", "a*)(uid=*")

      assert value == ~c"a*)(uid=*"
    end

    test "the template's own wildcards and escapes still work" do
      assert {:ok,
              {:substrings, {:SubstringFilter, ~c"cn", [{:initial, ~c"a"}, {:final, ~c"*b"}]}}} =
               Filter.build("(cn=a*{username})", "*b")

      assert {:ok, {:present, ~c"mail"}} = Filter.build("(mail=*)", "x")

      assert {:ok, {:equalityMatch, {_, ~c"cn", ~c"x*"}}} =
               Filter.build("(cn={username}\\2a)", "x")
    end

    test "templates are validated" do
      assert Filter.valid_template?("(uid={username})")

      assert Filter.valid_template?(
               "(&(objectClass=inetOrgPerson)(|(uid={username})(mail={username})))"
             )

      refute Filter.valid_template?("(uid=alice)")
      refute Filter.valid_template?("uid={username}")
      refute Filter.valid_template?("(uid={username}")
      refute Filter.valid_template?("(uid={username}\\zz)")
      refute Filter.valid_template?(nil)
    end
  end
end
