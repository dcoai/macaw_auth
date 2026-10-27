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
    @tag verifies: "escape-dn-property"
    property "round-trip, and no special survives unescaped" do
      check all(value <- values(), max_runs: 500) do
        escaped = Escape.dn_value(value)
        assert Escape.dn_unescape(escaped) == {:ok, value}
        assert dn_safe?(escaped, 0), "unescaped special in #{inspect(escaped)}"
      end
    end

    @tag verifies: "escape-dn-table"
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
            {"alice,cn=users", "alice\\,cn\\=users"},
            # exio decided this trailing space on the escaped text, so it went bare.
            {"a\\ ", "a\\\\\\ "}
          ] do
        assert Escape.dn_value(input) == expected, "#{inspect(input)}"
      end
    end

    @tag verifies: "auth-ldap-escape-dn"
    test "specials anywhere, # and spaces by position in the value, and the inverse" do
      # Specials are escaped wherever they are; every other byte is kept.
      assert Escape.dn_value("é*()x,y") == "é*()x\\,y"
      assert Escape.dn_value(<<255, ?;, 1>>) == <<255, ?\\, ?;, 1>>

      # `#` only at the start; a space only at the start or the end, decided
      # by position in the original value, never on the escaped text.
      assert Escape.dn_value("##") == "\\##"
      assert Escape.dn_value("  ") == "\\ \\ "
      assert Escape.dn_value("a  b") == "a  b"
      assert Escape.dn_value("a\\ ") == "a\\\\\\ "
      assert Escape.dn_value("a; ") == "a\\;\\ "

      # dn_unescape/1: \hh is that byte, \c is c, a dangling backslash :error.
      assert Escape.dn_unescape("\\41\\3b\\00") == {:ok, <<"A;", 0>>}
      assert Escape.dn_unescape("\\,\\ x\\#") == {:ok, ", x#"}
      assert Escape.dn_unescape("a\\ ") == {:ok, "a "}
      assert Escape.dn_unescape("\\") == :error
    end

    @tag verifies: "escape-dn-dangling"
    test "a dangling backslash doesn't unescape" do
      assert Escape.dn_unescape("a\\") == :error
    end
  end

  describe "filter values (RFC 4515)" do
    @tag verifies: "escape-filter-property"
    property "round-trip, and no special survives unescaped" do
      check all(value <- values(), max_runs: 500) do
        escaped = Escape.filter_value(value)
        assert Escape.filter_unescape(escaped) == {:ok, value}
        assert filter_safe?(escaped), "unescaped special in #{inspect(escaped)}"
      end
    end

    @tag verifies: "escape-filter"
    test "each special" do
      assert Escape.filter_value("*") == "\\2a"
      assert Escape.filter_value("(") == "\\28"
      assert Escape.filter_value(")") == "\\29"
      assert Escape.filter_value("\\") == "\\5c"
      assert Escape.filter_value(<<0>>) == "\\00"
      assert Escape.filter_value("a*)(uid=*") == "a\\2a\\29\\28uid=\\2a"
      assert Escape.filter_value(";,+") == ";,+"
    end

    @tag verifies: "escape-filter-property"
    property "an escaped value in a filter's text parses back to the value" do
      check all(value <- values(), max_runs: 300) do
        text = "(uid=" <> Escape.filter_value(value) <> ")"
        assert Filter.build(text, "") == Filter.build("(uid={username})", value)
      end
    end

    @tag verifies: "auth-ldap-escape-filter"
    test "the five specials become their pairs, every other byte stays, and the inverse" do
      assert Escape.filter_value("é;,+=<>~ #") == "é;,+=<>~ #"
      assert Escape.filter_value(<<255, ?*, 1>>) == <<255, "\\2a", 1>>

      # filter_unescape/1: \hh is that byte, in either case; anything else
      # after a backslash is :error.
      assert Escape.filter_unescape("\\2a\\2A\\41\\00") == {:ok, <<"**A", 0>>}
      assert Escape.filter_unescape("a;b") == {:ok, "a;b"}
      assert Escape.filter_unescape("\\*") == :error
      assert Escape.filter_unescape("\\zz") == :error
      assert Escape.filter_unescape("\\2") == :error
      assert Escape.filter_unescape("a\\") == :error
    end
  end

  describe "filters built with the username as data" do
    @tag verifies: "filter-data-property"
    property "any username is the whole assertion value, never syntax" do
      check all(value <- values(), max_runs: 500) do
        assert {:ok, {:equalityMatch, {:AttributeValueAssertion, ~c"uid", bytes}}} =
                 Filter.build("(uid={username})", value)

        assert :binary.list_to_bin(bytes) == value
      end
    end

    @tag verifies: "filter-literal"
    test "a wildcard or a parenthesis in a username is a literal" do
      assert {:ok, {:equalityMatch, {:AttributeValueAssertion, ~c"uid", ~c"*"}}} =
               Filter.build("(uid={username})", "*")

      assert {:ok, {:and, [{:equalityMatch, _}, {:equalityMatch, {_, ~c"uid", value}}]}} =
               Filter.build("(&(objectClass=person)(uid={username}))", "a*)(uid=*")

      assert value == ~c"a*)(uid=*"
    end

    @tag verifies: "filter-template"
    test "the template's own wildcards and escapes still work" do
      assert {:ok,
              {:substrings, {:SubstringFilter, ~c"cn", [{:initial, ~c"a"}, {:final, ~c"*b"}]}}} =
               Filter.build("(cn=a*{username})", "*b")

      assert {:ok, {:present, ~c"mail"}} = Filter.build("(mail=*)", "x")

      assert {:ok, {:equalityMatch, {_, ~c"cn", ~c"x*"}}} =
               Filter.build("(cn={username}\\2a)", "x")
    end

    @tag verifies: "filter-valid-template"
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

    @tag verifies: "auth-ldap-filter"
    test "the operators it supports, the template's escapes, and what is malformed" do
      eq = &:eldap.equalityMatch(String.to_charlist(&1), String.to_charlist(&2))

      assert Filter.build("(&(a={username})(|(b=1)(!(c=2))))", "u") ==
               {:ok,
                :eldap.and([eq.("a", "u"), :eldap.or([eq.("b", "1"), :eldap.not(eq.("c", "2"))])])}

      assert Filter.build("(cn=*)", "u") == {:ok, :eldap.present(~c"cn")}

      assert Filter.build("(cn=a*{username}*z)", "m") ==
               {:ok, :eldap.substrings(~c"cn", initial: ~c"a", any: ~c"m", final: ~c"z")}

      assert Filter.build("(n>={username})", "5") == {:ok, :eldap.greaterOrEqual(~c"n", ~c"5")}
      assert Filter.build("(n<={username})", "5") == {:ok, :eldap.lessOrEqual(~c"n", ~c"5")}
      assert Filter.build("(cn~={username})", "al") == {:ok, :eldap.approxMatch(~c"cn", ~c"al")}

      # Extensible matches are not supported.
      assert Filter.build("(cn:dn:={username})", "u") == :error
      assert Filter.build("(cn:caseExactMatch:={username})", "u") == :error

      # \hh in the template is its byte; a backslash without two hex digits is malformed.
      assert Filter.build("(cn=\\2a{username}\\28)", "x") == {:ok, eq.("cn", "*x(")}
      assert Filter.build("(cn=\\4{username})", "x") == :error

      # An empty middle part of a substrings filter is malformed.
      assert Filter.build("(cn=a**{username})", "x") == :error

      # Trimmed, and one filter with nothing after it.
      assert Filter.build("  (uid={username})\n", "x") == {:ok, eq.("uid", "x")}
      assert Filter.build("(uid={username})(cn=x)", "x") == :error
      assert Filter.build("(uid={username}) x", "x") == :error
    end
  end

  describe "escaping as the source uses it" do
    @tag verifies: "auth-ldap-escape"
    test "a username never changes a DN or widens a search" do
      hostile = "a*)(uid=*),cn=admins+uid=root;x"

      # In a DN template, the escaped username stays one attribute value: no
      # unescaped comma or plus splits it into more RDNs or attributes.
      dn = String.replace("uid={username},cn=users,dc=x", "{username}", Escape.dn_value(hostile))
      assert [first, "cn=users", "dc=x"] = Regex.split(~r/(?<!\\),/, dn)
      assert "uid=" <> escaped = first
      refute escaped =~ ~r/(?<!\\)[+,;]/
      assert Escape.dn_unescape(escaped) == {:ok, hostile}

      # In a search, the username is never spliced into the filter's text: it
      # is the assertion value of the term, whole.
      assert Filter.build("(&(objectClass=person)(uid={username}))", hostile) ==
               {:ok,
                :eldap.and([
                  :eldap.equalityMatch(~c"objectClass", ~c"person"),
                  :eldap.equalityMatch(~c"uid", String.to_charlist(hostile))
                ])}

      # filter_value/1 shows that filter as text, which parses back to the same term.
      text = "(&(objectClass=person)(uid=" <> Escape.filter_value(hostile) <> "))"

      assert Filter.build(text, "") ==
               Filter.build("(&(objectClass=person)(uid={username}))", hostile)
    end
  end
end
