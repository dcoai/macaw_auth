# American spelling throughout (#121): fails on British forms in the
# project's own tracked files.
#
#     elixir ci/spelling.exs          # report and exit 1 on any
#     elixir ci/spelling.exs FILE...  # check only these files
#
# Exempt: what the language or a library spells its own way (Elixir's
# `@behaviour`, and "behaviour" naming Elixir's feature: "OTP behaviours", "a
# `TextMeasure` behaviour", "the Access behaviour"), third-party texts kept
# verbatim (font licenses), binaries, and the word lists here and in this
# check's own test.

defmodule Spelling do
  # British words, matched where a word or identifier part starts (colours,
  # coloured, compile_catalogue) with any ending. None of these begins an
  # American word, except those in @american.
  @words ~w(
    colour behaviour favour honour humour labour neighbour flavour
    centre centred metre litre fibre grey licence catalogu
    analys cancelled cancelling modelled modelling labelled labelling
    travelled travelling signalled signalling fuelled judgement defence
    offence artefact whilst amongst programme
  )

  # -ise stems, matched only with a verb or noun ending, so "realistic",
  # "specialist", "optimistic", "organism" and "characteristic" don't match.
  @ise ~w(
    organis recognis normalis authoris initialis rasteris summaris optimis
    minimis maximis prioritis customis serialis synchronis utilis categoris
    visualis emphasis apologis capitalis characteris finalis standardis
    specialis memoris realis
  )

  # American words that begin like a British one.
  @american ~w(metresis greyhound analysis)

  @exempt_paths [
    ~r{^deps/},
    ~r{^_build/},
    ~r{\.(ttf|woff2?|png|ico|jpg|gif|db)$},
    ~r{^ci/spelling\.exs$},
    ~r{^test/ci/spelling_test\.exs$}
  ]

  # Elixir's own spelling: the attribute, its generated function, dependency
  # modules, and the language feature by name.
  @exempt_tokens ~r/@behaviour|\bbehaviour_info\b|\bBehaviour\b|(`[^`]+`|\bOTP|\bAccess|\bGenServer) behaviours?\b/

  @doc """
  The pattern: a British word, or an -ise stem with a verb or noun ending,
  wherever a word or an identifier's part starts (#123). Case-sensitive, in
  three forms: lower case after a non-letter (`colour`,
  `compile_catalogue`), capitalized after anything but a capital
  (`Colour`, `ScannerDefence`), and all capitals (`COLOUR`).
  """
  def regex do
    endings = "(?:e|ed|es|ing|ation|ations|er|ers)"

    forms =
      Enum.flat_map(@words, fn w ->
        [
          "(?<![A-Za-z])#{w}[a-z]*",
          "(?<![A-Z])#{String.capitalize(w)}[a-z]*",
          "(?<![A-Za-z])#{String.upcase(w)}[A-Z]*"
        ]
      end) ++
        Enum.flat_map(@ise, fn s ->
          [
            "(?<![A-Za-z])#{s}#{endings}(?![a-z])",
            "(?<![A-Z])#{String.capitalize(s)}#{endings}(?![a-z])",
            "(?<![A-Za-z])#{String.upcase(s)}#{String.upcase(endings)}(?![A-Z])"
          ]
        end)

    Regex.compile!(Enum.join(forms, "|"))
  end

  def exempt_tokens, do: @exempt_tokens

  def run(argv) do
    files = if argv == [], do: tracked(), else: argv
    regex = regex()

    checked =
      for file <- files,
          not Enum.any?(@exempt_paths, &Regex.match?(&1, file)),
          File.regular?(file),
          do: file

    # A file's path is checked as well as its contents (#123): the whole
    # path for the tree's files, the name alone for a file named on the
    # command line, wherever it lives.
    name = if argv == [], do: & &1, else: &Path.basename/1

    paths =
      for file <- checked,
          word <- words(regex, name.(file)),
          do: "#{file}: #{word} (in the path)"

    findings =
      for file <- checked,
          text = File.read!(file),
          String.valid?(text),
          {line, n} <- Enum.with_index(String.split(text, "\n"), 1),
          word <- words(regex, Regex.replace(@exempt_tokens, line, "")),
          do: "#{file}:#{n}: #{word}"

    findings = paths ++ findings

    case findings do
      [] ->
        IO.puts("spelling OK — American throughout (#{length(files)} files)")

      _ ->
        Enum.each(findings, &IO.puts/1)
        IO.puts(:stderr, "\n#{length(findings)} British spelling(s); use American (#121)")
        System.halt(1)
    end
  end

  defp words(regex, text) do
    for [word] <- Regex.scan(regex, text), String.downcase(word) not in @american, do: word
  end

  # The project's files, without git (CI's image has none): every file under
  # the root except `.git` and what `.gitignore` ignores. Its entries here
  # are anchored directories (`/deps/`), anchored files and `*.ext` globs.
  defp tracked do
    ignored =
      ".gitignore"
      |> File.read!()
      |> String.split("\n", trim: true)
      |> Enum.reject(&String.starts_with?(&1, "#"))
      |> Enum.map(&ignore_regex/1)

    "**"
    |> Path.wildcard(match_dot: true)
    |> Enum.reject(
      &(String.starts_with?(&1, ".git/") or Enum.any?(ignored, fn re -> Regex.match?(re, &1) end))
    )
    |> Enum.filter(&File.regular?/1)
  end

  defp ignore_regex(entry) do
    glob = entry |> String.trim_leading("/") |> String.trim_trailing("/")
    body = glob |> Regex.escape() |> String.replace("\\*", "[^/]*")
    prefix = if String.starts_with?(entry, "/"), do: "^", else: "(^|/)"
    Regex.compile!(prefix <> body <> "(/|$)")
  end
end

Spelling.run(System.argv())
