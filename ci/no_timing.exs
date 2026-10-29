# No test times its code (#15): fails on an elapsed-time instrument —
# `:timer.tc`, `System.monotonic_time`, `:erlang.monotonic_time`,
# `:os.perf_counter`, `:timer.now_diff` — called in test/ or in the
# conformance kit (lib/macaw/auth/conformance.ex), which is test code that
# ships in lib. On a shared runner elapsed time measures the runner, not the
# code: a test that compares two timings is flaky, and a margin wide enough
# to pass on a loaded runner proves little. "Takes the same time" is checked
# by the work that runs (`Macaw.Auth.Test.CountingHasher.work/1`, spec/06 §3,
# spec/10 §5); the sibling of ci/no_sleep.exs, which keeps tests off the
# clock the other way.
#
#     elixir ci/no_timing.exs
#     elixir ci/no_timing.exs --self-test  # planted timings must be caught
#
# Calls are found in the parsed code, so a comment or a string naming one is
# not a finding. Reading the date (`DateTime.utc_now/0`, `System.os_time/1`
# for a TOTP code against a backend on the real clock) is not timing and is
# not refused; subtracting two such readings would be, and is for review to
# catch.
#
# The allowlist names the files that may time, each with its reason. It is
# empty, and stays empty: there is no claim a timing proves that the work
# done does not. An entry whose file no longer times fails too, so the list
# never outlives its reason.

defmodule NoTiming do
  # {path, reason}: default closed.
  @allowed []

  @clocks [
    {:timer, :tc},
    {:timer, :now_diff},
    {System, :monotonic_time},
    {:erlang, :monotonic_time},
    {:os, :perf_counter}
  ]

  def main(["--self-test"]), do: NoTiming.SelfTest.run()

  def main([]) do
    files = Enum.sort(Path.wildcard("test/**/*.{ex,exs}") ++ ["lib/macaw/auth/conformance.ex"])
    sources = Map.new(files, &{&1, File.read!(&1)})

    case problems(sources, @allowed) do
      [] ->
        IO.puts("no timing OK — #{length(files)} files time nothing")

      problems ->
        Enum.each(problems, &IO.puts/1)

        IO.puts(
          :stderr,
          "\n#{length(problems)} problem(s): check the claim by the work that runs, never by elapsed time (#15)"
        )

        System.halt(1)
    end
  end

  @doc "The findings and stale allowlist entries for `sources` (`%{path => code}`)."
  def problems(sources, allowed) do
    allowed_paths = Map.new(allowed)

    findings =
      for {path, source} <- Enum.sort(sources),
          not Map.has_key?(allowed_paths, path),
          {line, {module, fun}} <- clocks(source, path),
          do: "#{path}:#{line}: #{inspect(module)}.#{fun}"

    stale =
      for {path, _reason} <- allowed,
          clocks(Map.get(sources, path, ""), path) == [],
          do: "#{path}: allowlisted, but no longer times; remove its entry"

    findings ++ stale
  end

  @doc "Each elapsed-time call in `source`, as `{line, {module, function}}`, in order."
  def clocks(source, path) do
    {_, found} =
      source
      |> Code.string_to_quoted!(file: path, columns: false)
      |> Macro.prewalk([], fn
        {{:., meta, [{:__aliases__, _, parts}, fun]}, _, _} = node, acc ->
          {node, [{meta[:line], {Module.concat(parts), fun}} | acc]}

        {{:., meta, [module, fun]}, _, _} = node, acc when is_atom(module) ->
          {node, [{meta[:line], {module, fun}} | acc]}

        node, acc ->
          {node, acc}
      end)

    found |> Enum.reverse() |> Enum.filter(fn {_line, call} -> call in @clocks end)
  end
end

defmodule NoTiming.SelfTest do
  # Each planted source must be refused, naming its call; each clean one must
  # pass; a stale allowlist entry must fail.
  @planted [
    {"test/a_test.exs", ~S|{us, _} = :timer.tc(fn -> 1 end)|, ":timer.tc"},
    {"test/b_test.exs", ~S|t = System.monotonic_time(:microsecond)|, "System.monotonic_time"},
    {"test/c_test.exs", ~S|:erlang.monotonic_time()|, ":erlang.monotonic_time"},
    {"test/d_test.exs", ~S|:os.perf_counter(:microsecond)|, ":os.perf_counter"},
    {"test/e_test.exs", ~S|:timer.now_diff(a, b)|, ":timer.now_diff"},
    {"test/f_test.exs", ~S|Enum.map(1..9, fn _ -> elem(:timer.tc(f), 0) end)|, ":timer.tc"},
    {"test/g_test.exs", ~S|tc = &:timer.tc/1|, ":timer.tc"}
  ]

  @clean [
    {"test/h_test.exs", "# :timer.tc(f) in a comment\n:ok"},
    {"test/i_test.exs", ~S|"System.monotonic_time() in a string"|},
    {"test/j_test.exs", ~S|Totp.code(secret, System.os_time(:second))|},
    {"test/k_test.exs", ~S|DateTime.utc_now()|}
  ]

  def run do
    sources =
      Map.new(@planted, fn {path, source, _call} -> {path, source} end)
      |> Map.merge(Map.new(@clean))

    found = NoTiming.problems(sources, [])

    missed =
      for {path, _source, call} <- @planted,
          not Enum.any?(found, &String.starts_with?(&1, "#{path}:1: #{call}")),
          do: "#{path}: #{call} not caught"

    false_alarms =
      for {path, _source} <- @clean,
          Enum.any?(found, &String.starts_with?(&1, path <> ":")),
          do: "#{path}: clean, but refused"

    stale =
      NoTiming.problems(%{"test/h_test.exs" => "# :timer.tc\n:ok"}, [{"test/h_test.exs", "x"}])

    stale_missed =
      if stale == ["test/h_test.exs: allowlisted, but no longer times; remove its entry"],
        do: [],
        else: ["a stale allowlist entry passed: #{inspect(stale)}"]

    excused =
      NoTiming.problems(%{"test/a_test.exs" => ":timer.tc(f)"}, [{"test/a_test.exs", "x"}])

    excused_failed = if excused == [], do: [], else: ["an allowlisted file was refused"]

    case missed ++ false_alarms ++ stale_missed ++ excused_failed do
      [] ->
        IO.puts("no_timing self-test OK (#{length(@planted)} planted timings caught)")

      faults ->
        Enum.each(faults, &IO.puts(:stderr, &1))
        IO.puts(:stderr, "no_timing self-test FAILED")
        System.halt(1)
    end
  end
end

NoTiming.main(System.argv())
