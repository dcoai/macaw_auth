# No test waits on the clock (#12, #9): fails on `Process.sleep` or
# `:timer.sleep` in test/ and in the conformance kit
# (lib/macaw/auth/conformance.ex), which is test code that ships in lib. A
# test orders or expires things with an injected clock (`now:`), never by
# sleeping: a sleep is slow, and a sleep long enough on one machine is too
# short on a loaded one.
#
#     elixir ci/no_sleep.exs
#
# The allowlist names the files that may sleep, each with its reason. It is
# empty, and stays empty unless a sleep has no injected-clock alternative.
# An entry whose file no longer sleeps fails too, so the list never
# outlives its reason.

defmodule NoSleep do
  # {path, reason}: default closed.
  @allowed []

  @sleep ~r/\bProcess\.sleep\b|:timer\.sleep\b/

  def run do
    files = Enum.sort(Path.wildcard("test/**/*.{ex,exs}") ++ ["lib/macaw/auth/conformance.ex"])
    allowed = Map.new(@allowed)

    findings =
      for file <- files,
          not Map.has_key?(allowed, file),
          {line, n} <- Enum.with_index(String.split(File.read!(file), "\n"), 1),
          Regex.match?(@sleep, line),
          do: "#{file}:#{n}: #{String.trim(line)}"

    stale =
      for {file, _reason} <- @allowed,
          not (File.regular?(file) and Regex.match?(@sleep, File.read!(file))),
          do: "#{file}: allowlisted, but no longer sleeps; remove its entry"

    case findings ++ stale do
      [] ->
        IO.puts("no sleep OK — #{length(files)} files wait on no clock")

      problems ->
        Enum.each(problems, &IO.puts/1)

        IO.puts(
          :stderr,
          "\n#{length(problems)} problem(s): order or expire by an injected clock (`now:`), never a sleep (#12)"
        )

        System.halt(1)
    end
  end
end

NoSleep.run()
