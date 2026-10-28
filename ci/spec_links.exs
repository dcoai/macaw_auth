# Checks every link in spec/*.md (and README.md) resolves:
#
#     elixir ci/spec_links.exs
#
# - A relative link names a file in spec/ (or a path from the repository root),
#   and its anchor, if any, is declared as {#anchor} in that file.
# - A link into another Macaw repository's spec
#   (https://github.com/dcoai/<repo>/blob/main/spec/FILE#anchor, its public home)
#   is checked against the sibling checkout ../<repo> when one is present
#   (a workstation), file and anchor both; without one (CI) its shape is checked.
#
# Each component has its own spec in its own repository (dco-tek/macaw/macaw#61),
# so specs link to each other across repositories. Copied into each Macaw
# repository unchanged; it reads the repository it runs in.

defmodule SpecLinks do
  @cross ~r{^https://github\.com/dcoai/(macaw[a-z_]*)/blob/main/spec/([0-9A-Za-z._-]+\.md)(?:#([a-z0-9-]+))?$}

  def run do
    files = Path.wildcard("spec/*.md") ++ Enum.filter(["README.md"], &File.exists?/1)

    faults =
      for file <- files,
          {line, n} <- Enum.with_index(String.split(File.read!(file), "\n"), 1),
          [_, target] <- Regex.scan(~r/\]\(([^)\s]+)\)/, line),
          fault = check(file, target),
          fault != nil,
          do: "#{file}:#{n}: #{fault}"

    case faults do
      [] ->
        IO.puts("spec links OK (#{length(files)} files)")

      _ ->
        Enum.each(faults, &IO.puts/1)
        System.halt(1)
    end
  end

  defp check(file, "https://gitlab.conet.yarina.org/dco-tek/" <> _ = url) do
    case Regex.run(@cross, url) do
      [_, repo, spec_file | rest] ->
        sibling(repo, spec_file, List.first(rest), url)

      nil ->
        if String.contains?(url, "/-/blob/main/spec/"),
          do: "malformed spec link #{url}",
          else: nil
    end
    |> then(&(&1 && "#{&1}" <> if(file, do: "", else: "")))
  end

  defp check(_file, "http" <> _), do: nil
  defp check(_file, "mailto:" <> _), do: nil

  defp check(file, target) do
    [path | anchor] = String.split(target, "#", parts: 2)

    resolved =
      cond do
        path == "" ->
          file

        String.starts_with?(path, "../") ->
          Path.expand(path, Path.dirname(file)) |> Path.relative_to_cwd()

        true ->
          Path.join(Path.dirname(file), path)
      end

    cond do
      not File.exists?(resolved) -> "missing file #{target}"
      anchor != [] and hd(anchor) not in anchors(resolved) -> "missing anchor #{target}"
      true -> nil
    end
  end

  defp sibling(repo, spec_file, anchor, url) do
    path = Path.join(["..", repo, "spec", spec_file])

    cond do
      not File.dir?(Path.join("..", repo)) -> nil
      not File.exists?(path) -> "missing file in ../#{repo}: #{url}"
      anchor && anchor not in anchors(path) -> "missing anchor in ../#{repo}: #{url}"
      true -> nil
    end
  end

  defp anchors(path) do
    if Path.extname(path) == ".md",
      do: Regex.scan(~r/\{#([a-z0-9-]+)\}/, File.read!(path)) |> Enum.map(&List.last/1),
      else: []
  end
end

SpecLinks.run()
