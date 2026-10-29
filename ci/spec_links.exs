# Checks every link in spec/*.md (and README.md) resolves, and says how many
# links of each kind it checked, so a run that checked nothing is visible:
#
#     elixir ci/spec_links.exs              # check this repository
#     elixir ci/spec_links.exs --self-test  # a planted broken link of each kind must fail
#
# The kinds:
#
# - relative: a file in spec/ (or a path from the repository root), and its
#   anchor, if any, declared as {#anchor} in that file. A bare #anchor names
#   one in the same file. A link may not leave the repository: the public home
#   has no sibling directories.
# - cross-repo: a file or directory of another Macaw repository at its public
#   home, https://github.com/dcoai/<repo>/blob/main/PATH#anchor (a file, most
#   often spec/FILE.md) or .../tree/main/PATH (a directory). Checked against
#   the sibling checkout ../<repo> when one is present (a workstation): the
#   file or directory, and the anchor in a .md file; without one (CI) its
#   shape is checked.
# - home: a repository's public home, https://github.com/dcoai/<repo>. Checked
#   against ../<repo> when present, else its shape.
# - issue: an issue or merge request on the GitLab (dco-tek/...), by shape. A
#   link into a file there (/-/blob/, /-/tree/) is refused: files are linked at
#   their public home (dco-tek/macaw/macaw#171). Any other github.com/dcoai or
#   GitLab link is refused as malformed.
# - external: every other http(s) and mailto link, counted but not checked.
#
# Each component has its own spec in its own repository (dco-tek/macaw/macaw#61),
# so specs link to each other across repositories. Copied into each Macaw
# repository unchanged; it reads the repository it runs in.

defmodule SpecLinks do
  @repo_link ~r{^https://github\.com/dcoai/(macaw[a-z_]*)/(blob|tree)/main/([0-9A-Za-z._-]+(?:/[0-9A-Za-z._-]+)*)/?(?:#([a-z0-9-]+))?$}
  @home_link ~r{^https://github\.com/dcoai/([a-z][a-z0-9_]*)$}
  @issue_link ~r{^https://gitlab\.conet\.yarina\.org/dco-tek(?:/[a-z][a-z0-9_]*)+/-/(?:issues|merge_requests)/[0-9]+(?:#[a-z0-9_-]+)?$}

  @kinds [
    :relative,
    :repo_sibling,
    :repo_shape,
    :home_sibling,
    :home_shape,
    :issue,
    :external
  ]

  @kind_names %{
    relative: "relative",
    repo_sibling: "cross-repo (against ../<repo>)",
    repo_shape: "cross-repo (shape only, no sibling)",
    home_sibling: "repo home (against ../<repo>)",
    home_shape: "repo home (shape only, no sibling)",
    issue: "GitLab issue (shape)",
    external: "external (not checked)",
    refused: "refused"
  }

  def main(["--self-test"]), do: SpecLinks.SelfTest.run()

  def main([]) do
    {files, faults, counts} = scan(File.cwd!())
    Enum.each(faults, fn {file, n, fault} -> IO.puts("#{file}:#{n}: #{fault}") end)
    IO.puts(summary(files, counts))

    cond do
      faults != [] -> System.halt(1)
      counts[:relative] == 0 -> halt("checked no relative link: is spec/ there?")
      true -> :ok
    end
  end

  def main(argv), do: halt("unknown arguments #{inspect(argv)}")

  defp halt(message) do
    IO.puts(:stderr, "spec_links: #{message}")
    System.halt(1)
  end

  @doc """
  Every link of the repository at `root`: `{files, faults, counts}`, a fault as
  `{file, line, message}` and counts by kind. Siblings are `root`'s siblings.
  """
  def scan(root) do
    files =
      Enum.sort(Path.wildcard(Path.join(root, "spec/*.md")))
      |> Enum.map(&Path.relative_to(&1, root))
      |> Kernel.++(Enum.filter(["README.md"], &File.exists?(Path.join(root, &1))))

    checked =
      for file <- files,
          {line, n} <- Enum.with_index(String.split(File.read!(Path.join(root, file)), "\n"), 1),
          [_, target] <- Regex.scan(~r/\]\(([^)\s]+)\)/, line),
          do: {file, n, check(root, file, target)}

    faults = for {file, n, {_kind, fault}} when fault != nil <- checked, do: {file, n, fault}

    counts =
      Enum.reduce(checked, Map.new(@kinds, &{&1, 0}), fn {_, _, {kind, _}}, acc ->
        Map.update(acc, kind, 1, &(&1 + 1))
      end)

    {files, faults, counts}
  end

  def summary(files, counts) do
    kinds = Enum.map_join(@kinds ++ [:refused], ", ", &"#{@kind_names[&1]}: #{counts[&1] || 0}")
    "spec links (#{length(files)} files): #{kinds}"
  end

  defp check(_root, _file, "https://gitlab.conet.yarina.org/" <> _ = url) do
    cond do
      url =~ ~r{/-/(blob|tree)/} ->
        {:refused, "a file on the GitLab, not at its public home (github.com/dcoai/…): #{url}"}

      url =~ @issue_link ->
        {:issue, nil}

      true ->
        {:refused, "malformed GitLab link: #{url}"}
    end
  end

  defp check(root, _file, "https://github.com/dcoai/" <> _ = url) do
    case {Regex.run(@repo_link, url), Regex.run(@home_link, url)} do
      {[_, repo, how, path | rest], _} -> repo(root, repo, how, path, List.first(rest), url)
      {nil, [_, repo]} -> home(root, repo)
      {nil, nil} -> {:refused, "malformed github.com/dcoai link: #{url}"}
    end
  end

  defp check(_root, _file, "http://" <> _), do: {:external, nil}
  defp check(_root, _file, "https://" <> _), do: {:external, nil}
  defp check(_root, _file, "mailto:" <> _), do: {:external, nil}

  defp check(root, file, target) do
    [path | anchor] = String.split(target, "#", parts: 2)
    base = Path.expand(root)

    resolved =
      if path == "",
        do: Path.join(base, file),
        else: Path.expand(path, Path.join(base, Path.dirname(file)))

    fault =
      cond do
        resolved != base and not String.starts_with?(resolved, base <> "/") ->
          "leaves the repository #{target}"

        not File.exists?(resolved) ->
          "missing file #{target}"

        anchor != [] and hd(anchor) not in anchors(resolved) ->
          "missing anchor #{target}"

        true ->
          nil
      end

    {:relative, fault}
  end

  defp repo(root, repo, how, rel, anchor, url) do
    sibling = Path.expand(Path.join(["..", repo]), root)
    path = Path.join(sibling, rel)

    cond do
      not File.dir?(sibling) ->
        {:repo_shape, nil}

      how == "blob" and not File.regular?(path) ->
        {:repo_sibling, "missing file in ../#{repo}: #{url}"}

      how == "tree" and not File.dir?(path) ->
        {:repo_sibling, "missing directory in ../#{repo}: #{url}"}

      anchor && anchor not in anchors(path) ->
        {:repo_sibling, "missing anchor in ../#{repo}: #{url}"}

      true ->
        {:repo_sibling, nil}
    end
  end

  # A home link's repository is checked when the workstation has its sibling;
  # one it lacks may be a sibling it never cloned, so only the shape holds.
  defp home(root, repo) do
    if File.dir?(Path.expand(Path.join(["..", repo]), root)),
      do: {:home_sibling, nil},
      else: {:home_shape, nil}
  end

  defp anchors(path) do
    if Path.extname(path) == ".md",
      do: Regex.scan(~r/\{#([a-z0-9-]+)\}/, File.read!(path)) |> Enum.map(&List.last/1),
      else: []
  end
end

defmodule SpecLinks.SelfTest do
  # A throwaway workspace: the repository under check (macaw_probe) beside one
  # sibling checkout (macaw_sib). Every line of spec/00-a.md tagged BAD must be
  # reported, and nothing else; every kind must have been counted.

  @sib "https://github.com/dcoai/macaw_sib/blob/main/spec"

  @spec_a """
  # A {#top}

  [ok same file](#top)
  [ok other file](01-b.md#there)
  [ok root path](../README.md)
  [ok sibling spec](#{@sib}/00-s.md#here)
  [ok spec, no sibling](https://github.com/dcoai/macaw_absent/blob/main/spec/00-x.md#any)
  [ok home, sibling](https://github.com/dcoai/macaw_sib)
  [ok home, no sibling](https://github.com/dcoai/macaw_absent)
  [ok sibling directory](https://github.com/dcoai/macaw_sib/tree/main/spec)
  [ok gitlab issue](https://gitlab.conet.yarina.org/dco-tek/macaw/macaw_sib/-/issues/1)
  [ok external](https://hexdocs.pm/macaw_auth)
  [BAD missing file](02-none.md)
  [BAD missing anchor](01-b.md#nowhere)
  [BAD missing same-file anchor](#nowhere)
  [BAD leaves the repository](../../macaw_sib/spec/00-s.md)
  [BAD sibling spec, missing file](#{@sib}/09-none.md)
  [BAD sibling spec, missing anchor](#{@sib}/00-s.md#nowhere)
  [BAD sibling file is a directory](#{@sib})
  [BAD sibling directory, missing](https://github.com/dcoai/macaw_sib/tree/main/design)
  [BAD spec shape: not main](https://github.com/dcoai/macaw_absent/blob/dev/spec/00-x.md)
  [BAD spec shape: anchor case](https://github.com/dcoai/macaw_absent/blob/main/spec/00-x.md#Any)
  [BAD home shape](https://github.com/dcoai/macaw_absent/)
  [BAD gitlab spec](https://gitlab.conet.yarina.org/dco-tek/macaw/macaw_sib/-/blob/main/spec/00-s.md)
  [BAD gitlab directory](https://gitlab.conet.yarina.org/dco-tek/macaw/macaw_sib/-/tree/main/spec)
  [BAD gitlab malformed](https://gitlab.conet.yarina.org/dco-tek/macaw/macaw_sib/-/issues/one)
  """

  def run do
    work =
      Path.join(System.tmp_dir!(), "spec_links_self_test_#{System.unique_integer([:positive])}")

    probe = Path.join(work, "macaw_probe")

    write(Path.join(probe, "spec/00-a.md"), @spec_a)
    write(Path.join(probe, "spec/01-b.md"), "# B {#there}\n")
    write(Path.join(probe, "README.md"), "# Probe\n")
    write(Path.join(work, "macaw_sib/spec/00-s.md"), "# S {#here}\n")

    {files, faults, counts} = SpecLinks.scan(probe)
    File.rm_rf!(work)

    lines = String.split(@spec_a, "\n")
    expected = for {line, n} <- Enum.with_index(lines, 1), line =~ "[BAD ", do: n
    reported = for {"spec/00-a.md", n, _} <- faults, do: n

    missed = Enum.map(expected -- reported, &Enum.at(lines, &1 - 1))

    spurious =
      Enum.reject(faults, fn {file, n, _} -> file == "spec/00-a.md" and n in expected end)

    uncounted = for {kind, 0} <- counts, do: kind

    IO.puts(SpecLinks.summary(files, counts))

    cond do
      missed != [] -> fail("broken links not reported:\n  " <> Enum.join(missed, "\n  "))
      spurious != [] -> fail("good links reported: #{inspect(spurious)}")
      uncounted != [] -> fail("kinds never counted: #{inspect(uncounted)}")
      true -> IO.puts("spec_links self-test OK (#{length(expected)} planted broken links caught)")
    end
  end

  defp write(path, text) do
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, text)
  end

  defp fail(message) do
    IO.puts(:stderr, "spec_links self-test FAILED: #{message}")
    System.halt(1)
  end
end

SpecLinks.main(System.argv())
