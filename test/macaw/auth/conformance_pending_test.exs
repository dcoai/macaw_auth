defmodule Macaw.Auth.PendingConformanceTest do
  # The kit, run against the in-memory backend with its second factor named
  # pending, as a backend still being built would: the five tests that need
  # it are skipped, visibly, and the other seventeen run.
  use Macaw.Auth.Conformance,
    backend: Macaw.Auth.Test.MemoryBackend,
    fixtures: Macaw.Auth.Test.MemoryBackend,
    pending: [second_factor: "a reason"]

  defp kit_tests do
    for %ExUnit.Test{name: name} = test <- __ex_unit__().tests,
        String.starts_with?(Atom.to_string(name), "test conformance: "),
        do: test
  end

  @tag verifies: "kit-pending"
  test "the five second-factor tests are skipped with the reason, and the other seventeen run" do
    {skipped, run} = Enum.split_with(kit_tests(), & &1.tags[:skip])

    assert length(skipped) == 5
    assert Enum.all?(skipped, &(&1.tags.skip == "pending (second factor): a reason"))
    assert length(run) == 17
  end

  @tag verifies: "auth-kit-pending"
  test "pending second factor skips exactly the second factor group" do
    {skipped, run} = Enum.split_with(kit_tests(), & &1.tags[:skip])

    assert Enum.all?(skipped, &(&1.tags.describe == "conformance: second factor"))
    refute Enum.any?(run, &(&1.tags.describe == "conformance: second factor"))
  end
end
