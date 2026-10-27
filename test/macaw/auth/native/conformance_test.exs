defmodule Macaw.Auth.Native.ConformanceTest do
  # The kit, run against the native backend over the test repo. The
  # second factor arrives with #52; until then the kit's test that needs a
  # user with one enrolled is skipped, and says so in the summary.
  use Macaw.Auth.Conformance,
    backend: Macaw.Auth.Native,
    fixtures: Macaw.Auth.Test.NativeFixtures,
    pending: [second_factor: "Macaw.Auth.Native has no second factor until #52"]
end
