defmodule Macaw.Auth.Native.ConformanceTest do
  # The kit, run against the native backend over the test repo: all of it,
  # the second factor included.
  use Macaw.Auth.Conformance,
    backend: Macaw.Auth.Native,
    fixtures: Macaw.Auth.Test.NativeFixtures
end
