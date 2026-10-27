defmodule Macaw.Auth.MemoryBackendConformanceTest do
  # The kit, run against the in-memory backend: the contract is satisfiable,
  # and the kit itself is exercised in this library's CI.
  use Macaw.Auth.Conformance,
    backend: Macaw.Auth.Test.MemoryBackend,
    fixtures: Macaw.Auth.Test.MemoryBackend
end
