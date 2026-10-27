defmodule Macaw.Auth.Native.ConformanceTest do
  # The kit, run against the native backend over the test repo: all of it,
  # the second factor included.
  use Macaw.Auth.Conformance,
    backend: Macaw.Auth.Native,
    fixtures: Macaw.Auth.Test.NativeFixtures

  alias Macaw.Auth
  alias Macaw.Auth.Conformance.Fixtures
  alias Macaw.Auth.Test.MemoryBackend, as: Mem
  alias Macaw.Auth.Test.NativeFixtures

  # The kit's own tests are generated into this module by `use`; surfex reads
  # only the tests written in this file, so these check the kit from here.

  @tag verifies: "kit-native"
  test "the kit's twenty-two tests run against the native backend, none skipped" do
    kit =
      for %ExUnit.Test{name: name} = test <- __ex_unit__().tests,
          String.starts_with?(Atom.to_string(name), "test conformance: "),
          do: test

    assert length(kit) == 22
    assert Enum.all?(kit, &(&1.tags[:skip] == nil))
  end

  @tag verifies: "auth-kit-fixtures"
  test "the fixtures' callbacks are the table's, and both fixture modules give them" do
    assert Enum.sort(Fixtures.behaviour_info(:callbacks)) ==
             Enum.sort(
               reset!: 0,
               user!: 1,
               disable!: 1,
               delete!: 1,
               idle_seconds: 0,
               stored_session_values: 0,
               enroll_second_factor!: 1
             )

    for fixtures <- [NativeFixtures, Mem],
        Code.ensure_loaded!(fixtures),
        {fun, arity} <- Fixtures.behaviour_info(:callbacks),
        do:
          assert(function_exported?(fixtures, fun, arity), "#{inspect(fixtures)}.#{fun}/#{arity}")

    # Against the native backend this test runs with: user!/1 takes the
    # roles and the second factor, and its credentials sign the user in.
    {user, creds} = NativeFixtures.user!(%{roles: ["admin"]})
    assert {:ok, %{id: id, roles: roles}} = Auth.authenticate(creds)
    assert id == user.id
    assert "admin" in roles

    {required, _} = NativeFixtures.user!(%{second_factor: :required})
    assert required.second_factor == :required

    # enroll_second_factor!/1 gives a function whose code the backend accepts now.
    next_code = NativeFixtures.enroll_second_factor!(user)
    {:ok, user} = Auth.authenticate(creds)
    assert user.second_factor == :enrolled
    {:ok, _, session} = Auth.create_session(user)
    assert Auth.verify_second_factor(session.id, next_code.()) == :ok

    # stored_session_values/0 reads every stored value, as binaries.
    assert Enum.all?(NativeFixtures.stored_session_values(), &is_binary/1)
    assert NativeFixtures.stored_session_values() != []
  end
end
