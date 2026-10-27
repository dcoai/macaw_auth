defmodule Macaw.Auth.MemoryBackendConformanceTest do
  # The kit, run against the in-memory backend: the contract is satisfiable,
  # and the kit itself is exercised in this library's CI.
  use Macaw.Auth.Conformance,
    backend: Macaw.Auth.Test.MemoryBackend,
    fixtures: Macaw.Auth.Test.MemoryBackend

  alias Macaw.Auth.Test.MemoryBackend, as: Mem

  # The kit's own tests are generated into this module by `use`; surfex reads
  # only the tests written in this file, so these check the kit from here.

  defp kit_tests do
    for %ExUnit.Test{name: name} = test <- __ex_unit__().tests,
        String.starts_with?(Atom.to_string(name), "test conformance: "),
        do: test
  end

  @tag verifies: "kit-memory"
  test "the kit's twenty-one tests run against the in-memory backend, none skipped" do
    assert length(kit_tests()) == 21
    assert Enum.all?(kit_tests(), &(&1.tags[:skip] == nil))
  end

  @tag verifies: "auth-kit-checks"
  test "the checks are twenty-one, in four groups, as the spec lists them" do
    groups =
      kit_tests()
      |> Enum.group_by(
        & &1.tags.describe,
        &String.replace_prefix(Atom.to_string(&1.name), "test #{&1.tags.describe} ", "")
      )
      |> Map.new(fn {group, names} -> {group, Enum.sort(names)} end)

    assert groups == %{
             "conformance: authenticate" =>
               Enum.sort([
                 "valid credentials sign in",
                 "a wrong password and an unknown user are the same refusal",
                 "a disabled user is refused"
               ]),
             "conformance: sessions" =>
               Enum.sort([
                 "a session round-trips by token and by id",
                 "a user deleted since signing in gets no session",
                 "a garbage token is invalid",
                 "no session token is stored as it is",
                 "revoking a session ends it and tells subscribed processes",
                 "revoking all but one keeps that one",
                 "revoking nothing tells nobody",
                 "an idle session expires, and a re-check never extends one",
                 "the backend reports the idle limit it expires sessions by",
                 "a disabled user's live session is refused",
                 "a user's sessions list newest first"
               ]),
             "conformance: steps" =>
               Enum.sort([
                 "a user without a second factor owes nothing",
                 "completing a step of a revoked session is invalid"
               ]),
             "conformance: second factor" =>
               Enum.sort([
                 "an enrolled second factor is owed until completed",
                 "an enrolled user is reported so, and a valid code passes the step",
                 "a wrong code is refused, and the step is still owed",
                 "a code is accepted once",
                 "a user whom policy requires to have one owes enrollment"
               ])
           }
  end

  @tag verifies: "auth-kit"
  test "backend: and fixtures: are required; not async; each test configures the backend, resets, and puts it back" do
    for opts <- [[backend: Mem], [fixtures: Mem]] do
      assert_raise KeyError, fn ->
        Code.eval_quoted(
          quote do
            defmodule Macaw.Auth.MissingOptionConformanceTest do
              use Macaw.Auth.Conformance, unquote(opts)
            end
          end
        )
      end
    end

    assert __ex_unit__(:config).async? == false

    # The kit's setup ran before this test: the backend under test is configured.
    assert Application.get_env(:macaw_auth, :backend) == Mem

    # It resets the store before each test.
    {_user, creds} = Mem.user!(%{})
    assert {:ok, _} = Macaw.Auth.authenticate(creds)
    __ex_unit__(:setup, %{})
    assert Macaw.Auth.authenticate(creds) == {:error, :invalid_credentials}

    # After each, it puts back the backend that was configured, or deletes the
    # setting when none was. on_exit callbacks run last-registered first, so
    # each check below runs right after the kit's restore it follows.
    Application.put_env(:macaw_auth, :backend, Macaw.Auth.Native)

    on_exit(fn ->
      assert Application.get_env(:macaw_auth, :backend) == Macaw.Auth.Native
    end)

    __ex_unit__(:setup, %{})
    assert Application.get_env(:macaw_auth, :backend) == Mem

    Application.delete_env(:macaw_auth, :backend)
    on_exit(fn -> assert Application.fetch_env(:macaw_auth, :backend) == :error end)
    __ex_unit__(:setup, %{})
    assert Application.get_env(:macaw_auth, :backend) == Mem
  end
end
