defmodule Macaw.Auth.AuthorizeTest do
  use ExUnit.Case, async: false

  alias Macaw.Auth
  alias Macaw.Auth.Test.Authorizer
  alias Macaw.Auth.Test.MemoryBackend, as: Mem

  setup do
    Application.put_env(:macaw_auth, :backend, Mem)
    Mem.reset!()
    on_exit(fn -> Application.delete_env(:macaw_auth, :authorizer) end)
    :ok
  end

  @tag verifies: "authorize-closed"
  test "closed by default: with no authorizer, nothing is allowed" do
    Application.delete_env(:macaw_auth, :authorizer)
    {admin, _} = Mem.user!(%{roles: ["admin"]})
    refute Auth.authorize(admin, :manage, nil)
    refute Auth.authorize(admin, :edit, %{owner_id: admin.id})
  end

  @tag verifies: "authorize-answer"
  test "the authorizer's answer is the answer" do
    Application.put_env(:macaw_auth, :authorizer, Authorizer)
    {admin, _} = Mem.user!(%{roles: ["admin"]})
    {viewer, _} = Mem.user!(%{roles: ["viewer"]})

    assert Auth.authorize(admin, :manage, nil) == true
    assert Auth.authorize(viewer, :manage, nil) == false
    assert Auth.authorize(viewer, :edit, %{owner_id: viewer.id}) == true
    assert Auth.authorize(viewer, :edit, %{owner_id: admin.id}) == false
  end

  @tag verifies: "authorize-faults"
  test "an authorizer that raises crashes the caller, and an answer other than true or false raises" do
    Application.put_env(:macaw_auth, :authorizer, Authorizer)
    {user, _} = Mem.user!(%{})

    assert_raise RuntimeError, "the authorizer failed", fn ->
      Auth.authorize(user, :explode, nil)
    end

    assert_raise CaseClauseError, fn -> Auth.authorize(user, :maybe, nil) end
  end
end
