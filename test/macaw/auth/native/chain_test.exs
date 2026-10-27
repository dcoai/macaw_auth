defmodule Macaw.Auth.Native.ChainTest do
  use Macaw.Auth.DataCase, async: false

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Config, UserRecord}
  alias Macaw.Auth.Native.Source.Password
  alias Macaw.Auth.Test.FakeDirectory
  alias Macaw.Auth.User

  @hasher Macaw.Auth.Native.Hasher.Bcrypt

  defp chain(sources) do
    Config.put(%Config{repo: Repo, hasher: @hasher, sources: sources})
  end

  defp local, do: %Password{name: "local", repo: Repo, hasher: @hasher}

  defp dir(name, entries, opts \\ []) do
    struct!(
      FakeDirectory,
      Keyword.merge(
        [name: name, entries: entries, roles: %{"staff" => ["viewer"], "admins" => ["admin"]}],
        opts
      )
    )
  end

  defp sign_in(username, password),
    do: Native.authenticate(%{username: username, password: password})

  defp asked do
    receive do
      {:asked, name} -> [name | asked()]
    after
      0 -> []
    end
  end

  test "sources are tried in order, and the first that knows the user decides" do
    chain([
      dir("first", %{"ann" => %{password: "first pw", groups: ["staff"]}}),
      dir("second", %{"ann" => %{password: "second pw"}, "ben" => %{password: "ben pw"}})
    ])

    assert {:ok, %User{source: "first"}} = sign_in("ann", "first pw")
    assert asked() == ["first"]

    # The first knows ann: her second-source password doesn't fall through.
    assert sign_in("ann", "second pw") == {:error, :invalid_credentials}
    assert asked() == ["first"]

    # The first doesn't know ben: the second decides.
    assert {:ok, %User{source: "second"}} = sign_in("ben", "ben pw")
    assert asked() == ["first", "second"]
  end

  test "a wrong local password never falls through to a directory" do
    local_user!("cat", "local password")
    chain([local(), dir("dir", %{"cat" => %{password: "directory password"}})])

    assert sign_in("cat", "directory password") == {:error, :invalid_credentials}
    assert asked() == []
    assert {:ok, %User{source: "local"}} = sign_in("cat", "local password")
  end

  test "an unreachable directory passes to the next source" do
    local_user!("dan", "local password")
    chain([dir("down", %{}, reachable: false), local()])

    assert {:ok, %User{source: "local", username: "dan"}} = sign_in("dan", "local password")
    assert sign_in("dan", "wrong") == {:error, :invalid_credentials}
  end

  test "when no source knows the user, the refusal is the same" do
    chain([local(), dir("dir", %{})])
    assert sign_in("nobody", "x") == {:error, :invalid_credentials}
    assert asked() == ["dir"]
  end

  describe "just-in-time provisioning" do
    test "a directory user's first sign-in makes their row, with no password" do
      chain([
        local(),
        dir("nas", %{"eve" => %{password: "pw", display_name: "Eve", groups: ["staff"]}})
      ])

      refute Repo.get_by(UserRecord, username: "eve")

      assert {:ok, %User{} = user} = sign_in("eve", "pw")
      assert %User{username: "eve", source: "nas", roles: ["viewer"], display_name: "Eve"} = user

      record = Repo.get_by!(UserRecord, username: "eve")
      assert record.id == user.id
      assert record.source == "nas"
      assert record.hashed_password == nil
      assert record.extra == %{"groups" => ["staff"]}

      # The same row the next time.
      assert {:ok, %User{id: id}} = sign_in("eve", "pw")
      assert id == user.id
      assert Repo.aggregate(UserRecord, :count) == 1
    end

    test "roles are re-derived from the directory at every sign-in" do
      entries = %{"fay" => %{password: "pw", groups: ["staff", "admins"], display_name: "Fay"}}
      chain([dir("nas", entries)])
      assert {:ok, %User{roles: ["viewer", "admin"]}} = sign_in("fay", "pw")

      # Edited locally: the directory's word wins at the next sign-in.
      Repo.update_all(UserRecord, set: [roles: ["superuser"]])
      assert {:ok, %User{roles: ["viewer", "admin"]}} = sign_in("fay", "pw")

      # Removed from admins in the directory: the role goes.
      chain([dir("nas", put_in(entries["fay"].groups, ["staff"]))])
      assert {:ok, %User{roles: ["viewer"]}} = sign_in("fay", "pw")
      assert Repo.get_by!(UserRecord, username: "fay").roles == ["viewer"]
    end

    test "a local user is never taken over by a directory's entry of the same name" do
      local = local_user!("owner", "local password")
      chain([dir("nas", %{"owner" => %{password: "directory password"}}), local()])

      assert sign_in("owner", "directory password") == {:error, :invalid_credentials}
      assert Repo.get!(UserRecord, local.id).source == "local"
      assert Repo.aggregate(UserRecord, :count) == 1
    end

    test "another directory's user is not taken over either" do
      chain([dir("a", %{"gil" => %{password: "pw"}}), dir("b", %{"gil" => %{password: "pw"}})])
      assert {:ok, %User{source: "a"}} = sign_in("gil", "pw")

      chain([dir("b", %{"gil" => %{password: "pw"}})])
      assert sign_in("gil", "pw") == {:error, :invalid_credentials}
    end

    test "a disabled directory user stays refused, and their row unchanged" do
      chain([dir("nas", %{"hal" => %{password: "pw", groups: ["staff"]}})])
      assert {:ok, _} = sign_in("hal", "pw")
      Repo.update_all(UserRecord, set: [disabled_at: DateTime.utc_now(), roles: []])

      assert sign_in("hal", "pw") == {:error, :disabled}
      assert Repo.get_by!(UserRecord, username: "hal").roles == []
    end

    test "a directory username that isn't a valid one is refused" do
      chain([dir("nas", %{"Bad User" => %{password: "pw"}})])
      assert sign_in("Bad User", "pw") == {:error, :invalid_credentials}
      assert Repo.aggregate(UserRecord, :count) == 0
    end
  end

  test "telemetry carries the reason and the source, never the password" do
    chain([local(), dir("nas", %{"ivy" => %{password: "pw"}})])
    ref = :telemetry_test.attach_event_handlers(self(), [[:macaw_auth, :native, :authenticate]])

    sign_in("ivy", "wrong")

    assert_received {[:macaw_auth, :native, :authenticate], ^ref, %{count: 1},
                     %{result: :error, reason: :invalid_credentials, source: "nas"} = meta}

    refute inspect(meta) =~ "wrong"

    sign_in("ivy", "pw")
    assert_received {_, ^ref, _, %{result: :ok, source: "nas", user_id: id}} when is_binary(id)
  end
end
