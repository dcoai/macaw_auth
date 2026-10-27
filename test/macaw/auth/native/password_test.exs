defmodule Macaw.Auth.Native.Source.PasswordTest do
  use Macaw.Auth.DataCase, async: false

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.UserRecord
  alias Macaw.Auth.User

  defp sign_in(username, password),
    do: Native.authenticate(%{username: username, password: password})

  test "a local user signs in, as the contract's user" do
    record =
      local_user!("Alice", "correct horse battery", %{
        display_name: "Alice",
        roles: ["admin", "viewer"]
      })

    assert record.username == "alice"

    assert {:ok, %User{} = user} = sign_in("alice", "correct horse battery")

    assert %User{
             username: "alice",
             display_name: "Alice",
             source: "local",
             roles: ["admin", "viewer"],
             disabled: false,
             second_factor: :none
           } = user

    assert user.id == record.id
  end

  test "the username is matched trimmed and without regard to case" do
    local_user!("bob", "correct horse battery")
    assert {:ok, %User{username: "bob"}} = sign_in("  BOB ", "correct horse battery")
  end

  test "a wrong password, an unknown user and an invalid username are one refusal" do
    local_user!("carol", "correct horse battery")
    assert sign_in("carol", "wrong") == {:error, :invalid_credentials}
    assert sign_in("nobody", "correct horse battery") == {:error, :invalid_credentials}
    assert sign_in("not a name!", "x") == {:error, :invalid_credentials}
    assert sign_in("carol", "") == {:error, :invalid_credentials}
    assert Native.authenticate(%{}) == {:error, :invalid_credentials}
  end

  test "a disabled user is refused, and told so only with the right password" do
    record = local_user!("dave", "correct horse battery")
    Repo.update!(Ecto.Changeset.change(record, disabled_at: DateTime.utc_now()))

    assert sign_in("dave", "correct horse battery") == {:error, :disabled}
    assert sign_in("dave", "wrong") == {:error, :invalid_credentials}
  end

  test "a directory user's row (no password) is not the password source's" do
    Repo.insert!(%UserRecord{username: "erin", source: "nas", roles: ["viewer"]})
    assert sign_in("erin", "") == {:error, :invalid_credentials}
    assert sign_in("erin", "anything") == {:error, :invalid_credentials}
  end

  test "usernames are unique without regard to case" do
    local_user!("frank", "correct horse battery")

    assert {:error, changeset} =
             Native.create_user(%{username: " Frank", password: "another password"})

    assert {"has already been taken", _} = changeset.errors[:username]
  end

  describe "the same time for an unknown user as a wrong password" do
    test "an unknown user spends the hasher's no-user verification" do
      configure!(hasher: Macaw.Auth.Test.CountingHasher)
      local_user!("gina", "correct horse battery")

      assert sign_in("nobody", "x") == {:error, :invalid_credentials}
      assert_received {:hasher, :no_user_verify}

      assert sign_in("not a name!", "x") == {:error, :invalid_credentials}
      assert_received {:hasher, :no_user_verify}

      assert sign_in("gina", "wrong") == {:error, :invalid_credentials}
      assert_received {:hasher, :verify}
      refute_received {:hasher, :no_user_verify}
    end

    # At a real cost (bcrypt 2^9 rounds, tens of milliseconds a hash), so
    # the hash dominates; the median and a 3x margin keep a busy CI runner
    # from failing it.
    test "measured: the medians are within a factor of three" do
      previous = Application.get_env(:bcrypt_elixir, :log_rounds)
      Application.put_env(:bcrypt_elixir, :log_rounds, 9)
      on_exit(fn -> Application.put_env(:bcrypt_elixir, :log_rounds, previous) end)
      local_user!("hank", "correct horse battery")

      median = fn username ->
        times =
          for _ <- 1..9 do
            {us, {:error, :invalid_credentials}} = :timer.tc(fn -> sign_in(username, "wrong") end)
            us
          end

        times |> Enum.sort() |> Enum.at(4)
      end

      wrong = median.("hank")
      unknown = median.("nobody")
      assert unknown < wrong * 3 and wrong < unknown * 3, "unknown #{unknown}us, wrong #{wrong}us"
    end
  end
end
