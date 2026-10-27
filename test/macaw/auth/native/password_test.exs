defmodule Macaw.Auth.Native.Source.PasswordTest do
  use Macaw.Auth.DataCase, async: false

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.UserRecord
  alias Macaw.Auth.User

  defp sign_in(username, password),
    do: Native.authenticate(%{username: username, password: password})

  @tag verifies: "native-authenticate"
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

  @tag verifies: "password-trim-case"
  test "the username is matched trimmed and without regard to case" do
    assert local_user!("Alice", "correct horse battery").username == "alice"
    assert {:ok, %User{username: "alice"}} = sign_in("alice", "correct horse battery")

    local_user!("bob", "correct horse battery")
    assert {:ok, %User{username: "bob"}} = sign_in("  BOB ", "correct horse battery")
  end

  @tag verifies: "native-one-refusal"
  test "a wrong password, an unknown user and an invalid username are one refusal; disabled only with the right password" do
    local_user!("carol", "correct horse battery")
    assert sign_in("carol", "wrong") == {:error, :invalid_credentials}
    assert sign_in("nobody", "correct horse battery") == {:error, :invalid_credentials}
    assert sign_in("not a name!", "x") == {:error, :invalid_credentials}
    assert sign_in("carol", "") == {:error, :invalid_credentials}
    assert Native.authenticate(%{}) == {:error, :invalid_credentials}

    record = local_user!("dave", "correct horse battery")
    Repo.update!(Ecto.Changeset.change(record, disabled_at: DateTime.utc_now()))

    assert sign_in("dave", "correct horse battery") == {:error, :disabled}
    assert sign_in("dave", "wrong") == {:error, :invalid_credentials}
  end

  @tag verifies: "password-directory-row"
  test "a directory user's row (no password) is not the password source's" do
    Repo.insert!(%UserRecord{username: "erin", source: "nas", roles: ["viewer"]})
    assert sign_in("erin", "") == {:error, :invalid_credentials}
    assert sign_in("erin", "anything") == {:error, :invalid_credentials}
  end

  @tag verifies: "native-create-user"
  test "create_user makes a local user, its username normalized and unique without regard to case" do
    assert {:ok, alice} = Native.create_user(%{username: "Alice", password: "a long password"})
    stored = Repo.get!(UserRecord, alice.id)
    assert stored.username == "alice"
    assert stored.source == "local"
    assert stored.hashed_password =~ ~r/^\$2b\$/
    assert Macaw.Auth.Native.Hasher.Bcrypt.verify("a long password", stored.hashed_password)

    local_user!("frank", "correct horse battery")

    assert {:error, changeset} =
             Native.create_user(%{username: " Frank", password: "another password"})

    assert {"has already been taken", _} = changeset.errors[:username]
  end

  describe "the same time for an unknown user as a wrong password" do
    @tag verifies: "password-timing-work"
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
    # from failing it. The throttle is emptied before each attempt, so all
    # nine are checked rather than the last four refused unchecked.
    @tag verifies: "password-timing-measured"
    test "measured: the medians are within a factor of three" do
      previous = Application.get_env(:bcrypt_elixir, :log_rounds)
      Application.put_env(:bcrypt_elixir, :log_rounds, 9)
      on_exit(fn -> Application.put_env(:bcrypt_elixir, :log_rounds, previous) end)
      local_user!("hank", "correct horse battery")

      median = fn username ->
        times =
          for _ <- 1..9 do
            Macaw.Auth.Native.Throttle.reset()
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

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 06" do
    @tag verifies: "auth-source-password"
    test "the password source: its settings, whom it knows, and its reasons in order" do
      alias Macaw.Auth.Native.Source.Password
      alias Macaw.Auth.Test.CountingHasher

      context = [repo: Repo, hasher: CountingHasher]

      assert {:ok, %Password{name: "local"} = source} =
               Password.parse(%{type: :password}, context)

      assert {:ok, %Password{name: "staff"}} =
               Password.parse(%{type: :password, name: "staff"}, context)

      assert Password.parse(%{type: :password, host: "x"}, context) ==
               {:error, "sources[local].host: is not a known setting"}

      configure!(hasher: CountingHasher)
      bob = local_user!("bob", "correct horse battery")
      Repo.insert!(%UserRecord{username: "erin", source: "nas"})
      check = &Password.authenticate(source, &1, &2, [])

      # It knows a user whose row has a hash, looked up by the normalized username.
      assert {:ok, %{record: %UserRecord{id: id}}} = check.("  BOB ", "correct horse battery")
      assert id == bob.id
      assert_received {:hasher, :verify}

      # Not its to judge, spending the no-user time: no row, a row without a hash, no username.
      for username <- ["nobody", "erin", "not a name!"] do
        assert check.(username, "x") == {:error, :no_user}
        assert_received {:hasher, :no_user_verify}
      end

      refute Password.knows?(source, :no_user)
      assert Password.knows?(source, :invalid_credentials)
      assert Password.knows?(source, :disabled)

      # A missing password is checked as "".
      assert check.("bob", nil) == {:error, :invalid_credentials}
      assert_received {:hasher, :verify}

      # A hash made with other parameters is replaced at a successful sign-in.
      previous = Application.get_env(:bcrypt_elixir, :log_rounds)
      Application.put_env(:bcrypt_elixir, :log_rounds, 5)
      on_exit(fn -> Application.put_env(:bcrypt_elixir, :log_rounds, previous) end)
      assert {:ok, %{record: rehashed}} = check.("bob", "correct horse battery")
      assert rehashed.hashed_password =~ ~r/^\$2b\$05\$/
      assert Repo.get!(UserRecord, bob.id).hashed_password == rehashed.hashed_password

      # The password before the account's state.
      Repo.update!(Ecto.Changeset.change(bob, disabled_at: DateTime.utc_now()))
      assert check.("bob", "wrong") == {:error, :invalid_credentials}
      assert check.("bob", "correct horse battery") == {:error, :disabled}

      for reason <- [:no_user, :invalid_credentials, :disabled],
          do: assert(is_binary(Password.explain(reason)))
    end
  end
end
