defmodule Macaw.Auth.Native.UsersTest do
  use Macaw.Auth.DataCase, async: false

  alias Macaw.Auth
  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Totp, UserRecord}

  @t0 ~U[2026-10-01 12:00:00.000000Z]
  @key :crypto.strong_rand_bytes(32)

  setup do
    previous = Application.get_env(:macaw_auth, :backend)
    Application.put_env(:macaw_auth, :backend, Native)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:macaw_auth, :backend, previous),
        else: Application.delete_env(:macaw_auth, :backend)
    end)

    configure!(sealing_key: @key)
    :ok
  end

  defp sign_in(username, password),
    do: Native.authenticate(%{username: username, password: password})

  describe "bootstrap_admin/1" do
    test "makes the first user, a local one with the given role, only when there is none" do
      assert {:ok, %UserRecord{} = record} =
               Native.bootstrap_admin(%{
                 username: "Root",
                 password: "correct horse battery",
                 role: "admin"
               })

      assert %UserRecord{username: "root", roles: ["admin"], source: "local"} = record

      assert {:ok, %{username: "root", roles: ["admin"]}} =
               sign_in("root", "correct horse battery")

      # Idempotent: every later call, at every boot, is a no-op.
      for _ <- 1..2 do
        assert Native.bootstrap_admin(%{
                 username: "root",
                 password: "another password",
                 role: "admin"
               }) == :exists
      end

      assert {:ok, _} = sign_in("root", "correct horse battery")
      assert sign_in("root", "another password") == {:error, :invalid_credentials}
      assert Repo.aggregate(UserRecord, :count) == 1
    end

    test "does nothing when any user exists, whoever it is, even without a password" do
      local_user!("alice", "correct horse battery", %{roles: ["viewer"]})

      assert Native.bootstrap_admin(%{username: "root", password: "pw", role: "admin"}) ==
               :exists

      assert Native.bootstrap_admin(%{username: "root", password: nil, role: "admin"}) == :exists
      assert Repo.aggregate(UserRecord, :count) == 1
      assert Repo.get_by(UserRecord, username: "root") == nil
    end

    test "a directory user counts as a user" do
      Repo.insert!(%UserRecord{username: "erin", source: "nas", roles: ["viewer"]})

      assert Native.bootstrap_admin(%{username: "root", password: "pw", role: "admin"}) ==
               :exists
    end

    test "with no user yet, a password and a role are required" do
      assert Native.bootstrap_admin(%{username: "root", password: "", role: "admin"}) ==
               {:error, :no_password}

      assert Native.bootstrap_admin(%{username: "root", password: nil, role: "admin"}) ==
               {:error, :no_password}

      assert Native.bootstrap_admin(%{username: "root", password: "pw", role: ""}) ==
               {:error, :no_role}

      assert Native.bootstrap_admin(%{username: "root", password: "pw"}) == {:error, :no_role}

      assert {:error, %Ecto.Changeset{} = changeset} =
               Native.bootstrap_admin(%{username: "not a name!", password: "pw", role: "admin"})

      assert changeset.errors[:username]
      assert Repo.aggregate(UserRecord, :count) == 0
    end
  end

  describe "the users" do
    test "list_users/0 is every user, by username; get_user/1 finds one as typed" do
      local_user!("carol", "correct horse battery")
      local_user!("alice", "correct horse battery")
      Repo.insert!(%UserRecord{username: "bob", source: "nas"})

      assert Enum.map(Native.list_users(), & &1.username) == ["alice", "bob", "carol"]
      assert %UserRecord{username: "alice"} = Native.get_user(" Alice ")
      assert Native.get_user("nobody") == nil
      assert Native.get_user("not a name!") == nil
    end

    test "disable_user/1 refuses sign-in; enable_user/1 lets it back" do
      local_user!("dave", "correct horse battery")

      assert {:ok, %UserRecord{disabled_at: %DateTime{} = at}} = Native.disable_user("dave")
      assert sign_in("dave", "correct horse battery") == {:error, :disabled}

      # Disabling again keeps when it was first disabled.
      assert {:ok, %UserRecord{disabled_at: ^at}} = Native.disable_user("DAVE")

      assert {:ok, %UserRecord{disabled_at: nil}} = Native.enable_user("dave")
      assert {:ok, _} = sign_in("dave", "correct horse battery")

      assert Native.disable_user("nobody") == {:error, :not_found}
      assert Native.enable_user("nobody") == {:error, :not_found}
    end

    test "set_password/3 replaces a local user's password and revokes their sessions" do
      record = local_user!("frank", "correct horse battery")
      {:ok, token, _} = Auth.create_session(Native.to_user(record))
      :ok = Auth.subscribe(record.id)

      assert {:ok, %UserRecord{}} = Native.set_password("frank", "a new password")
      assert sign_in("frank", "correct horse battery") == {:error, :invalid_credentials}
      assert {:ok, _} = sign_in("frank", "a new password")
      assert Auth.fetch(token) == {:error, :invalid}
      assert_receive {:sessions_revoked, [_]}
    end

    test "set_password/3 with announce: false revokes without telling open pages" do
      record = local_user!("gina", "correct horse battery")
      {:ok, token, _} = Auth.create_session(Native.to_user(record))
      :ok = Auth.subscribe(record.id)

      assert {:ok, _} = Native.set_password("gina", "a new password", announce: false)
      assert Auth.fetch(token) == {:error, :invalid}
      refute_receive {:sessions_revoked, _}, 50
    end

    test "set_password/3 refuses a directory user, an empty password and an unknown user" do
      Repo.insert!(%UserRecord{username: "erin", source: "nas"})
      local_user!("hank", "correct horse battery")

      assert Native.set_password("erin", "a password") == {:error, :not_local}
      assert Repo.get_by!(UserRecord, username: "erin").hashed_password == nil
      assert Native.set_password("hank", "") == {:error, :no_password}
      assert Native.set_password("hank", nil) == {:error, :no_password}
      assert Native.set_password("nobody", "a password") == {:error, :not_found}
    end

    test "set_roles/2 replaces a local user's roles; a directory user's are the directory's" do
      local_user!("ivy", "correct horse battery", %{roles: ["viewer"]})
      Repo.insert!(%UserRecord{username: "erin", source: "nas", roles: ["viewer"]})

      assert {:ok, %UserRecord{roles: ["admin", "editor"]}} =
               Native.set_roles("ivy", ["admin", "editor"])

      assert {:ok, %{roles: ["admin", "editor"]}} = sign_in("ivy", "correct horse battery")
      assert Native.set_roles("erin", ["admin"]) == {:error, :not_local}
      assert Repo.get_by!(UserRecord, username: "erin").roles == ["viewer"]
      assert Native.set_roles("ivy", [""]) == {:error, :invalid_roles}
      assert Native.set_roles("ivy", "admin") == {:error, :invalid_roles}
      assert Native.set_roles("nobody", ["admin"]) == {:error, :not_found}
    end

    test "admin_reset/2 with announce: false clears the factor and sessions, telling no page" do
      record = local_user!("jack", "correct horse battery")
      user = Native.to_user(record)
      {:ok, %{secret: secret}} = Native.enroll_begin(user)
      {:ok, _codes} = Native.enroll_confirm(user, Totp.code(secret, @t0), now: @t0)
      {:ok, token, _} = Auth.create_session(Native.to_user(Repo.get!(UserRecord, user.id)))
      :ok = Auth.subscribe(user.id)

      assert Native.admin_reset(user, announce: false) == :ok
      assert Auth.fetch(token) == {:error, :invalid}
      refute_receive {:sessions_revoked, _}, 50
      assert Native.to_user(Repo.get!(UserRecord, user.id)).second_factor == :none
      assert Native.recovery_codes_left(user) == 0
    end
  end
end
