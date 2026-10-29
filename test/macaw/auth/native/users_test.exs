defmodule Macaw.Auth.Native.UsersTest do
  use Macaw.Auth.DataCase, async: false

  import Ecto.Query, only: [where: 2]

  alias Macaw.Auth
  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{RecoveryCodeRecord, SessionRecord, Totp, UserRecord}

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
    @tag verifies: "users-bootstrap"
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

    @tag verifies: "users-bootstrap-exists"
    test "does nothing when any user exists, whoever it is, even without a password" do
      alice = local_user!("alice", "correct horse battery", %{roles: ["viewer"]})

      assert Native.bootstrap_admin(%{username: "root", password: "pw", role: "admin"}) ==
               :exists

      assert Native.bootstrap_admin(%{username: "root", password: nil, role: "admin"}) == :exists
      assert Repo.aggregate(UserRecord, :count) == 1
      assert Repo.get_by(UserRecord, username: "root") == nil

      # A directory user counts as a user.
      Repo.delete!(alice)
      Repo.insert!(%UserRecord{username: "erin", source: "nas", roles: ["viewer"]})

      assert Native.bootstrap_admin(%{username: "root", password: "pw", role: "admin"}) ==
               :exists

      assert Repo.get_by(UserRecord, username: "root") == nil
    end

    @tag verifies: "users-bootstrap-needs"
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
    @tag verifies: "users-list-get"
    test "list_users/0 is every user, by username; get_user/1 finds one as typed" do
      local_user!("carol", "correct horse battery")
      local_user!("alice", "correct horse battery")
      Repo.insert!(%UserRecord{username: "bob", source: "nas"})

      assert Enum.map(Native.list_users(), & &1.username) == ["alice", "bob", "carol"]
      assert %UserRecord{username: "alice"} = Native.get_user(" Alice ")
      assert Native.get_user("nobody") == nil
      assert Native.get_user("not a name!") == nil
    end

    @tag verifies: "users-disable-enable"
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

    @tag verifies: "users-delete"
    test "delete_user/2 revokes a user's sessions, then deletes them with their recovery codes" do
      record = local_user!("mona", "correct horse battery")
      user = Native.to_user(record)
      {:ok, %{secret: secret}} = Native.enroll_begin(user)
      {:ok, [_ | _]} = Native.enroll_confirm(user, Totp.code(secret, @t0), now: @t0)
      enrolled = Native.to_user(Repo.get!(UserRecord, user.id))
      {:ok, token, _} = Auth.create_session(enrolled)
      {:ok, _, _} = Auth.create_session(enrolled)
      :ok = Auth.subscribe(record.id)

      assert {:ok, %UserRecord{id: id, username: "mona"}} = Native.delete_user(" Mona ")
      assert id == record.id
      assert Repo.get(UserRecord, id) == nil
      assert Repo.aggregate(where(SessionRecord, user_id: ^id), :count) == 0
      assert Repo.aggregate(where(RecoveryCodeRecord, user_id: ^id), :count) == 0
      assert Auth.fetch(token) == {:error, :invalid}
      assert_receive {:sessions_revoked, [_, _]}

      # Refused exactly as a user who never was.
      assert sign_in("mona", "correct horse battery") == {:error, :invalid_credentials}
      assert sign_in("nobody", "correct horse battery") == {:error, :invalid_credentials}

      # With announce: false the session goes and no page is told.
      nina = local_user!("nina", "correct horse battery")
      {:ok, token, _} = Auth.create_session(Native.to_user(nina))
      :ok = Auth.subscribe(nina.id)

      assert {:ok, _} = Native.delete_user("nina", announce: false)
      assert Auth.fetch(token) == {:error, :invalid}
      refute_receive {:sessions_revoked, _}, 50

      # A directory user is deleted too.
      Repo.insert!(%UserRecord{username: "erin", source: "nas", roles: ["viewer"]})
      assert {:ok, %UserRecord{username: "erin"}} = Native.delete_user("erin")
      assert Native.get_user("erin") == nil

      assert Native.delete_user("nobody") == {:error, :not_found}
      assert Native.delete_user("mona") == {:error, :not_found}
    end

    @tag verifies: "users-set-password"
    test "set_password/3 replaces a local user's password and revokes their sessions; announce: false tells no page" do
      record = local_user!("frank", "correct horse battery")
      {:ok, token, _} = Auth.create_session(Native.to_user(record))
      :ok = Auth.subscribe(record.id)

      assert {:ok, %UserRecord{}} = Native.set_password("frank", "a new password")
      assert sign_in("frank", "correct horse battery") == {:error, :invalid_credentials}
      assert {:ok, _} = sign_in("frank", "a new password")
      assert Auth.fetch(token) == {:error, :invalid}
      assert_receive {:sessions_revoked, [_]}

      # With announce: false, the session is revoked and no page is told.
      gina = local_user!("gina", "correct horse battery")
      {:ok, token, _} = Auth.create_session(Native.to_user(gina))
      :ok = Auth.subscribe(gina.id)

      assert {:ok, _} = Native.set_password("gina", "a new password", announce: false)
      assert Auth.fetch(token) == {:error, :invalid}
      refute_receive {:sessions_revoked, _}, 50
    end

    @tag verifies: "users-set-password-refused"
    test "set_password/3 refuses a directory user, an empty password and an unknown user" do
      Repo.insert!(%UserRecord{username: "erin", source: "nas"})
      local_user!("hank", "correct horse battery")

      assert Native.set_password("erin", "a password") == {:error, :not_local}
      assert Repo.get_by!(UserRecord, username: "erin").hashed_password == nil
      assert Native.set_password("hank", "") == {:error, :no_password}
      assert Native.set_password("hank", nil) == {:error, :no_password}
      assert Native.set_password("nobody", "a password") == {:error, :not_found}
    end

    @tag verifies: "users-set-roles"
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

    @tag verifies: "users-admin-reset-quiet"
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

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 13" do
    # Runs `fun` once, right after the first query on `table`: between the
    # code under test's read and its write.
    defp after_first_query(table, fun) do
      id = make_ref()

      :telemetry.attach(
        id,
        [:macaw, :auth, :test, :repo, :query],
        fn _event, _measurements, %{source: source}, _config ->
          if source == table do
            :telemetry.detach(id)
            fun.()
          end
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(id) end)
    end

    @tag verifies: "auth-users-api"
    test "users are named as sign-in matches them; local is the password source's; revocations say why" do
      configure!(sealing_key: @key, sources: [%{type: :password, name: "office"}])
      {:ok, kim} = Native.create_user(%{username: "Kim", password: "correct horse battery"})
      assert kim.source == "office"

      assert %UserRecord{username: "kim"} = Native.get_user("  KIM ")
      assert {:ok, %UserRecord{roles: ["ops"]}} = Native.set_roles(" Kim", ["ops"])
      assert {:ok, %UserRecord{disabled_at: %DateTime{}}} = Native.disable_user("KIM ")
      assert {:ok, %UserRecord{disabled_at: nil}} = Native.enable_user(" kim")

      # A row whose source isn't the configured password source's name is
      # not local, even one named "local".
      Repo.insert!(%UserRecord{username: "lee", source: "local", roles: ["viewer"]})
      assert Native.set_password("lee", "a password") == {:error, :not_local}
      assert Native.set_roles("lee", ["admin"]) == {:error, :not_local}

      # set_password/3 revokes with reason :password_changed.
      ref = make_ref()
      parent = self()

      :telemetry.attach(
        "users-api-#{inspect(ref)}",
        [:macaw_auth, :native, :session],
        fn _name, _measurements, meta, _ -> send(parent, {ref, meta}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach("users-api-#{inspect(ref)}") end)
      {:ok, _token, _} = Auth.create_session(Native.to_user(kim))
      assert {:ok, _} = Native.set_password("kim", "another password", announce: false)
      assert_received {^ref, %{event: :revoked, reason: :password_changed, user_id: id}}
      assert id == kim.id

      # delete_user/2 revokes with reason :user_deleted; a deletion another
      # made between its look-up and its delete is :not_found.
      {:ok, _token, _} = Auth.create_session(Native.to_user(kim))
      assert {:ok, _} = Native.delete_user("kim", announce: false)
      assert_received {^ref, %{event: :revoked, reason: :user_deleted, user_id: ^id}}

      after_first_query("macaw_auth_users", fn -> Repo.delete_all(UserRecord) end)
      assert Native.delete_user("lee") == {:error, :not_found}
    end

    @tag verifies: "auth-users-bootstrap"
    test "the first admin takes a display name and a password change; two first boots make one" do
      assert {:ok, record} =
               Native.bootstrap_admin(%{
                 username: "root",
                 password: "correct horse battery",
                 role: "admin",
                 display_name: "The Root",
                 must_change_password: true
               })

      assert %UserRecord{display_name: "The Root", must_change_password: true} = record
      Repo.delete!(record)

      # Another boot makes "root" between this one's look and its insert:
      # this one meets the unique index and answers :exists.
      parent = self()

      after_first_query("macaw_auth_users", fn ->
        send(
          parent,
          {:other, Native.bootstrap_admin(%{username: "root", password: "pw a", role: "admin"})}
        )
      end)

      assert Native.bootstrap_admin(%{username: "Root", password: "pw b", role: "admin"}) ==
               :exists

      assert_received {:other, {:ok, %UserRecord{username: "root"}}}
      assert Repo.aggregate(UserRecord, :count) == 1
      assert {:ok, _} = sign_in("root", "pw a")
    end

    @tag verifies: "auth-users-store"
    test "the users and sessions are Ecto schemas on the configured repo; there is no Store behavior" do
      assert Macaw.Auth.Native.Config.get().repo == Repo
      assert UserRecord.__schema__(:source) == "macaw_auth_users"
      assert Macaw.Auth.Native.SessionRecord.__schema__(:source) == "macaw_auth_sessions"
      assert {:error, "repo: " <> _} = Macaw.Auth.Native.Config.parse([])
      refute Code.ensure_loaded?(Macaw.Auth.Native.Store)
      refute Code.ensure_loaded?(Macaw.Auth.Store)
    end
  end
end
