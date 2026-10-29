defmodule Macaw.Auth.Native.ReleaseTest do
  use Macaw.Auth.DataCase, async: false

  import ExUnit.CaptureIO

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Release, Totp, UserRecord}

  @t0 ~U[2026-10-01 12:00:00.000000Z]

  setup do
    configure!(sealing_key: :crypto.strong_rand_bytes(32))
    prefix = "RTA#{System.unique_integer([:positive])}"

    on_exit(fn ->
      System.delete_env(prefix <> "_CTL_ARGS")
      System.delete_env(prefix <> "_CTL_PASSWORD")
    end)

    %{prefix: prefix}
  end

  # Runs an entry point as `bin/<app> eval` would, the arguments as JSON in
  # <PREFIX>_CTL_ARGS and the password in <PREFIX>_CTL_PASSWORD: the JSON
  # objects it printed, one per line.
  defp release(fun, prefix, args, password \\ nil) do
    System.put_env(prefix <> "_CTL_ARGS", JSON.encode!(args))

    if password,
      do: System.put_env(prefix <> "_CTL_PASSWORD", password),
      else: System.delete_env(prefix <> "_CTL_PASSWORD")

    capture_io(fn ->
      case fun do
        :bootstrap -> Release.bootstrap(prefix)
        :user -> Release.user(prefix)
      end
    end)
    |> String.split("\n", trim: true)
    |> Enum.map(&JSON.decode!/1)
  end

  defp row(name), do: Repo.get_by!(UserRecord, username: name)

  defp sign_in(username, password),
    do: Native.authenticate(%{username: username, password: password})

  describe "bootstrap/1" do
    @tag verifies: "users-release-bootstrap"
    test "makes the first admin, then answers that a user exists", %{prefix: prefix} do
      assert release(:bootstrap, prefix, ["Root", "--role", "admin"], "first pw") ==
               [%{"ok" => true, "created" => "root", "role" => "admin"}]

      assert {:ok, %{roles: ["admin"]}} = sign_in("root", "first pw")

      for password <- ["other pw", nil] do
        assert release(:bootstrap, prefix, ["other", "--role", "admin"], password) ==
                 [%{"ok" => true, "created" => nil, "reason" => "a user already exists"}]
      end

      assert Repo.aggregate(UserRecord, :count) == 1
    end
  end

  describe "user/1" do
    @tag verifies: "users-release-commands"
    test "every command, as the mix task runs it", %{prefix: prefix} do
      assert release(:user, prefix, ["add", "alice", "--role", "admin"], "first pw") ==
               [%{"ok" => true, "added" => "alice", "roles" => ["admin"]}]

      assert [%{"username" => "alice", "roles" => ["admin"], "second_factor" => "none"}] =
               release(:user, prefix, ["list"])

      assert release(:user, prefix, ["roles", "alice", "viewer", "ops"]) ==
               [%{"ok" => true, "roles_set" => "alice", "roles" => ["viewer", "ops"]}]

      assert release(:user, prefix, ["password", "alice"], "second pw") ==
               [%{"ok" => true, "password_set" => "alice"}]

      assert {:ok, _} = sign_in("alice", "second pw")

      assert release(:user, prefix, ["disable", "alice"]) ==
               [%{"ok" => true, "disabled" => "alice"}]

      assert sign_in("alice", "second pw") == {:error, :disabled}

      assert release(:user, prefix, ["enable", "alice"]) ==
               [%{"ok" => true, "enabled" => "alice"}]

      assert {:ok, user} = sign_in("alice", "second pw")
      {:ok, %{secret: secret}} = Native.enroll_begin(user)
      {:ok, _codes} = Native.enroll_confirm(user, Totp.code(secret, @t0), now: @t0)

      assert release(:user, prefix, ["reset-second-factor", "alice"]) ==
               [%{"ok" => true, "second_factor_reset" => "alice"}]

      assert row("alice").totp_enabled_at == nil
    end
  end

  describe "in a fresh VM, as bin/<app> eval runs it" do
    @describetag :tmp_dir

    # Each runs `elixir` with only the build's code paths and nothing the
    # test loaded, over its own SQLite database (migrated with the shipped
    # migrations), the arguments in RT_CTL_ARGS: `{stdout, stderr, status}`.
    setup %{tmp_dir: dir} do
      db = Path.join(dir, "release.db")
      migrations = Path.expand("../../../../tmp/test/migrations", __DIR__)

      prelude = """
      Application.load(:macaw_auth)
      Application.put_env(:ecto_sqlite3, :json_library, JSON)
      Application.put_env(:bcrypt_elixir, :log_rounds, 4)
      Application.put_env(:macaw_auth, Macaw.Auth.Test.Repo, database: #{inspect(db)}, pool_size: 1)
      Application.put_env(:macaw_auth, Macaw.Auth.Native, repo: Macaw.Auth.Test.Repo)
      """

      migrate = """
      {:ok, _, _} =
        Ecto.Migrator.with_repo(Macaw.Auth.Test.Repo, fn repo ->
          Ecto.Migrator.run(repo, #{inspect(migrations)}, :up, all: true, log: false)
        end)
      """

      assert {_, _, 0} = eval(dir, prelude <> migrate, [])

      configured =
        prelude <>
          ~s|Application.put_env(:macaw_auth, Macaw.Auth.Native.Release, env_prefix: "RT")\n|

      %{dir: dir, prelude: prelude, configured: configured}
    end

    defp eval(dir, code, env) do
      err = Path.join(dir, "stderr")
      paths = Path.wildcard(Path.join(Mix.Project.build_path(), "lib/*/ebin"))
      args = Enum.flat_map(paths, &["-pa", &1]) ++ ["-e", code]

      {out, status} =
        System.cmd("sh", ["-c", ~s(elixir "$@" 2>"$ERR"), "sh" | args], env: [{"ERR", err} | env])

      {out, File.read!(err), status}
    end

    defp objects(out), do: out |> String.split("\n", trim: true) |> Enum.map(&JSON.decode!/1)

    @tag verifies: "users-release-fresh-vm"
    test "bootstrap/0 makes the first admin once; user/0 adds and lists, the password only in RT_CTL_PASSWORD",
         c do
      code = c.configured <> "Macaw.Auth.Native.Release.bootstrap()"
      env = [{"RT_CTL_ARGS", ~s(["root", "--role", "admin"])}, {"RT_CTL_PASSWORD", "first pw"}]

      assert {out, "", 0} = eval(c.dir, code, env)
      assert objects(out) == [%{"ok" => true, "created" => "root", "role" => "admin"}]

      assert {out, "", 0} = eval(c.dir, code, [{"RT_CTL_ARGS", ~s(["x", "--role", "admin"])}])

      assert objects(out) == [
               %{"ok" => true, "created" => nil, "reason" => "a user already exists"}
             ]

      code = c.configured <> "Macaw.Auth.Native.Release.user()"

      env = [
        {"RT_CTL_ARGS", ~s(["add", "alice", "--role", "admin"])},
        {"RT_CTL_PASSWORD", "correct horse battery"}
      ]

      assert {out, "", 0} = eval(c.dir, code, env)
      assert objects(out) == [%{"ok" => true, "added" => "alice", "roles" => ["admin"]}]
      refute out =~ "correct horse"

      assert {out, "", 0} = eval(c.dir, code, [{"RT_CTL_ARGS", ~s(["list"])}])

      assert [
               %{"username" => "alice", "roles" => ["admin"], "source" => "local"},
               %{"username" => "root"}
             ] = objects(out)
    end

    @tag verifies: "users-release-delete"
    test "delete answers the protocol's object; an unknown user fails with one stderr line", c do
      # Here, over the test's repo: alice deleted can't sign in.
      local_user!("alice", "first pw")

      assert release(:user, c.prefix, ["delete", "alice"]) ==
               [%{"ok" => true, "deleted" => "alice"}]

      assert Native.get_user("alice") == nil
      assert sign_in("alice", "first pw") == {:error, :invalid_credentials}

      # As bin/<app> eval runs it.
      code = c.configured <> "Macaw.Auth.Native.Release.user()"

      env = [
        {"RT_CTL_ARGS", ~s(["add", "bob", "--role", "admin"])},
        {"RT_CTL_PASSWORD", "correct horse battery"}
      ]

      assert {_, "", 0} = eval(c.dir, code, env)
      assert {out, "", 0} = eval(c.dir, code, [{"RT_CTL_ARGS", ~s(["delete", "bob"])}])
      assert objects(out) == [%{"ok" => true, "deleted" => "bob"}]
      assert {"", "", 0} = eval(c.dir, code, [{"RT_CTL_ARGS", ~s(["list"])}])

      assert {"", err, 1} = eval(c.dir, code, [{"RT_CTL_ARGS", ~s(["delete", "nobody"])}])
      assert [line] = String.split(err, "\n", trim: true)
      assert JSON.decode!(line) == %{"ok" => false, "error" => "no user named nobody"}
    end

    @tag verifies: "users-release-fresh-vm-errors"
    test "a user's error, malformed arguments and a missing env_prefix: one stderr line, exit status 1",
         c do
      code = c.configured <> "Macaw.Auth.Native.Release.user()"

      for {args, error} <- [
            {~s(["disable", "nobody"]), "no user named nobody"},
            {~s(["frob"]), "usage: " <> Macaw.Auth.Native.UserCommands.usage()}
          ] do
        assert {"", err, 1} = eval(c.dir, code, [{"RT_CTL_ARGS", args}])
        assert [line] = String.split(err, "\n", trim: true)
        assert JSON.decode!(line) == %{"ok" => false, "error" => error}
      end

      env = [
        {"RT_CTL_ARGS", ~s(["add", "carol", "--role", "admin", "--password", "hunter2"])},
        {"RT_CTL_PASSWORD", "env pw"}
      ]

      assert {"", err, 1} = eval(c.dir, code, env)
      assert err =~ "never read from the command line"
      refute err =~ "hunter2"

      # Malformed arguments fail as macaw_host's protocol says.
      for args <- ["not json", "[1, 2]"] do
        assert {"", "RT_CTL_ARGS must be a JSON array of strings\n", 1} =
                 eval(c.dir, code, [{"RT_CTL_ARGS", args}])
      end

      # Without a configured env_prefix the entry points refuse, naming the setting.
      for fun <- ["bootstrap", "user"] do
        code = c.prelude <> "Macaw.Auth.Native.Release.#{fun}()"

        assert {"", err, 1} = eval(c.dir, code, [{"RT_CTL_ARGS", ~s(["list"])}])
        assert [line] = String.split(err, "\n", trim: true)

        assert JSON.decode!(line) == %{
                 "ok" => false,
                 "error" =>
                   "config :macaw_auth, Macaw.Auth.Native.Release, env_prefix: is not set"
               }
      end
    end
  end

  # The section's own text, beside the hints inside it.
  describe "the sections of spec 13" do
    @describetag :tmp_dir

    @tag verifies: "auth-users-release"
    test "bootstrap's own usage; the prefix given; revoking without telling a page", c do
      for args <- [["root"], ["root", "--role", "-x"]] do
        code = "Macaw.Auth.Native.Release.bootstrap(#{inspect(c.prefix)})"

        paths = Path.wildcard(Path.join(Mix.Project.build_path(), "lib/*/ebin"))
        argv = Enum.flat_map(paths, &["-pa", &1]) ++ ["-e", code]
        err = Path.join(c.tmp_dir, "stderr")

        {out, 1} =
          System.cmd("sh", ["-c", ~s(elixir "$@" 2>"$ERR"), "sh" | argv],
            env: [{"ERR", err}, {c.prefix <> "_CTL_ARGS", JSON.encode!(args)}]
          )

        assert out == ""

        assert JSON.decode!(File.read!(err)) == %{
                 "ok" => false,
                 "error" => "usage: bootstrap NAME --role R"
               }
      end

      # user/1 with the prefix given, here, apart from the app's node: the
      # password's revocation tells no open page.
      record = local_user!("alice", "first pw")
      {:ok, token, _} = Native.create_session(Native.to_user(record), [])
      :ok = Macaw.Auth.subscribe(record.id)

      assert release(:user, c.prefix, ["password", "alice"], "second pw") ==
               [%{"ok" => true, "password_set" => "alice"}]

      assert Native.fetch_session(token, []) == {:error, :invalid}
      refute_receive {:sessions_revoked, _}, 50

      # bootstrap/0 and user/0 read the prefix from the configuration.
      on_exit(fn -> Application.delete_env(:macaw_auth, Release) end)
      Application.put_env(:macaw_auth, Release, env_prefix: c.prefix)
      Repo.delete_all(UserRecord)
      System.put_env(c.prefix <> "_CTL_ARGS", ~s(["root", "--role", "admin"]))
      System.put_env(c.prefix <> "_CTL_PASSWORD", "root pw")

      assert JSON.decode!(capture_io(fn -> Release.bootstrap() end)) ==
               %{"ok" => true, "created" => "root", "role" => "admin"}

      System.put_env(c.prefix <> "_CTL_ARGS", ~s(["disable", "root"]))

      assert JSON.decode!(capture_io(fn -> Release.user() end)) == %{
               "ok" => true,
               "disabled" => "root"
             }
    end
  end
end
