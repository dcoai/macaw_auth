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

    capture_io(fn -> apply(Release, fun, [prefix]) end)
    |> String.split("\n", trim: true)
    |> Enum.map(&JSON.decode!/1)
  end

  defp row(name), do: Repo.get_by!(UserRecord, username: name)

  defp sign_in(username, password),
    do: Native.authenticate(%{username: username, password: password})

  describe "bootstrap/1" do
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

    test "bootstrap/0 makes the first admin once, then is a no-op", c do
      code = c.configured <> "Macaw.Auth.Native.Release.bootstrap()"
      env = [{"RT_CTL_ARGS", ~s(["root", "--role", "admin"])}, {"RT_CTL_PASSWORD", "first pw"}]

      assert {out, "", 0} = eval(c.dir, code, env)
      assert objects(out) == [%{"ok" => true, "created" => "root", "role" => "admin"}]

      assert {out, "", 0} = eval(c.dir, code, [{"RT_CTL_ARGS", ~s(["x", "--role", "admin"])}])

      assert objects(out) == [
               %{"ok" => true, "created" => nil, "reason" => "a user already exists"}
             ]
    end

    test "user/0 adds and lists, the password only ever in RT_CTL_PASSWORD", c do
      code = c.configured <> "Macaw.Auth.Native.Release.user()"

      env = [
        {"RT_CTL_ARGS", ~s(["add", "alice", "--role", "admin"])},
        {"RT_CTL_PASSWORD", "correct horse battery"}
      ]

      assert {out, "", 0} = eval(c.dir, code, env)
      assert objects(out) == [%{"ok" => true, "added" => "alice", "roles" => ["admin"]}]
      refute out =~ "correct horse"

      assert {out, "", 0} = eval(c.dir, code, [{"RT_CTL_ARGS", ~s(["list"])}])
      assert [%{"username" => "alice", "roles" => ["admin"], "source" => "local"}] = objects(out)
    end

    test "a user's error is one JSON line on stderr and exit status 1, no stack trace", c do
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
    end

    test "malformed arguments fail as macaw_host's protocol says", c do
      code = c.configured <> "Macaw.Auth.Native.Release.user()"

      for args <- ["not json", "[1, 2]"] do
        assert {"", "RT_CTL_ARGS must be a JSON array of strings\n", 1} =
                 eval(c.dir, code, [{"RT_CTL_ARGS", args}])
      end
    end

    test "without a configured env_prefix the entry points refuse, naming the setting", c do
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
end
