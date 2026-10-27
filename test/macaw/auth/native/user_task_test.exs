defmodule Mix.Tasks.MacawAuth.UserTest do
  use Macaw.Auth.DataCase, async: false

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Totp, UserCommands, UserRecord}
  alias Mix.Tasks.MacawAuth.User, as: UserTask

  @var "MACAW_AUTH_USER_PASSWORD"
  @t0 ~U[2026-10-01 12:00:00.000000Z]

  setup do
    configure!(sealing_key: :crypto.strong_rand_bytes(32))
    Mix.shell(Mix.Shell.Process)
    previous = System.get_env(@var)

    on_exit(fn ->
      Mix.shell(Mix.Shell.IO)
      if previous, do: System.put_env(@var, previous), else: System.delete_env(@var)
    end)

    :ok
  end

  # Runs the task as `mix macaw_auth.user ARGV` would, with `password` in
  # its environment variable: `{exit status, stdout lines, stderr lines}`.
  # The task ends a failure with `exit({:shutdown, 1})`, as Mix exits 1.
  defp task(argv, password \\ nil) do
    if password, do: System.put_env(@var, password), else: System.delete_env(@var)
    Process.flag(:trap_exit, true)
    running = Task.async(fn -> UserTask.run(argv) end)

    status =
      case Task.yield(running, 10_000) do
        {:ok, _} -> 0
        {:exit, {:shutdown, status}} -> status
      end

    {status, shell(:info), shell(:error)}
  end

  defp shell(kind) do
    receive do
      {:mix_shell, ^kind, [line]} -> [line | shell(kind)]
    after
      0 -> []
    end
  end

  defp json(lines), do: Enum.map(lines, &JSON.decode!/1)

  defp row(name), do: Repo.get_by!(UserRecord, username: name)

  defp sign_in(username, password),
    do: Native.authenticate(%{username: username, password: password})

  @tag verifies: "users-commands"
  test "add, list, roles, password, disable, enable and reset-second-factor" do
    assert {0, out, []} = task(["add", "Alice", "--role", "admin", "--role", "ops"], "first pw")
    assert json(out) == [%{"ok" => true, "added" => "alice", "roles" => ["admin", "ops"]}]
    assert {:ok, %{roles: ["admin", "ops"]}} = sign_in("alice", "first pw")

    Repo.insert!(%UserRecord{username: "erin", source: "nas", roles: ["viewer"]})

    assert {0, out, []} = task(["list"])

    assert json(out) == [
             %{
               "username" => "alice",
               "display_name" => nil,
               "source" => "local",
               "roles" => ["admin", "ops"],
               "disabled" => false,
               "must_change_password" => false,
               "second_factor" => "none"
             },
             %{
               "username" => "erin",
               "display_name" => nil,
               "source" => "nas",
               "roles" => ["viewer"],
               "disabled" => false,
               "must_change_password" => false,
               "second_factor" => "none"
             }
           ]

    assert {0, out, []} = task(["roles", "alice", "viewer"])
    assert json(out) == [%{"ok" => true, "roles_set" => "alice", "roles" => ["viewer"]}]
    assert row("alice").roles == ["viewer"]

    assert {0, out, []} = task(["password", "alice"], "second pw")
    assert json(out) == [%{"ok" => true, "password_set" => "alice"}]
    assert {:ok, _} = sign_in("alice", "second pw")

    assert {0, out, []} = task(["disable", "alice"])
    assert json(out) == [%{"ok" => true, "disabled" => "alice"}]
    assert sign_in("alice", "second pw") == {:error, :disabled}

    assert {0, out, []} = task(["enable", "alice"])
    assert json(out) == [%{"ok" => true, "enabled" => "alice"}]
    assert {:ok, user} = sign_in("alice", "second pw")

    {:ok, %{secret: secret}} = Native.enroll_begin(user)
    {:ok, _codes} = Native.enroll_confirm(user, Totp.code(secret, @t0), now: @t0)
    assert row("alice").totp_enabled_at

    assert {0, out, []} = task(["reset-second-factor", "alice"])
    assert json(out) == [%{"ok" => true, "second_factor_reset" => "alice"}]
    assert row("alice").totp_enabled_at == nil
  end

  @tag verifies: "users-password-argv"
  test "a password passed as an argument is refused, never echoed, and nothing changes" do
    local_user!("bob", "old pw")

    for argv <- [
          ["add", "carol", "--role", "admin", "--password", "hunter2"],
          ["add", "carol", "--role", "admin", "--password=hunter2"],
          ["add", "carol", "-p", "hunter2", "--role", "admin"],
          ["password", "bob", "--password", "hunter2"],
          ["password", "bob", "-p", "hunter2"]
        ] do
      assert {1, [], [line]} = task(argv, "env pw")
      assert %{"ok" => false, "error" => error} = JSON.decode!(line)
      assert error =~ "never read from the command line"
      assert error =~ @var
      refute line =~ "hunter2"
    end

    # A stray word where none belongs may be a password too: refused, unechoed.
    for argv <- [["add", "carol", "hunter2", "--role", "admin"], ["password", "bob", "hunter2"]] do
      assert {1, [], [line]} = task(argv, "env pw")
      assert %{"ok" => false, "error" => "usage: " <> _} = JSON.decode!(line)
      refute line =~ "hunter2"
    end

    assert Repo.get_by(UserRecord, username: "carol") == nil
    assert {:ok, _} = sign_in("bob", "old pw")
  end

  @tag verifies: "users-password-env"
  test "add and password need the password in the environment variable" do
    local_user!("bob", "old pw")

    for argv <- [["add", "carol", "--role", "admin"], ["password", "bob"]],
        password <- [nil, ""] do
      assert {1, [], [line]} = task(argv, password)
      assert %{"ok" => false, "error" => error} = JSON.decode!(line)
      assert error =~ "set #{@var}"
    end

    assert Repo.get_by(UserRecord, username: "carol") == nil
  end

  @tag verifies: "users-task-errors"
  test "a user's error is one JSON line on stderr and exit status 1, never a stack trace" do
    local_user!("bob", "old pw")
    Repo.insert!(%UserRecord{username: "erin", source: "nas"})

    for {argv, error} <- [
          {["disable", "nobody"], "no user named nobody"},
          {["roles", "erin", "admin"], "erin's roles come from the directory nas"},
          {["password", "erin"], "erin's password is checked by the directory nas"},
          {["add", "bob", "--role", "admin"], "username: has already been taken"},
          {["add", "carol"], "usage: " <> UserCommands.usage()},
          {["roles", "bob"], "usage: " <> UserCommands.usage()},
          {["frob", "secret"], "usage: " <> UserCommands.usage()},
          {[], "usage: " <> UserCommands.usage()}
        ] do
      assert {1, [], [line]} = task(argv, "env pw")
      assert JSON.decode!(line) == %{"ok" => false, "error" => error}, inspect(argv)
    end
  end

  # The section's own text, beside the hints inside it.
  @tag verifies: "auth-users-task"
  test "the task reads MACAW_AUTH_USER_PASSWORD, answers on stdout, and revokes telling no page" do
    record = local_user!("alice", "old pw")
    {:ok, token, _} = Native.create_session(Native.to_user(record), [])
    :ok = Macaw.Auth.subscribe(record.id)

    assert {0, [line], []} = task(["password", "alice"], "new pw")
    assert JSON.decode!(line) == %{"ok" => true, "password_set" => "alice"}
    refute line =~ "new pw"
    assert {:ok, _} = sign_in("alice", "new pw")

    # Revoked, and the open page is not told: it leaves at its next re-check.
    assert Native.fetch_session(token, []) == {:error, :invalid}
    refute_receive {:sessions_revoked, _}, 50

    {:ok, token, _} = Native.create_session(Native.to_user(row("alice")), [])
    assert {0, _, []} = task(["reset-second-factor", "alice"])
    assert Native.fetch_session(token, []) == {:error, :invalid}
    refute_receive {:sessions_revoked, _}, 50
  end
end
