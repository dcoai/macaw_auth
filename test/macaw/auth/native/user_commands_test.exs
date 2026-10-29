defmodule Macaw.Auth.Native.UserCommandsTest do
  use Macaw.Auth.DataCase, async: false

  import ExUnit.CaptureIO

  alias Macaw.Auth.Native.{Config, Release, UserCommands, UserRecord}
  alias Mix.Tasks.MacawAuth.User, as: UserTask

  @opts [password_var: "THE_PASSWORD", announce: false]

  setup do
    configure!(sealing_key: :crypto.strong_rand_bytes(32))
    :ok
  end

  defp run(words, password \\ nil), do: UserCommands.run(words, password, @opts)

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 13" do
    @tag verifies: "auth-users"
    test "the mix task and the release entry point answer as the one implementation does" do
      local_user!("alice", "correct horse battery", %{roles: ["admin"]})
      Repo.insert!(%UserRecord{username: "erin", source: "nas", roles: ["viewer"]})
      {:ok, objects} = run(["list"])
      expected = objects |> JSON.encode!() |> JSON.decode!()

      Mix.shell(Mix.Shell.Process)
      on_exit(fn -> Mix.shell(Mix.Shell.IO) end)
      UserTask.run(["list"])

      from_task =
        for _ <- objects do
          assert_received {:mix_shell, :info, [line]}
          JSON.decode!(line)
        end

      prefix = "UCT#{System.unique_integer([:positive])}"
      System.put_env(prefix <> "_CTL_ARGS", ~s(["list"]))
      on_exit(fn -> System.delete_env(prefix <> "_CTL_ARGS") end)

      from_release =
        capture_io(fn -> Release.user(prefix) end)
        |> String.split("\n", trim: true)
        |> Enum.map(&JSON.decode!/1)

      assert length(expected) == 2
      assert from_task == expected
      assert from_release == expected
    end

    @tag verifies: "auth-users-commands"
    test "answers, never raises; names as stored; roles are words; nothing typed becomes an atom" do
      local_user!("dave", "correct horse battery")

      assert {:ok, [%{ok: true, disabled: "dave"}]} = run(["disable", " DAVE "])
      assert {:ok, [%{ok: true, enabled: "dave"}]} = run(["enable", "Dave"])

      for words <- [
            ["add", "bob", "--role", "-admin"],
            ["add", "bob", "--role", ""],
            ["roles", "dave", "--admin"],
            ["roles", "dave", ""],
            ["disable"],
            ["list", "extra"]
          ] do
        assert run(words, "pw") == {:error, "usage: " <> UserCommands.usage()}, inspect(words)
      end

      assert UserCommands.usage() ==
               "list | add NAME --role R [--role R…] | disable NAME | enable NAME | " <>
                 "delete NAME | password NAME | roles NAME R… | reset-second-factor NAME"

      word = "frobnicate#{System.unique_integer([:positive])}"
      assert {:error, "usage: " <> _} = run([word, word])
      assert_raise ArgumentError, fn -> String.to_existing_atom(word) end

      # The configuration is read first: a fault is an answer, not a raise.
      configured = Application.get_env(:macaw_auth, Macaw.Auth.Native)
      on_exit(fn -> Application.put_env(:macaw_auth, Macaw.Auth.Native, configured) end)
      Application.put_env(:macaw_auth, Macaw.Auth.Native, repo: Repo, shade: 1)
      :persistent_term.erase(Config)

      assert run(["list"]) ==
               {:error,
                "config :macaw_auth, Macaw.Auth.Native: :shade: is not a Macaw.Auth.Native setting"}

      # With the repo already running, start/0 uses it as it is.
      Application.put_env(:macaw_auth, Macaw.Auth.Native, configured)
      :persistent_term.erase(Config)
      assert UserCommands.start() == :ok
      assert {:ok, [_dave]} = run(["list"])
    end

    @tag verifies: "auth-users-passwords"
    test "bootstrap refuses a password among its words too; no answer repeats a password or a stray word" do
      for words <- [
            ["root", "--role", "admin", "--password", "hunter2"],
            ["root", "--role", "admin", "--password=hunter2"],
            ["-p", "hunter2", "root", "--role", "admin"]
          ] do
        assert {:error, message} = UserCommands.bootstrap(words, "env pw", @opts)

        assert message ==
                 "a password is never read from the command line: set THE_PASSWORD to it instead"
      end

      assert UserCommands.bootstrap(["root", "--role", "admin"], nil, @opts) ==
               {:error,
                "set THE_PASSWORD to the password (it is never read from the command line)"}

      assert Repo.aggregate(UserRecord, :count) == 0

      assert {:ok, answer} = UserCommands.bootstrap(["root", "--role", "admin"], "boot pw", @opts)
      refute inspect(answer) =~ "boot pw"
      assert {:ok, answer} = run(["add", "carol", "--role", "admin"], "add pw")
      refute inspect(answer) =~ "add pw"
      assert {:ok, answer} = run(["password", "carol"], "new pw")
      refute inspect(answer) =~ "new pw"

      # A stray word may be a password typed in the wrong place.
      for words <- [
            ["add", "dan", "hunter2", "--role", "admin"],
            ["password", "carol", "hunter2"],
            ["disable", "carol", "hunter2"],
            ["hunter2"]
          ] do
        assert {:error, message} = run(words, "env pw")
        refute message =~ "hunter2", inspect(words)
      end

      assert {:error, message} = UserCommands.bootstrap(["root", "hunter2"], "env pw", @opts)
      refute message =~ "hunter2"
    end
  end

  describe "delete" do
    @tag verifies: "users-delete-command"
    test "deletes the user with their sessions, answering the stored name" do
      nora = local_user!("nora", "correct horse battery")
      {:ok, _token, _} = Macaw.Auth.Native.create_session(Macaw.Auth.Native.to_user(nora), [])

      assert run(["delete", " Nora "]) == {:ok, [%{ok: true, deleted: "nora"}]}
      assert Repo.get(UserRecord, nora.id) == nil
      assert Macaw.Auth.Native.list_sessions(nora.id, []) == []

      assert run(["delete", "nobody"]) == {:error, "no user named nobody"}

      for words <- [["delete"], ["delete", ""], ["delete", "nora", "nina"]] do
        assert run(words) == {:error, "usage: " <> UserCommands.usage()}, inspect(words)
      end
    end
  end
end
