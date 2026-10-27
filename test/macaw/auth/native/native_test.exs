defmodule Macaw.Auth.NativeTest do
  @moduledoc """
  Spec 05's sections: the native backend's sign-in, its refusals, the
  throttle around it, its telemetry, reading the configuration and making
  users, each section's own text beside the hints inside it.
  """

  use Macaw.Auth.DataCase, async: false

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Config, Sessions, Throttle, UserRecord}
  alias Macaw.Auth.Native.Source.Password
  alias Macaw.Auth.Test.{CountingHasher, FakeDirectory}
  alias Macaw.Auth.User

  @t0 ~U[2026-10-01 12:00:00.000Z]
  @event [:macaw_auth, :native, :authenticate]

  defp at(ms), do: DateTime.add(@t0, ms, :millisecond)
  defp ms(ms), do: DateTime.to_unix(@t0, :millisecond) + ms

  defp sign_in(username, password, opts \\ []),
    do: Native.authenticate(%{username: username, password: password}, opts)

  defp chain(sources) do
    %Config{} = config = Config.get()
    Config.put(%Config{config | sources: sources})
  end

  defp local, do: %Password{name: "local", repo: Repo, hasher: Macaw.Auth.Native.Hasher.Bcrypt}

  defp with_app_env(key, value) do
    previous = Application.fetch_env(:macaw_auth, key)
    Application.put_env(:macaw_auth, key, value)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:macaw_auth, key, value)
        :error -> Application.delete_env(:macaw_auth, key)
      end
    end)
  end

  describe "the sections of spec 05" do
    @tag verifies: "auth-native"
    test "the native backend implements every backend callback, its sessions those of Sessions" do
      for {name, arity} <- Macaw.Auth.Backend.behaviour_info(:callbacks) do
        assert function_exported?(Native, name, arity), "#{name}/#{arity}"
      end

      user = Native.to_user(local_user!("ana", "correct horse battery"))
      assert {:ok, token, session} = Native.create_session(user, [])
      assert {:ok, %User{id: id}, %{id: sid}} = Sessions.fetch(token, [])
      assert {id, sid} == {user.id, session.id}
      assert [%{id: ^sid}] = Native.list_sessions(user.id, [])
    end

    @tag verifies: "auth-native-authenticate"
    test "authenticate/2: the throttle first, then the chain, then the counts" do
      configure!(hasher: CountingHasher)
      local_user!("bea", "correct horse battery")

      # A missing or non-string value counts as "": checked, and refused.
      assert Native.authenticate(%{username: "bea", password: 123}) ==
               {:error, :invalid_credentials}

      assert_received {:hasher, :verify}
      assert Native.authenticate(%{username: "bea"}) == {:error, :invalid_credentials}

      # A refusal counts a failure for the username, normalized, and the address,
      # a tuple as its string.
      Throttle.reset()
      for _ <- 1..5, do: sign_in(" BEA", "wrong", now: at(0), remote_ip: {192, 0, 2, 7})
      assert Throttle.check("bea", nil, ms(0)) == {:delay, 1_000}
      assert Throttle.check("someone", "192.0.2.7", ms(0)) == {:delay, 1_000}

      # Anything that can't be a username shares one key.
      Throttle.reset()
      for name <- ["Not A Name!", "also not!", "", "-x", "?"], do: sign_in(name, "x", now: at(0))
      assert Throttle.check(:invalid, nil, ms(0)) == {:delay, 1_000}

      # A success resets the username's count, not the address's.
      Throttle.reset()
      for _ <- 1..4, do: sign_in("bea", "wrong", now: at(0), remote_ip: "198.51.100.3")

      assert {:ok, %User{username: "bea"}} =
               sign_in("bea", "correct horse battery", now: at(0), remote_ip: "198.51.100.3")

      assert Throttle.check("bea", nil, ms(0)) == :ok
      sign_in("other", "wrong", now: at(0), remote_ip: "198.51.100.3")
      assert Throttle.check("x", "198.51.100.3", ms(0)) == {:delay, 1_000}
    end

    @tag verifies: "auth-native-refusal"
    test "whatever the source's reason, the caller sees one refusal; telemetry sees the reason" do
      ref = :telemetry_test.attach_event_handlers(self(), [@event])
      local_user!("cy", "correct horse battery")

      # A directory that couldn't be reached, as the only source.
      chain([struct!(FakeDirectory, name: "down", reachable: false)])
      assert sign_in("cy", "x") == {:error, :invalid_credentials}
      assert_received {@event, ^ref, _, %{reason: :connect_failed, source: "down"}}

      # A provisioning refusal: a directory's "cy" is the local user's row.
      directory = struct!(FakeDirectory, name: "nas", entries: %{"cy" => %{password: "dir pw"}})
      chain([directory, local()])
      assert sign_in("cy", "dir pw") == {:error, :invalid_credentials}
      assert_received {@event, ^ref, _, %{reason: :username_taken, source: "nas"}}

      # An unknown user at the local source: its own reason, :no_user.
      chain([local()])
      assert sign_in("nobody", "x") == {:error, :invalid_credentials}
      assert_received {@event, ^ref, _, %{reason: :no_user, source: "local"}}
    end

    @tag verifies: "auth-native-throttled"
    test "while a wait runs: not checked, a hash's time spent, :throttled, and not counted" do
      configure!(hasher: CountingHasher)
      local_user!("dee", "correct horse battery")
      for _ <- 1..5, do: sign_in("dee", "wrong", now: at(0))
      flush_hasher()

      for t <- [0, 500, 999] do
        assert sign_in("dee", "correct horse battery", now: at(t)) == {:error, :throttled}
        assert_received {:hasher, :no_user_verify}
        refute_received {:hasher, :verify}
      end

      # Still five failures: the wait is the fifth's, one second.
      assert Throttle.check("dee", nil, ms(999)) == {:delay, 1}
      assert Throttle.check("dee", nil, ms(1_000)) == :ok
    end

    @tag verifies: "auth-native-telemetry"
    test "every attempt emits one event, its metadata exactly the four keys, never the username" do
      ref = :telemetry_test.attach_event_handlers(self(), [@event])
      record = local_user!("eli", "correct horse battery")

      sign_in("eli", "correct horse battery")

      assert_received {@event, ^ref, %{count: 1},
                       %{result: :ok, reason: nil, source: "local", user_id: id} = meta}

      assert id == record.id
      assert map_size(meta) == 4

      sign_in("nobody-here", "a secret guess")
      assert_received {@event, ^ref, %{count: 1}, meta}
      assert meta == %{result: :error, reason: :no_user, source: "local", user_id: nil}

      for _ <- 1..5, do: sign_in("eli", "wrong", now: at(0))
      flush_events(ref)
      sign_in("eli", "a secret guess", now: at(0))
      assert_received {@event, ^ref, %{count: 1}, meta}
      assert meta == %{result: :error, reason: :throttled, source: nil, user_id: nil}
      refute inspect(meta) =~ "eli"
      refute_received {@event, ^ref, _, _}
    end

    @tag verifies: "auth-native-config-load"
    test "parse/2's environment, load!/0 at boot and once, get/0 at first use, put/1" do
      search = %{base_dn: "dc=x", bind_dn: "cn=svc", bind_password: {:env, "MACAW_AUTH_TEST_PW"}}

      ldap = %{
        type: :ldap,
        name: "nas",
        host: "ldap",
        ssl: false,
        starttls: true,
        search: search
      }

      # The environment is the process's by default.
      System.put_env("MACAW_AUTH_TEST_PW", "from the process")
      on_exit(fn -> System.delete_env("MACAW_AUTH_TEST_PW") end)

      assert {:ok, %Config{sources: [%{bind_password: "from the process"}]}} =
               Config.parse(repo: Repo, sources: [ldap])

      # load!/0 parses the application's configuration and keeps it.
      with_app_env(Native, repo: Repo, session_idle_days: 3)
      assert %Config{session_idle_days: 3} = Config.load!()
      assert %Config{session_idle_days: 3} = Config.get()

      # get/0 loads it at first use when nothing was kept.
      :persistent_term.erase(Config)
      with_app_env(Native, repo: Repo, session_idle_days: 4)
      assert %Config{session_idle_days: 4} = Config.get()

      # put/1 replaces it.
      {:ok, five} = Config.parse(repo: Repo, session_idle_days: 5)
      assert Config.put(five) == five
      assert Config.get() == five

      # The application reads it at start when the backend is native: a fault
      # refuses to start.
      with_app_env(:backend, Native)
      with_app_env(Native, repo: Repo, session_idle_days: 0)

      assert_raise Config.Error,
                   "config :macaw_auth, Macaw.Auth.Native: session_idle_days: must be an integer in 1..3650, got 0",
                   fn -> Macaw.Auth.Application.start(:normal, []) end
    end

    @tag verifies: "auth-native-users"
    test "to_user/1 maps a row; create_user/1 makes a local user of the configured password source" do
      disabled_at = DateTime.utc_now()

      row = %UserRecord{
        id: "u1",
        username: "fay",
        display_name: "Fay",
        source: "nas",
        roles: nil,
        disabled_at: disabled_at,
        must_change_password: true,
        extra: nil
      }

      assert Native.to_user(row) == %User{
               id: "u1",
               username: "fay",
               display_name: "Fay",
               source: "nas",
               roles: [],
               disabled: true,
               second_factor: :none,
               must_change_password: true,
               extra: %{}
             }

      # second_factor follows the configured policy.
      configure!(totp_required: true)
      assert Native.to_user(row).second_factor == :required

      # Optional fields, and the source the configured password source's name.
      chain([%Password{local() | name: "staff"}])

      assert {:ok, gus} =
               Native.create_user(%{
                 username: "gus",
                 password: "a long password",
                 display_name: "Gus",
                 roles: ["admin"],
                 must_change_password: true,
                 extra: %{"email" => "gus@example.test"}
               })

      assert {gus.source, gus.display_name, gus.roles, gus.must_change_password, gus.extra} ==
               {"staff", "Gus", ["admin"], true, %{"email" => "gus@example.test"}}

      # With no password source configured, "local".
      chain([struct!(FakeDirectory, name: "nas")])

      assert {:ok, %UserRecord{source: "local"}} =
               Native.create_user(%{username: "hal", password: "pw"})

      # A bad username is a changeset error.
      assert {:error, %Ecto.Changeset{errors: [username: _]}} =
               Native.create_user(%{username: "not a name!", password: "pw"})
    end
  end

  defp flush_hasher do
    receive do
      {:hasher, _} -> flush_hasher()
    after
      0 -> :ok
    end
  end

  defp flush_events(ref) do
    receive do
      {@event, ^ref, _, _} -> flush_events(ref)
    after
      0 -> :ok
    end
  end
end
