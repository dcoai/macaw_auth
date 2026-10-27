defmodule Macaw.Auth.Native.SessionsTest do
  use Macaw.Auth.DataCase, async: false
  use ExUnitProperties

  import Ecto.Query, only: [where: 2]

  alias Macaw.Auth
  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.SessionRecord
  alias Macaw.Auth.Session

  @t0 ~U[2026-10-01 12:00:00.000000Z]
  @idle 14 * 86_400

  setup do
    previous = Application.get_env(:macaw_auth, :backend)
    Application.put_env(:macaw_auth, :backend, Native)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:macaw_auth, :backend, previous),
        else: Application.delete_env(:macaw_auth, :backend)
    end)

    :ok
  end

  defp user!(attrs \\ %{}) do
    n = System.unique_integer([:positive])
    "user#{n}" |> local_user!("correct horse #{n}", attrs) |> Native.to_user()
  end

  defp at(seconds), do: DateTime.add(@t0, seconds, :second)

  defp row(session), do: Repo.get!(SessionRecord, session.id)

  # A revocation racing the code under test: `revoke` runs once, right after
  # the first query on `table`, between the code's look-up and its write.
  defp after_first_query(table, revoke) do
    id = make_ref()

    :telemetry.attach(
      id,
      [:macaw, :auth, :test, :repo, :query],
      fn _event, _measurements, %{source: source}, _config ->
        if source == table do
          :telemetry.detach(id)
          revoke.()
        end
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(id) end)
  end

  defp delete_row(session),
    do: Repo.delete_all(where(SessionRecord, id: ^session.id))

  defp all_values do
    for table <- ["macaw_auth_sessions", "macaw_auth_users"],
        value <- List.flatten(Repo.query!("SELECT * FROM #{table}").rows),
        is_binary(value),
        do: value
  end

  describe "the token" do
    property "no form of a token is ever written, in any column of any row" do
      check all(n <- integer(1..6), max_runs: 15) do
        user = user!()

        tokens =
          for i <- 1..n do
            {:ok, token, _} =
              Native.create_session(user,
                remote_ip: "198.51.100.#{i}",
                user_agent: "agent #{i}",
                now: at(i)
              )

            token
          end

        values = all_values()

        for token <- tokens do
          assert byte_size(token) == 32

          forms = [
            token,
            Base.encode64(token),
            Base.url_encode64(token, padding: false),
            Base.encode16(token, case: :lower),
            Base.encode16(token)
          ]

          for value <- values, form <- forms do
            refute :binary.match(value, form) != :nomatch, "a token was written"
          end

          hash = :crypto.hash(:sha256, token)
          assert Repo.aggregate(where(SessionRecord, token_hash: ^hash), :count) == 1
          # The raw read sees the stored hash itself, so it reads what is there.
          assert hash in values
        end
      end
    end

    test "a session records the client, the user agent truncated to 255" do
      user = user!()

      {:ok, token, session} =
        Native.create_session(user,
          remote_ip: {203, 0, 113, 9},
          user_agent: String.duplicate("a", 400),
          now: @t0
        )

      assert %Session{remote_ip: "203.0.113.9", created_at: @t0, last_used_at: @t0} = session
      assert String.length(session.user_agent) == 255
      assert {:ok, _, %Session{user_agent: agent}} = Native.fetch_session(token, now: @t0)
      assert String.length(agent) == 255
    end

    test "a garbage token and an id that is no session are invalid" do
      assert Native.fetch_session(:crypto.strong_rand_bytes(32), []) == {:error, :invalid}
      assert Native.fetch_session_by_id("not-a-uuid", []) == {:error, :invalid}
      assert Native.fetch_session_by_id(Ecto.UUID.generate(), []) == {:error, :invalid}
      assert Native.fetch_session_by_id(nil, []) == {:error, :invalid}
    end

    test "a user deleted since signing in gets no session" do
      ref = :telemetry_test.attach_event_handlers(self(), [[:macaw_auth, :native, :session]])
      user = user!()
      Repo.delete_all(where(Native.UserRecord, id: ^user.id))

      assert Native.create_session(user, now: @t0) == {:error, :invalid}
      assert Native.create_session(%{user | id: "junk"}, now: @t0) == {:error, :invalid}
      assert Repo.aggregate(SessionRecord, :count) == 0
      refute_received {[:macaw_auth, :native, :session], ^ref, _, _}
    end

    test "creating a session emits telemetry without the token" do
      ref = :telemetry_test.attach_event_handlers(self(), [[:macaw_auth, :native, :session]])
      user = user!()
      {:ok, _token, _} = Native.create_session(user, now: @t0)
      uid = user.id

      assert_received {[:macaw_auth, :native, :session], ^ref, %{count: 1},
                       %{event: :created, reason: nil, user_id: ^uid} = meta}

      assert map_size(meta) == 3
    end
  end

  describe "idle expiry and touch, with an injected clock" do
    test "a session idle longer than session_idle_days expires and is deleted" do
      ref = :telemetry_test.attach_event_handlers(self(), [[:macaw_auth, :native, :session]])
      user = user!()
      {:ok, token, session} = Native.create_session(user, now: @t0)

      assert {:ok, _, _} = Native.fetch_session(token, touch: false, now: at(@idle))
      assert Native.fetch_session(token, touch: false, now: at(@idle + 1)) == {:error, :expired}
      assert Repo.get(SessionRecord, session.id) == nil
      assert Native.fetch_session(token, now: at(@idle + 1)) == {:error, :invalid}

      uid = user.id

      assert_received {[:macaw_auth, :native, :session], ^ref, _,
                       %{event: :expired, reason: :idle, user_id: ^uid}}
    end

    test "the idle period is configured" do
      configure!(session_idle_days: 1)
      {:ok, token, _} = Native.create_session(user!(), now: @t0)
      assert {:ok, _, _} = Native.fetch_session(token, now: at(86_400))
      assert Native.fetch_session(token, now: at(86_401)) == {:error, :expired}
    end

    test "the backend reports its idle limit in seconds" do
      assert Native.session_idle_seconds([]) == @idle
      assert Auth.session_idle_seconds() == @idle
      configure!(session_idle_days: 1)
      assert Native.session_idle_seconds([]) == 86_400
    end

    test "touch: true writes last_used_at at most hourly, and so extends the session" do
      {:ok, token, session} = Native.create_session(user!(), now: @t0)

      assert {:ok, _, %{last_used_at: @t0}} =
               Native.fetch_session(token, touch: true, now: at(3_599))

      assert row(session).last_used_at == @t0

      later = at(3_600)

      assert {:ok, _, %{last_used_at: ^later}} =
               Native.fetch_session(token, touch: true, now: later)

      assert row(session).last_used_at == later

      assert {:ok, _, %{last_used_at: ^later}} =
               Native.fetch_session(token, touch: true, now: at(3_600 + 60))

      # Idle from the touch, not from creation.
      assert {:ok, _, _} = Native.fetch_session(token, touch: false, now: at(3_600 + @idle))

      assert Native.fetch_session(token, touch: false, now: at(3_600 + @idle + 1)) ==
               {:error, :expired}
    end

    test "touch: false never extends, by token or by id" do
      {:ok, token, session} = Native.create_session(user!(), now: @t0)

      for hours <- [2, 30, 24 * 13] do
        assert {:ok, _, _} = Native.fetch_session(token, touch: false, now: at(hours * 3_600))
        assert {:ok, _, _} = Native.fetch_session_by_id(session.id, now: at(hours * 3_600))
      end

      assert row(session).last_used_at == @t0
      assert Native.fetch_session_by_id(session.id, now: at(@idle + 1)) == {:error, :expired}
    end

    test "a touch racing a revocation is :invalid, never a crash" do
      {:ok, token, session} = Native.create_session(user!(), now: @t0)
      # The session is read, then its user: the revocation lands between
      # the look-up and the touch's write.
      after_first_query("macaw_auth_users", fn -> delete_row(session) end)

      assert Native.fetch_session(token, touch: true, now: at(3_600)) == {:error, :invalid}
      assert Repo.get(SessionRecord, session.id) == nil
    end

    test "the default is not to touch" do
      {:ok, token, session} = Native.create_session(user!(), now: @t0)
      assert {:ok, _, _} = Native.fetch_session(token, now: at(7_200))
      assert row(session).last_used_at == @t0
    end
  end

  describe "a disabled user" do
    test "has their session deleted and refused" do
      ref = :telemetry_test.attach_event_handlers(self(), [[:macaw_auth, :native, :session]])
      user = user!()
      {:ok, token, session} = Native.create_session(user, now: @t0)

      Native.UserRecord
      |> Repo.get!(user.id)
      |> Ecto.Changeset.change(disabled_at: @t0)
      |> Repo.update!()

      assert Native.fetch_session(token, now: @t0) == {:error, :disabled}
      assert Repo.get(SessionRecord, session.id) == nil
      assert Native.fetch_session(token, now: @t0) == {:error, :invalid}

      uid = user.id

      assert_received {[:macaw_auth, :native, :session], ^ref, %{count: 1},
                       %{event: :revoked, reason: :disabled, user_id: ^uid}}
    end
  end

  describe "listing" do
    test "newest first, by created at and then id when timestamps tie" do
      user = user!()
      {:ok, _, old} = Native.create_session(user, now: at(0))
      tied = for _ <- 1..3, do: elem(Native.create_session(user, now: at(10)), 2)
      {:ok, _, new} = Native.create_session(user, now: at(20))
      {:ok, _, _other} = Native.create_session(user!(), now: at(30))

      ids = Enum.map(Native.list_sessions(user.id, []), & &1.id)
      tied_ids = tied |> Enum.map(& &1.id) |> Enum.sort(:desc)
      assert ids == [new.id] ++ tied_ids ++ [old.id]
    end

    test "an id that is no user lists nothing" do
      assert Native.list_sessions("nope", []) == []
      assert Native.list_sessions(Ecto.UUID.generate(), []) == []
    end
  end

  describe "revocation" do
    test "one session, or a user's but one; only deleting, no push" do
      user = user!()
      {:ok, _, a} = Native.create_session(user, [])
      {:ok, _, b} = Native.create_session(user, [])
      {:ok, _, c} = Native.create_session(user, [])
      :ok = Auth.subscribe(user.id)

      assert Native.revoke_sessions(a.id, []) == {user.id, [a.id]}
      assert Native.revoke_sessions(a.id, []) == {nil, []}

      assert {uid, [id]} = Native.revoke_sessions({:user, user.id}, except: c.id)
      assert {uid, id} == {user.id, b.id}
      assert Enum.map(Native.list_sessions(user.id, []), & &1.id) == [c.id]
      assert Native.revoke_sessions({:user, user.id}, except: "not-an-id") == {user.id, [c.id]}
      assert Native.revoke_sessions({:user, user.id}, []) == {user.id, []}

      refute_received {:sessions_revoked, _}
    end

    test "an id that is nothing revokes nothing" do
      assert Native.revoke_sessions("junk", []) == {nil, []}
      assert Native.revoke_sessions({:user, "junk"}, []) == {"junk", []}
    end

    test "the reason goes to telemetry" do
      ref = :telemetry_test.attach_event_handlers(self(), [[:macaw_auth, :native, :session]])
      user = user!()
      for _ <- 1..2, do: Native.create_session(user, [])
      :ok = Auth.revoke({:user, user.id}, reason: :password_changed)

      assert_received {[:macaw_auth, :native, :session], ^ref, %{count: 2},
                       %{event: :revoked, reason: :password_changed}}
    end
  end

  describe "revocation reaches an open page, through the facade" do
    defp open_page(user_id) do
      test = self()

      pid =
        spawn_link(fn ->
          :ok = Auth.subscribe(user_id)
          send(test, :subscribed)

          receive do
            message -> send(test, {:page, message})
          end
        end)

      assert_receive :subscribed
      pid
    end

    test "with the local Registry" do
      user = user!()
      {:ok, token, session} = Native.create_session(user, [])
      open_page(user.id)

      :ok = Auth.revoke(session.id)

      assert_receive {:page, {:sessions_revoked, [id]}}
      assert id == session.id
      assert Auth.fetch(token) == {:error, :invalid}
    end

    test "with Phoenix.PubSub" do
      start_supervised!({Phoenix.PubSub, name: Macaw.Auth.Test.PubSub})
      Application.put_env(:macaw_auth, :pubsub, Macaw.Auth.Test.PubSub)
      on_exit(fn -> Application.delete_env(:macaw_auth, :pubsub) end)

      user = user!()
      {:ok, _, keep} = Native.create_session(user, [])
      {:ok, _, gone} = Native.create_session(user, [])
      open_page(user.id)

      :ok = Auth.revoke({:user, user.id}, except: keep.id)

      assert_receive {:page, {:sessions_revoked, [id]}}
      assert id == gone.id
    end
  end

  describe "steps" do
    test "the second factor is marked passed; other steps are kept as names" do
      user = user!(%{must_change_password: true})
      {:ok, token, session} = Native.create_session(user, second_factor_passed: false)
      assert %Session{second_factor_passed: false, completed_steps: []} = session

      :ok = Native.complete_step(session.id, :second_factor, [])
      :ok = Native.complete_step(session.id, :password_change, [])
      :ok = Native.complete_step(session.id, :password_change, [])

      assert {:ok, user,
              %Session{second_factor_passed: true, completed_steps: [:password_change]}} =
               Native.fetch_session(token, [])

      assert row(session).completed_steps == ["password_change"]
      assert Auth.pending_step(user, elem(Native.fetch_session(token, []), 2)) == nil
    end

    test "a stored name that is no step is dropped, never made an atom" do
      {:ok, token, session} = Native.create_session(user!(), [])

      session
      |> row()
      |> Ecto.Changeset.change(completed_steps: ["password_change", "no_such_step_xyz"])
      |> Repo.update!()

      assert {:ok, _, %Session{completed_steps: [:password_change]}} =
               Native.fetch_session(token, [])

      assert_raise ArgumentError, fn -> String.to_existing_atom("no_such_step_xyz") end
    end

    test "completing a step of a session that doesn't exist is :invalid" do
      for step <- Auth.steps(), id <- [Ecto.UUID.generate(), "junk"] do
        assert Native.complete_step(id, step, []) == {:error, :invalid}
      end
    end

    test "a password change racing a revocation is :invalid, and the session stays gone" do
      {:ok, _token, session} = Native.create_session(user!(), [])
      # Revoked between the step's read of the row and its write.
      after_first_query("macaw_auth_sessions", fn -> delete_row(session) end)

      assert Native.complete_step(session.id, :password_change, []) == {:error, :invalid}
      assert Repo.get(SessionRecord, session.id) == nil
    end
  end
end
