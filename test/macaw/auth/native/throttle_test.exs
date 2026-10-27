defmodule Macaw.Auth.Native.ThrottleTest do
  use Macaw.Auth.DataCase, async: false

  import Plug.Test

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.Throttle

  @t0 ~U[2026-10-01 12:00:00.000Z]
  @cap 15 * 60 * 1000

  defp at(ms), do: DateTime.add(@t0, ms, :millisecond)
  defp ms(ms), do: DateTime.to_unix(@t0, :millisecond) + ms

  defp sign_in(username, password, ms, ip \\ "192.0.2.1"),
    do: Native.authenticate(%{username: username, password: password}, now: at(ms), remote_ip: ip)

  defp fail_times(n, username, ms, ip \\ "192.0.2.1") do
    for _ <- 1..n,
        do: assert(sign_in(username, "wrong", ms, ip) == {:error, :invalid_credentials})
  end

  @tag verifies: "throttle-delays"
  test "the wait: none for four failures, 2^(n-5) s from the fifth, capped at 15 minutes" do
    assert Enum.map(0..4, &Throttle.delay_ms/1) == [0, 0, 0, 0, 0]
    assert Enum.map(5..9, &Throttle.delay_ms/1) == [1_000, 2_000, 4_000, 8_000, 16_000]
    assert Throttle.delay_ms(14) == 512_000
    assert Throttle.delay_ms(15) == @cap
    assert Throttle.delay_ms(1_000_000) == @cap
  end

  @tag verifies: "throttle-wait"
  test "five failures, then each attempt waits, and a block doesn't check the password" do
    local_user!("ivan", "correct horse battery")
    fail_times(5, "ivan", 0)

    assert sign_in("ivan", "correct horse battery", 0) == {:error, :throttled}
    assert sign_in("ivan", "correct horse battery", 999) == {:error, :throttled}

    # The wait passed: checked again, and a sixth failure doubles it.
    assert sign_in("ivan", "wrong", 1_000) == {:error, :invalid_credentials}
    assert sign_in("ivan", "correct horse battery", 2_999) == {:error, :throttled}
    assert {:ok, _} = sign_in("ivan", "correct horse battery", 3_000)
  end

  @tag verifies: "native-throttled-not-counted"
  test "attempts inside the wait aren't failures: the next wait grows only with checked ones" do
    local_user!("una", "correct horse battery")
    fail_times(5, "una", 0)

    # Ten retries inside the one-second wait, all refused unchecked.
    for ms <- 0..900//100, do: assert(sign_in("una", "wrong", ms) == {:error, :throttled})

    # A sixth checked failure after the wait: the next wait is two seconds, not more.
    assert sign_in("una", "wrong", 1_000) == {:error, :invalid_credentials}
    assert Throttle.check("una", "192.0.2.1", ms(1_000)) == {:delay, 2_000}
    assert {:ok, _} = sign_in("una", "correct horse battery", 3_000)
  end

  @tag verifies: "throttle-cap"
  test "the cap: the wait never exceeds 15 minutes" do
    for _ <- 1..40, do: Throttle.failure("judy", nil, ms(0))
    assert Throttle.check("judy", nil, ms(0)) == {:delay, @cap}
    assert Throttle.check("judy", nil, ms(@cap - 1)) == {:delay, 1}
    assert Throttle.check("judy", nil, ms(@cap)) == :ok
  end

  @tag verifies: "throttle-success-resets-user"
  test "a success resets the username's count" do
    local_user!("kim", "correct horse battery")
    fail_times(5, "kim", 0)
    assert {:ok, _} = sign_in("kim", "correct horse battery", 1_000, "192.0.2.50")

    # Five free failures again (from another address, so only the username counts).
    fail_times(4, "kim", 1_000, "192.0.2.51")
    assert {:ok, _} = sign_in("kim", "correct horse battery", 1_000, "192.0.2.51")
  end

  @tag verifies: "throttle-success-keeps-address"
  test "a success doesn't reset the address's count" do
    local_user!("lee", "correct horse battery")
    for i <- 1..5, do: sign_in("guess#{i}", "x", 0, "192.0.2.9")
    assert sign_in("lee", "correct horse battery", 0, "192.0.2.9") == {:error, :throttled}

    assert {:ok, _} = sign_in("lee", "correct horse battery", 1_000, "192.0.2.9")
    assert sign_in("guess9", "x", 1_000, "192.0.2.9") == {:error, :invalid_credentials}
    assert sign_in("lee", "correct horse battery", 1_001, "192.0.2.9") == {:error, :throttled}
  end

  @tag verifies: "throttle-per-address"
  test "per address: one address trying many usernames waits, another address doesn't" do
    local_user!("mia", "correct horse battery")
    for i <- 1..5, do: sign_in("user#{i}", "wrong", 0, "198.51.100.1")

    assert sign_in("mia", "correct horse battery", 0, "198.51.100.1") == {:error, :throttled}
    assert {:ok, _} = sign_in("mia", "correct horse battery", 0, "198.51.100.2")
  end

  @tag verifies: "throttle-per-username"
  test "per username: many addresses trying one username wait, other usernames don't" do
    local_user!("ned", "correct horse battery")
    local_user!("oli", "correct horse battery")
    for i <- 1..5, do: sign_in("ned", "wrong", 0, "203.0.113.#{i}")

    assert sign_in("ned", "correct horse battery", 0, "203.0.113.99") == {:error, :throttled}
    assert {:ok, _} = sign_in("oli", "correct horse battery", 0, "203.0.113.99")
  end

  @tag verifies: "throttle-normalized"
  test "the username key is the normalized username" do
    local_user!("pat", "correct horse battery")
    for name <- ["Pat", " PAT ", "pat", "pAt", "pat "], do: sign_in(name, "wrong", 0, nil)
    assert sign_in("pat", "correct horse battery", 0, nil) == {:error, :throttled}
  end

  @tag verifies: "throttle-no-address"
  test "no address, no address key" do
    for i <- 1..5, do: sign_in("nobody#{i}", "wrong", 0, nil)
    assert sign_in("nobody6", "wrong", 0, nil) == {:error, :invalid_credentials}
  end

  @tag verifies: "plug-authenticate-ip"
  test "the plug's authenticate counts the connection's address" do
    Application.put_env(:macaw_auth, :backend, Native)
    on_exit(fn -> Application.delete_env(:macaw_auth, :backend) end)
    local_user!("quinn", "correct horse battery")
    conn = %{conn(:post, "/login") | remote_ip: {198, 51, 100, 77}}

    for i <- 1..5,
        do: Macaw.Auth.Plug.authenticate(conn, %{username: "u#{i}", password: "x"}, now: at(0))

    assert Throttle.check("quinn", "198.51.100.77", ms(0)) == {:delay, 1_000}
  end

  @tag verifies: "native-telemetry-throttled"
  test "a throttled refusal goes to telemetry" do
    fail_times(5, "rae", 0)
    ref = :telemetry_test.attach_event_handlers(self(), [[:macaw_auth, :native, :authenticate]])
    assert sign_in("rae", "x", 0) == {:error, :throttled}

    assert_received {[:macaw_auth, :native, :authenticate], ^ref, %{count: 1},
                     %{result: :error, reason: :throttled, user_id: nil}}
  end

  describe "a block takes a hash's time" do
    @tag verifies: "native-throttled-no-hash-check"
    test "it spends the hasher's no-user verification, and checks nothing" do
      configure!(hasher: Macaw.Auth.Test.CountingHasher)
      local_user!("sam", "correct horse battery")
      fail_times(5, "sam", 0)
      flush_hasher()

      assert sign_in("sam", "correct horse battery", 0) == {:error, :throttled}
      assert_received {:hasher, :no_user_verify}
      refute_received {:hasher, :verify}
    end

    @tag verifies: "throttle-timing-work"
    test "a blocked wrong guess spends the no-user verification too, and verifies nothing" do
      configure!(hasher: Macaw.Auth.Test.CountingHasher)
      local_user!("sue", "correct horse battery")
      fail_times(5, "sue", 0)
      flush_hasher()

      assert sign_in("sue", "wrong again", 0) == {:error, :throttled}
      assert_received {:hasher, :no_user_verify}
      refute_received {:hasher, :verify}
    end

    # As the password source's timing test: at a real cost, the hash
    # dominates; medians and a 3x margin keep a busy runner from failing it.
    @tag verifies: "throttle-timing-measured"
    test "measured: a blocked attempt and a checked one are within a factor of three" do
      previous = Application.get_env(:bcrypt_elixir, :log_rounds)
      Application.put_env(:bcrypt_elixir, :log_rounds, 9)
      on_exit(fn -> Application.put_env(:bcrypt_elixir, :log_rounds, previous) end)
      local_user!("tess", "correct horse battery")

      checked =
        median(fn ->
          Throttle.reset()
          {:error, :invalid_credentials} = sign_in("tess", "wrong", 0)
        end)

      for _ <- 1..5, do: Throttle.failure("tess", nil, ms(0))
      blocked = median(fn -> {:error, :throttled} = sign_in("tess", "wrong", 0) end)

      assert blocked < checked * 3 and checked < blocked * 3,
             "blocked #{blocked}us, checked #{checked}us"
    end
  end

  defp median(fun) do
    times = for _ <- 1..9, do: elem(:timer.tc(fun), 0)
    times |> Enum.sort() |> Enum.at(4)
  end

  defp flush_hasher do
    receive do
      {:hasher, _} -> flush_hasher()
    after
      0 -> :ok
    end
  end

  describe "a failure is one atomic update" do
    # spec/10 §6-7: the count and the time change together, and the time is the
    # latest failure's, in whatever order the failures arrive.
    @tag verifies: "throttle-failure-order"
    test "a failure that arrives second keeps the later time" do
      for _ <- 1..5, do: Throttle.failure("yan", "192.0.2.4", ms(0))
      Throttle.failure("yan", "192.0.2.4", ms(2_000))
      Throttle.failure("yan", "192.0.2.4", ms(1_000))

      assert :ets.lookup(Throttle, {:user, "yan"}) == [{{:user, "yan"}, 7, ms(2_000)}]
      assert :ets.lookup(Throttle, {:ip, "192.0.2.4"}) == [{{:ip, "192.0.2.4"}, 7, ms(2_000)}]
      # Seven failures wait 4 s from the latest, at 2 000, not from the one at 1 000.
      assert Throttle.check("yan", "192.0.2.4", ms(5_999)) == {:delay, 1}
      assert Throttle.check("yan", "192.0.2.4", ms(6_000)) == :ok
    end

    @tag verifies: "throttle-failure-concurrent"
    test "concurrent failures each count, and the latest time stands" do
      times = Enum.shuffle(1..400)

      times
      |> Task.async_stream(&Throttle.failure("zed", "192.0.2.5", ms(&1)),
        max_concurrency: System.schedulers_online() * 4
      )
      |> Stream.run()

      assert :ets.lookup(Throttle, {:user, "zed"}) == [{{:user, "zed"}, 400, ms(400)}]
      assert :ets.lookup(Throttle, {:ip, "192.0.2.5"}) == [{{:ip, "192.0.2.5"}, 400, ms(400)}]
    end
  end

  describe "the sweep" do
    @tag verifies: "throttle-sweep"
    test "forgets keys whose last failure is over a day old" do
      day = 24 * 60 * 60 * 1000
      for _ <- 1..5, do: Throttle.failure("uma", "192.0.2.3", ms(0))
      Throttle.failure("vic", nil, ms(day))

      assert Throttle.sweep(ms(day)) == 0
      assert Throttle.sweep(ms(day + 1)) == 2
      assert Throttle.check("uma", "192.0.2.3", ms(day + 1)) == :ok
      assert :ets.lookup(Throttle, {:user, "vic"}) != []
    end

    @tag verifies: "throttle-sweep-owner"
    test "the table's owner sweeps on its own" do
      old = Throttle.now() - 2 * 24 * 60 * 60 * 1000
      Throttle.failure("wes", nil, old)
      Throttle.failure("xan", nil, Throttle.now())

      owner = Process.whereis(Throttle)
      send(owner, :sweep)
      :sys.get_state(owner)

      assert :ets.lookup(Throttle, {:user, "wes"}) == []
      assert [{_, 1, _}] = :ets.lookup(Throttle, {:user, "xan"})
    end
  end

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 10" do
    alias Macaw.Auth.Native.{Config, Totp, UserRecord}

    @day 24 * 60 * 60 * 1000

    defp rows, do: :ets.tab2list(Throttle) |> Enum.sort()

    @tag verifies: "auth-throttle"
    test "the values are constants, which no setting changes: five free, 2^(n-5) s, the cap, a day" do
      assert {:error, _} = Config.parse(repo: Repo, throttle: [free: 10])
      assert {:error, _} = Config.parse(repo: Repo, free_failures: 10)

      Application.put_env(:macaw_auth, :throttle, free: 10, cap_ms: 1)
      on_exit(fn -> Application.delete_env(:macaw_auth, :throttle) end)

      assert Throttle.delay_ms(4) == 0
      assert Throttle.delay_ms(5) == 1_000
      assert Throttle.delay_ms(40) == @cap

      Throttle.failure("ava", "192.0.2.60", ms(0))
      assert Throttle.sweep(ms(@day)) == 0
      assert Throttle.sweep(ms(@day + 1)) == 2
    end

    @tag verifies: "auth-throttle-keys"
    test "the keys: the normalized username or :invalid, the address as a string; the longer wait wins" do
      for name <- ["Bea ", "not a name!", "@@"],
          do:
            Native.authenticate(%{username: name, password: "x"},
              now: at(0),
              remote_ip: {192, 0, 2, 70}
            )

      assert rows() == [
               {{:ip, "192.0.2.70"}, 3, ms(0)},
               {{:user, :invalid}, 2, ms(0)},
               {{:user, "bea"}, 1, ms(0)}
             ]

      # check/3: the longer of the two keys' waits.
      for _ <- 1..6, do: Throttle.failure("cal", nil, ms(0))
      for _ <- 1..5, do: Throttle.failure("other", "192.0.2.71", ms(0))
      assert Throttle.check("cal", "192.0.2.71", ms(0)) == {:delay, 2_000}
      assert Throttle.check("dee", "192.0.2.71", ms(0)) == {:delay, 1_000}
      assert Throttle.check("dee", "192.0.2.72", ms(0)) == :ok

      # failure/3 counts on both keys.
      Throttle.reset()
      assert Throttle.failure("dee", "192.0.2.72", ms(5)) == :ok
      assert rows() == [{{:ip, "192.0.2.72"}, 1, ms(5)}, {{:user, "dee"}, 1, ms(5)}]

      # now/0 is the system clock in milliseconds.
      before = System.system_time(:millisecond)
      now = Throttle.now()
      assert before <= now and now <= System.system_time(:millisecond)
    end

    @tag verifies: "auth-throttle-backoff"
    test "nothing is locked for good: at the cap, the right password succeeds once the wait passed" do
      local_user!("eli", "correct horse battery")
      for _ <- 1..40, do: Throttle.failure("eli", "192.0.2.1", ms(0))

      assert sign_in("eli", "correct horse battery", @cap - 1) == {:error, :throttled}
      assert {:ok, _} = sign_in("eli", "correct horse battery", @cap)

      # From the key's last failure, and another checked failure doubles the wait.
      fail_times(5, "fay", 0, "192.0.2.80")
      assert sign_in("fay", "wrong", 1_000, "192.0.2.80") == {:error, :invalid_credentials}
      assert Throttle.check("fay", "192.0.2.80", ms(1_000)) == {:delay, 2_000}
    end

    @tag verifies: "auth-throttle-reset"
    test "success/1 forgets the username's key and only it; a sign-in resets the normalized name" do
      Throttle.failure("gus", "192.0.2.90", ms(0))
      assert Throttle.success("gus") == :ok
      assert rows() == [{{:ip, "192.0.2.90"}, 1, ms(0)}]

      local_user!("gus", "correct horse battery")
      Throttle.failure("gus", "192.0.2.91", ms(0))
      assert {:ok, _} = sign_in(" GUS", "correct horse battery", 0, "192.0.2.91")
      assert :ets.lookup(Throttle, {:user, "gus"}) == []
      assert [{_, 1, _}] = :ets.lookup(Throttle, {:ip, "192.0.2.91"})
    end

    @tag verifies: "auth-throttle-second-factor"
    test "codes: their own username key, the sign-in's address key, a wrong code counts, others don't" do
      key = :crypto.strong_rand_bytes(32)
      configure!(sealing_key: key, hasher: Macaw.Auth.Test.CountingHasher)

      t0 = at(0)
      user = "hal" |> local_user!("correct horse battery") |> Native.to_user()

      # Not started: refused, and not counted.
      assert Native.enroll_confirm(user, "000001", now: t0, remote_ip: "192.0.2.95") ==
               {:error, :not_started}

      assert rows() == []

      {:ok, %{secret: secret}} = Native.enroll_begin(user)
      opts = [now: t0, remote_ip: "192.0.2.95"]
      assert Native.enroll_confirm(user, "000001", opts) == {:error, :invalid_code}

      assert :ets.lookup(Throttle, {:user, {:second_factor, "hal"}}) == [
               {{:user, {:second_factor, "hal"}}, 1, DateTime.to_unix(t0, :millisecond)}
             ]

      assert :ets.lookup(Throttle, {:user, "hal"}) == []

      # An accepted code resets the user's second-factor key, never the address.
      assert {:ok, _codes} = Native.enroll_confirm(user, Totp.code(secret, t0), opts)
      assert :ets.lookup(Throttle, {:user, {:second_factor, "hal"}}) == []
      assert [{_, 1, _}] = :ets.lookup(Throttle, {:ip, "192.0.2.95"})

      # Code failures from an address slow sign-ins from it.
      user = UserRecord |> Repo.get!(user.id) |> Native.to_user()
      {:ok, _, session} = Native.create_session(user, now: t0)

      for _ <- 1..4,
          do:
            assert(
              Native.verify_second_factor(session.id, "000001", opts) == {:error, :invalid_code}
            )

      flush_hasher()
      assert sign_in("hal", "correct horse battery", 0, "192.0.2.95") == {:error, :throttled}

      # A blocked code attempt spends no hash's time.
      flush_hasher()

      assert Native.verify_second_factor(session.id, Totp.code(secret, t0), opts) ==
               {:error, :throttled}

      refute_received {:hasher, _}

      # And the reverse: sign-in failures from an address slow codes from it.
      Throttle.reset()
      fail_times(5, "someone", 0, "192.0.2.96")
      from_there = [now: t0, remote_ip: "192.0.2.96"]
      assert Native.verify_second_factor(session.id, "000001", from_there) == {:error, :throttled}

      # A policy that requires one: disabling is refused, and not counted.
      Throttle.reset()
      configure!(sealing_key: key, totp_required: true)
      assert Native.disable(user, "000001", opts) == {:error, :required}
      assert rows() == []
    end

    @tag verifies: "auth-throttle-timing"
    test "whichever key blocks, a blocked attempt spends one hash's time, as a checked one does" do
      configure!(hasher: Macaw.Auth.Test.CountingHasher)
      local_user!("ida", "correct horse battery")

      # Checked: one verification.
      flush_hasher()
      assert sign_in("ida", "wrong", 0, "192.0.2.100") == {:error, :invalid_credentials}
      assert_received {:hasher, :verify}
      refute_received {:hasher, _}

      # Blocked by the username alone (another address), then by the address alone.
      for _ <- 1..5, do: Throttle.failure("ida", nil, ms(0))
      for _ <- 1..5, do: Throttle.failure("someone", "192.0.2.101", ms(0))

      for {name, ip} <- [{"ida", "192.0.2.102"}, {"jon", "192.0.2.101"}] do
        flush_hasher()
        assert sign_in(name, "wrong", 0, ip) == {:error, :throttled}
        assert_received {:hasher, :no_user_verify}
        refute_received {:hasher, _}
      end
    end

    @tag verifies: "auth-throttle-table"
    test "a named public table the application's throttle owns, rows {key, failures, last}, reset, and the owner's options" do
      owner = Process.whereis(Throttle)

      assert {Throttle, ^owner, :worker, _} =
               List.keyfind(Supervisor.which_children(Macaw.Auth.Supervisor), Throttle, 0)

      assert :ets.info(Throttle, :owner) == owner
      assert :ets.info(Throttle, :named_table)
      assert :ets.info(Throttle, :protection) == :public

      Throttle.failure("kai", nil, ms(7))
      assert rows() == [{{:user, "kai"}, 1, ms(7)}]
      assert Throttle.reset() == :ok
      assert rows() == []

      # The owner's :sweep_every_ms and :clock: a throttle started with them
      # sweeps on its own, at its clock's time.
      test = self()
      :ok = Supervisor.terminate_child(Macaw.Auth.Supervisor, Throttle)
      on_exit(fn -> {:ok, _} = Supervisor.restart_child(Macaw.Auth.Supervisor, Throttle) end)

      {:ok, pid} =
        Throttle.start_link(
          sweep_every_ms: 10,
          clock: fn ->
            send(test, :clock_read)
            ms(2 * @day)
          end
        )

      Throttle.failure("lou", nil, ms(0))
      Throttle.failure("max", nil, ms(2 * @day))
      assert_receive :clock_read
      :sys.get_state(pid)
      assert rows() == [{{:user, "max"}, 1, ms(2 * @day)}]
      :ok = GenServer.stop(pid)
    end
  end
end
