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

  # The user key the username's sign-in counts on: its account's, or the name's.
  defp key(username), do: Throttle.user_key(username)

  # The rows held for `key`, as `{key, failures, last}`.
  defp row(key), do: Enum.filter(Throttle.rows(), &(elem(&1, 0) == key))

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
    assert Throttle.check(key("una"), "192.0.2.1", ms(1_000)) == {:delay, 2_000}
    assert {:ok, _} = sign_in("una", "correct horse battery", 3_000)
  end

  @tag verifies: "throttle-cap"
  test "the cap: the wait never exceeds 15 minutes" do
    judy = {:name, "judy"}
    for _ <- 1..40, do: Throttle.failure(judy, nil, ms(0))
    assert Throttle.check(judy, nil, ms(0)) == {:delay, @cap}
    assert Throttle.check(judy, nil, ms(@cap - 1)) == {:delay, 1}
    assert Throttle.check(judy, nil, ms(@cap)) == :ok
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

    assert Throttle.check(key("quinn"), "198.51.100.77", ms(0)) == {:delay, 1_000}
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

    # As the password source's: the same time, checked by what runs, never
    # by timing two runs (#15). A checked attempt and a blocked one (a wrong
    # guess or the right password) are each exactly one bcrypt operation and
    # nothing else, and the stored hash is at the configured cost, the one
    # `no_user_verify/0` hashes at, so the operations are the same work.
    @tag verifies: "throttle-timing-measured"
    test "the same work: a blocked attempt and a checked one are each one bcrypt operation at the same cost" do
      alias Macaw.Auth.Native.Hasher.Bcrypt
      alias Macaw.Auth.Test.CountingHasher

      configure!(hasher: CountingHasher)
      tess = local_user!("tess", "correct horse battery")
      refute Bcrypt.needs_rehash?(tess.hashed_password)

      assert CountingHasher.work(fn ->
               assert sign_in("tess", "wrong", 0) == {:error, :invalid_credentials}
             end) == [:verify]

      for _ <- 1..5, do: Throttle.failure(key("tess"), nil, ms(0))

      for password <- ["wrong", "correct horse battery"] do
        assert CountingHasher.work(fn ->
                 assert sign_in("tess", password, 0) == {:error, :throttled}
               end) == [:no_user_verify]
      end
    end
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
      yan = {:name, "yan"}
      for _ <- 1..5, do: Throttle.failure(yan, "192.0.2.4", ms(0))
      Throttle.failure(yan, "192.0.2.4", ms(2_000))
      Throttle.failure(yan, "192.0.2.4", ms(1_000))

      assert row({:user, yan}) == [{{:user, yan}, 7, ms(2_000)}]
      assert row({:ip, "192.0.2.4"}) == [{{:ip, "192.0.2.4"}, 7, ms(2_000)}]
      # Seven failures wait 4 s from the latest, at 2 000, not from the one at 1 000.
      assert Throttle.check(yan, "192.0.2.4", ms(5_999)) == {:delay, 1}
      assert Throttle.check(yan, "192.0.2.4", ms(6_000)) == :ok
    end

    @tag verifies: "throttle-failure-concurrent"
    test "concurrent failures each count, and the latest time stands" do
      zed = {:name, "zed"}
      times = Enum.shuffle(1..400)

      # The tasks share the test's sandboxed connection (their callers'), so
      # here they take turns at it; the one statement is what makes each
      # failure count on a database with concurrent writers too.
      times
      |> Task.async_stream(&Throttle.failure(zed, "192.0.2.5", ms(&1)),
        max_concurrency: System.schedulers_online() * 4
      )
      |> Stream.run()

      assert row({:user, zed}) == [{{:user, zed}, 400, ms(400)}]
      assert row({:ip, "192.0.2.5"}) == [{{:ip, "192.0.2.5"}, 400, ms(400)}]
    end
  end

  describe "the sweep" do
    @tag verifies: "throttle-sweep"
    test "forgets keys whose last failure is over a day old" do
      day = 24 * 60 * 60 * 1000
      for _ <- 1..5, do: Throttle.failure({:name, "uma"}, "192.0.2.3", ms(0))
      Throttle.failure({:name, "vic"}, nil, ms(day))

      assert Throttle.sweep(ms(day)) == 0
      assert Throttle.sweep(ms(day + 1)) == 2
      assert Throttle.check({:name, "uma"}, "192.0.2.3", ms(day + 1)) == :ok
      assert Throttle.rows() == [{{:user, {:name, "vic"}}, 1, ms(day)}]
    end

    @tag verifies: "throttle-sweep-owner"
    test "the table's owner sweeps on its own" do
      old = Throttle.now() - 2 * 24 * 60 * 60 * 1000
      Throttle.failure({:name, "wes"}, nil, old)
      Throttle.failure({:name, "xan"}, nil, Throttle.now())

      # The owner sweeps through the test's sandboxed connection.
      owner = Process.whereis(Throttle)
      Ecto.Adapters.SQL.Sandbox.allow(Repo, self(), owner)
      send(owner, :sweep)
      :sys.get_state(owner)

      assert [{{:user, {:name, "xan"}}, 1, _}] = Throttle.rows()
    end
  end

  describe "kept in the database, per account" do
    @tag verifies: "throttle-restart"
    test "failures survive a restart of the throttle's process, on both keys" do
      local_user!("nell", "correct horse battery")
      fail_times(5, "nell", 0, "192.0.2.120")
      before = Throttle.rows()

      old = Process.whereis(Throttle)
      :ok = Supervisor.terminate_child(Macaw.Auth.Supervisor, Throttle)
      {:ok, new} = Supervisor.restart_child(Macaw.Auth.Supervisor, Throttle)
      assert new != old

      assert Throttle.rows() == before
      # The account waits from another address, and the address for another name.
      assert sign_in("nell", "correct horse battery", 999, "192.0.2.121") == {:error, :throttled}
      assert sign_in("someone", "x", 999, "192.0.2.120") == {:error, :throttled}
      assert {:ok, _} = sign_in("nell", "correct horse battery", 1_000, "192.0.2.121")
    end

    @tag verifies: "throttle-rename"
    test "a renamed account keeps its count; its old name is then a name no account has" do
      record = local_user!("nia", "correct horse battery")
      fail_times(5, "nia", 0, nil)
      record |> Ecto.Changeset.change(username: "nina") |> Repo.update!()

      assert key("nina") == {:account, record.id}
      assert sign_in("nina", "correct horse battery", 0, nil) == {:error, :throttled}

      assert key("nia") == {:name, "nia"}
      assert sign_in("nia", "correct horse battery", 0, nil) == {:error, :invalid_credentials}
      assert {:ok, _} = sign_in("nina", "correct horse battery", 1_000, nil)
    end

    # The curve over n failures, for an account and for a name no account
    # has: the same wait, and the same answer to the next attempt.
    @tag verifies: "throttle-unknown-name"
    test "an unknown name waits exactly as a known account does, failure for failure" do
      local_user!("kay", "correct horse battery")
      assert {:account, _} = key("kay")
      assert key("ghost") == {:name, "ghost"}

      waits =
        [0, 0, 0, 0, 0, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000] ++
          [64_000, 128_000, 256_000, 512_000, @cap, @cap]

      for {wait, n} <- Enum.with_index(waits) do
        Throttle.reset()
        for name <- ["kay", "ghost"], _ <- 1..n//1, do: Throttle.failure(key(name), nil, ms(0))

        expected = if wait == 0, do: :ok, else: {:delay, wait}

        assert Enum.map(["kay", "ghost"], &Throttle.check(key(&1), nil, ms(0))) == [
                 expected,
                 expected
               ],
               "#{n} failures"

        answer = if wait == 0, do: {:error, :invalid_credentials}, else: {:error, :throttled}
        assert Enum.map(["kay", "ghost"], &sign_in(&1, "wrong", 0, nil)) == [answer, answer]
      end
    end
  end

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 10" do
    alias Macaw.Auth.Native.{Config, Totp, UserRecord}

    @day 24 * 60 * 60 * 1000

    defp rows, do: Throttle.rows()

    @tag verifies: "auth-throttle"
    test "the values are constants, which no setting changes: five free, 2^(n-5) s, the cap, a day" do
      assert {:error, _} = Config.parse(repo: Repo, throttle: [free: 10])
      assert {:error, _} = Config.parse(repo: Repo, free_failures: 10)

      Application.put_env(:macaw_auth, :throttle, free: 10, cap_ms: 1)
      on_exit(fn -> Application.delete_env(:macaw_auth, :throttle) end)

      assert Throttle.delay_ms(4) == 0
      assert Throttle.delay_ms(5) == 1_000
      assert Throttle.delay_ms(40) == @cap

      Throttle.failure({:name, "ava"}, "192.0.2.60", ms(0))
      assert Throttle.sweep(ms(@day)) == 0
      assert Throttle.sweep(ms(@day + 1)) == 2
    end

    @tag verifies: "auth-throttle-keys"
    test "the keys: the account, else the normalized name, or :invalid; the address as a string; the longer wait wins" do
      amy = local_user!("amy", "correct horse battery")

      for name <- ["Bea ", "not a name!", "@@", " AMY"],
          do:
            Native.authenticate(%{username: name, password: "x"},
              now: at(0),
              remote_ip: {192, 0, 2, 70}
            )

      assert rows() == [
               {{:ip, "192.0.2.70"}, 4, ms(0)},
               {{:user, :invalid}, 2, ms(0)},
               {{:user, {:account, amy.id}}, 1, ms(0)},
               {{:user, {:name, "bea"}}, 1, ms(0)}
             ]

      assert key(" Amy") == {:account, amy.id}
      assert key("BEA") == {:name, "bea"}
      assert key("not a name!") == :invalid

      # check/3: the longer of the two keys' waits.
      for _ <- 1..6, do: Throttle.failure({:name, "cal"}, nil, ms(0))
      for _ <- 1..5, do: Throttle.failure({:name, "other"}, "192.0.2.71", ms(0))
      assert Throttle.check({:name, "cal"}, "192.0.2.71", ms(0)) == {:delay, 2_000}
      assert Throttle.check({:name, "dee"}, "192.0.2.71", ms(0)) == {:delay, 1_000}
      assert Throttle.check({:name, "dee"}, "192.0.2.72", ms(0)) == :ok

      # failure/3 counts on both keys.
      Throttle.reset()
      assert Throttle.failure({:name, "dee"}, "192.0.2.72", ms(5)) == :ok
      assert rows() == [{{:ip, "192.0.2.72"}, 1, ms(5)}, {{:user, {:name, "dee"}}, 1, ms(5)}]

      # now/0 is the system clock in milliseconds.
      before = System.system_time(:millisecond)
      now = Throttle.now()
      assert before <= now and now <= System.system_time(:millisecond)
    end

    @tag verifies: "auth-throttle-backoff"
    test "nothing is locked for good: at the cap, the right password succeeds once the wait passed" do
      local_user!("eli", "correct horse battery")
      for _ <- 1..40, do: Throttle.failure(key("eli"), "192.0.2.1", ms(0))

      assert sign_in("eli", "correct horse battery", @cap - 1) == {:error, :throttled}
      assert {:ok, _} = sign_in("eli", "correct horse battery", @cap)

      # From the key's last failure, and another checked failure doubles the wait.
      fail_times(5, "fay", 0, "192.0.2.80")
      assert sign_in("fay", "wrong", 1_000, "192.0.2.80") == {:error, :invalid_credentials}
      assert Throttle.check(key("fay"), "192.0.2.80", ms(1_000)) == {:delay, 2_000}
    end

    @tag verifies: "auth-throttle-reset"
    test "success/1 forgets the user key and only it; a sign-in resets its account's" do
      Throttle.failure({:name, "gus"}, "192.0.2.90", ms(0))
      assert Throttle.success({:name, "gus"}) == :ok
      assert rows() == [{{:ip, "192.0.2.90"}, 1, ms(0)}]

      gus = local_user!("gus", "correct horse battery")
      Throttle.failure({:account, gus.id}, "192.0.2.91", ms(0))
      assert {:ok, _} = sign_in(" GUS", "correct horse battery", 0, "192.0.2.91")
      assert row({:user, {:account, gus.id}}) == []
      assert [{_, 1, _}] = row({:ip, "192.0.2.91"})
    end

    @tag verifies: "auth-throttle-second-factor"
    test "codes: their own username key, the sign-in's address key, a wrong code counts, others don't" do
      key = :crypto.strong_rand_bytes(32)
      configure!(sealing_key: key, hasher: Macaw.Auth.Test.CountingHasher)

      t0 = at(0)
      user = "hal" |> local_user!("correct horse battery") |> Native.to_user()

      # No ticket: refused, and not counted.
      assert Native.enroll_confirm(user, nil, "000001", now: t0, remote_ip: "192.0.2.95") ==
               {:error, :invalid_ticket}

      assert rows() == []

      {:ok, %{ticket: ticket, secret: secret}} = Native.enroll_begin(user, now: t0)
      opts = [now: t0, remote_ip: "192.0.2.95"]
      assert Native.enroll_confirm(user, ticket, "000001", opts) == {:error, :invalid_code}

      # The account's own second-factor key, by its id.
      assert row({:user, {:second_factor, user.id}}) == [
               {{:user, {:second_factor, user.id}}, 1, DateTime.to_unix(t0, :millisecond)}
             ]

      assert row({:user, {:account, user.id}}) == []

      # An accepted code resets the account's second-factor key, never the address.
      assert {:ok, _codes} = Native.enroll_confirm(user, ticket, Totp.code(secret, t0), opts)
      assert row({:user, {:second_factor, user.id}}) == []
      assert [{_, 1, _}] = row({:ip, "192.0.2.95"})

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
      for _ <- 1..5, do: Throttle.failure(key("ida"), nil, ms(0))
      for _ <- 1..5, do: Throttle.failure({:name, "someone"}, "192.0.2.101", ms(0))

      for {name, ip} <- [{"ida", "192.0.2.102"}, {"jon", "192.0.2.101"}] do
        flush_hasher()
        assert sign_in(name, "wrong", 0, ip) == {:error, :throttled}
        assert_received {:hasher, :no_user_verify}
        refute_received {:hasher, _}
      end
    end

    @tag verifies: "auth-throttle-table"
    test "rows of macaw_auth_throttle in the configured repo, {key, failures, last}, reset, and the sweep's owner and its options" do
      owner = Process.whereis(Throttle)

      assert {Throttle, ^owner, :worker, _} =
               List.keyfind(Supervisor.which_children(Macaw.Auth.Supervisor), Throttle, 0)

      Throttle.failure({:name, "kai"}, "192.0.2.110", ms(7))
      assert rows() == [{{:ip, "192.0.2.110"}, 1, ms(7)}, {{:user, {:name, "kai"}}, 1, ms(7)}]

      # The repo's rows, in the columns ThrottleRecord encodes a key in.
      assert Repo.query!(
               "SELECT kind, subject, failures, last_failure_ms FROM macaw_auth_throttle ORDER BY kind"
             ).rows == [["address", "192.0.2.110", 1, ms(7)], ["name", "kai", 1, ms(7)]]

      assert Throttle.reset() == :ok
      assert rows() == []

      # The owner's :sweep_every_ms and :clock: a throttle started with them
      # sweeps on its own, at its clock's time. Its first clock read waits
      # until the test has let it use the sandboxed connection.
      test = self()
      :ok = Supervisor.terminate_child(Macaw.Auth.Supervisor, Throttle)
      on_exit(fn -> {:ok, _} = Supervisor.restart_child(Macaw.Auth.Supervisor, Throttle) end)
      Throttle.failure({:name, "lou"}, nil, ms(0))
      Throttle.failure({:name, "max"}, nil, ms(2 * @day))

      {:ok, pid} =
        Throttle.start_link(
          sweep_every_ms: 10,
          clock: fn ->
            send(test, {:clock_read, self()})

            unless Process.get(:allowed) do
              receive do
                :allowed -> Process.put(:allowed, true)
              end
            end

            ms(2 * @day)
          end
        )

      assert_receive {:clock_read, ^pid}
      Ecto.Adapters.SQL.Sandbox.allow(Repo, self(), pid)
      send(pid, :allowed)
      :sys.get_state(pid)
      assert rows() == [{{:user, {:name, "max"}}, 1, ms(2 * @day)}]
      :ok = GenServer.stop(pid)
    end
  end
end
