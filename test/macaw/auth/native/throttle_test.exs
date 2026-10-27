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

  test "the wait: none for four failures, 2^(n-5) s from the fifth, capped at 15 minutes" do
    assert Enum.map(0..4, &Throttle.delay_ms/1) == [0, 0, 0, 0, 0]
    assert Enum.map(5..9, &Throttle.delay_ms/1) == [1_000, 2_000, 4_000, 8_000, 16_000]
    assert Throttle.delay_ms(14) == 512_000
    assert Throttle.delay_ms(15) == @cap
    assert Throttle.delay_ms(1_000_000) == @cap
  end

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

  test "the cap: the wait never exceeds 15 minutes" do
    for _ <- 1..40, do: Throttle.failure("judy", nil, ms(0))
    assert Throttle.check("judy", nil, ms(0)) == {:delay, @cap}
    assert Throttle.check("judy", nil, ms(@cap - 1)) == {:delay, 1}
    assert Throttle.check("judy", nil, ms(@cap)) == :ok
  end

  test "a success resets the username's count" do
    local_user!("kim", "correct horse battery")
    fail_times(5, "kim", 0)
    assert {:ok, _} = sign_in("kim", "correct horse battery", 1_000, "192.0.2.50")

    # Five free failures again (from another address, so only the username counts).
    fail_times(4, "kim", 1_000, "192.0.2.51")
    assert {:ok, _} = sign_in("kim", "correct horse battery", 1_000, "192.0.2.51")
  end

  test "a success doesn't reset the address's count" do
    local_user!("lee", "correct horse battery")
    for i <- 1..5, do: sign_in("guess#{i}", "x", 0, "192.0.2.9")
    assert sign_in("lee", "correct horse battery", 0, "192.0.2.9") == {:error, :throttled}

    assert {:ok, _} = sign_in("lee", "correct horse battery", 1_000, "192.0.2.9")
    assert sign_in("guess9", "x", 1_000, "192.0.2.9") == {:error, :invalid_credentials}
    assert sign_in("lee", "correct horse battery", 1_001, "192.0.2.9") == {:error, :throttled}
  end

  test "per address: one address trying many usernames waits, another address doesn't" do
    local_user!("mia", "correct horse battery")
    for i <- 1..5, do: sign_in("user#{i}", "wrong", 0, "198.51.100.1")

    assert sign_in("mia", "correct horse battery", 0, "198.51.100.1") == {:error, :throttled}
    assert {:ok, _} = sign_in("mia", "correct horse battery", 0, "198.51.100.2")
  end

  test "per username: many addresses trying one username wait, other usernames don't" do
    local_user!("ned", "correct horse battery")
    local_user!("oli", "correct horse battery")
    for i <- 1..5, do: sign_in("ned", "wrong", 0, "203.0.113.#{i}")

    assert sign_in("ned", "correct horse battery", 0, "203.0.113.99") == {:error, :throttled}
    assert {:ok, _} = sign_in("oli", "correct horse battery", 0, "203.0.113.99")
  end

  test "the username key is the normalized username" do
    local_user!("pat", "correct horse battery")
    for name <- ["Pat", " PAT ", "pat", "pAt", "pat "], do: sign_in(name, "wrong", 0, nil)
    assert sign_in("pat", "correct horse battery", 0, nil) == {:error, :throttled}
  end

  test "no address, no address key" do
    for i <- 1..5, do: sign_in("nobody#{i}", "wrong", 0, nil)
    assert sign_in("nobody6", "wrong", 0, nil) == {:error, :invalid_credentials}
  end

  test "the plug's authenticate counts the connection's address" do
    Application.put_env(:macaw_auth, :backend, Native)
    on_exit(fn -> Application.delete_env(:macaw_auth, :backend) end)
    local_user!("quinn", "correct horse battery")
    conn = %{conn(:post, "/login") | remote_ip: {198, 51, 100, 77}}

    for i <- 1..5,
        do: Macaw.Auth.Plug.authenticate(conn, %{username: "u#{i}", password: "x"}, now: at(0))

    assert Throttle.check("quinn", "198.51.100.77", ms(0)) == {:delay, 1_000}
  end

  test "a throttled refusal goes to telemetry" do
    fail_times(5, "rae", 0)
    ref = :telemetry_test.attach_event_handlers(self(), [[:macaw_auth, :native, :authenticate]])
    assert sign_in("rae", "x", 0) == {:error, :throttled}

    assert_received {[:macaw_auth, :native, :authenticate], ^ref, %{count: 1},
                     %{result: :error, reason: :throttled, user_id: nil}}
  end

  describe "a block takes a hash's time" do
    test "it spends the hasher's no-user verification, and checks nothing" do
      configure!(hasher: Macaw.Auth.Test.CountingHasher)
      local_user!("sam", "correct horse battery")
      fail_times(5, "sam", 0)
      flush_hasher()

      assert sign_in("sam", "correct horse battery", 0) == {:error, :throttled}
      assert_received {:hasher, :no_user_verify}
      refute_received {:hasher, :verify}
    end

    # As the password source's timing test: at a real cost, the hash
    # dominates; medians and a 3x margin keep a busy runner from failing it.
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

  describe "the sweep" do
    test "forgets keys whose last failure is over a day old" do
      day = 24 * 60 * 60 * 1000
      for _ <- 1..5, do: Throttle.failure("uma", "192.0.2.3", ms(0))
      Throttle.failure("vic", nil, ms(day))

      assert Throttle.sweep(ms(day)) == 0
      assert Throttle.sweep(ms(day + 1)) == 2
      assert Throttle.check("uma", "192.0.2.3", ms(day + 1)) == :ok
      assert :ets.lookup(Throttle, {:user, "vic"}) != []
    end

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
end
