defmodule Macaw.Auth.PlugNativeTest do
  # The plugs over the native backend, where the client's address they pass
  # on is seen: its throttle counts it.
  use Macaw.Auth.DataCase, async: false

  import Plug.Test
  import Plug.Conn

  alias Macaw.Auth
  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.Throttle
  alias Macaw.Auth.Plug, as: AuthPlug
  alias Macaw.Auth.Test.NativeFixtures

  @t0 ~U[2026-10-01 12:00:00.000Z]

  setup do
    previous = Application.get_env(:macaw_auth, :backend)
    Application.put_env(:macaw_auth, :backend, Native)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:macaw_auth, :backend, previous),
        else: Application.delete_env(:macaw_auth, :backend)
    end)

    configure!(sealing_key: NativeFixtures.sealing_key())
    :ok
  end

  defp ms(ms), do: DateTime.to_unix(@t0, :millisecond) + ms

  defp from(ip), do: %{conn(:post, "/login") | remote_ip: ip}

  defp signed_in(user, ip) do
    {:ok, token, _} = Auth.create_session(user)

    %{conn(:get, "/login/second-factor") | remote_ip: ip}
    |> init_test_session(%{AuthPlug.token_key() => token})
    |> AuthPlug.fetch_current_user([])
  end

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 02" do
    @tag verifies: "auth-plug-authenticate"
    test "authenticate/3 counts the conn's address, as a string, unless the options give one" do
      local_user!("quinn", "correct horse battery")
      conn = from({198, 51, 100, 77})

      assert {:ok, %Auth.User{username: "quinn"}} =
               AuthPlug.authenticate(conn, %{username: "quinn", password: "correct horse battery"})

      # The options' address is counted, not the conn's.
      for i <- 1..5 do
        assert AuthPlug.authenticate(conn, %{username: "u#{i}", password: "x"},
                 remote_ip: "203.0.113.9",
                 now: @t0
               ) == {:error, :invalid_credentials}
      end

      assert Throttle.check("someone", "203.0.113.9", ms(0)) == {:delay, 1_000}
      assert Throttle.check("someone", "198.51.100.77", ms(0)) == :ok

      # An IPv6 conn's address, formatted.
      v6 = from({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1})
      for i <- 1..5, do: AuthPlug.authenticate(v6, %{username: "v#{i}", password: "x"}, now: @t0)
      assert Throttle.check("someone", "2001:db8::1", ms(0)) == {:delay, 1_000}
    end

    @tag verifies: "auth-plug-verify"
    test "verify_second_factor/2: accepted, on to the next step; refused, the conn unchanged; throttled by the conn's address" do
      record = local_user!("rowan", "correct horse battery", %{must_change_password: true})
      user = Native.to_user(record)
      next_code = NativeFixtures.enroll_second_factor!(user)
      {:ok, user} = Auth.authenticate(%{username: "rowan", password: "correct horse battery"})
      conn = signed_in(user, {192, 0, 2, 50})
      assert conn.assigns.pending_step == :second_factor

      # Refused: the conn as it came, for the page to render the reason.
      assert AuthPlug.verify_second_factor(conn, "000000") == {:error, :invalid_code, conn}

      # Accepted: the step is completed and the browser goes on, to the next step.
      assert {:ok, accepted} = AuthPlug.verify_second_factor(conn, next_code.())
      assert accepted.halted
      assert accepted.status == 302
      assert get_resp_header(accepted, "location") == ["/password"]
      assert accepted.assigns.pending_step == :password_change

      # Wrong codes for five users from one address: a sixth user's right code
      # from it is throttled, the reason given back with the conn.
      for i <- 1..5 do
        record = local_user!("wren#{i}", "correct horse battery")
        user = Native.to_user(record)
        _ = NativeFixtures.enroll_second_factor!(user)

        {:ok, user} =
          Auth.authenticate(%{username: "wren#{i}", password: "correct horse battery"})

        conn = signed_in(user, {192, 0, 2, 60})
        assert {:error, :invalid_code, ^conn} = AuthPlug.verify_second_factor(conn, "000000")
      end

      record = local_user!("sage", "correct horse battery")
      user = Native.to_user(record)
      code = NativeFixtures.enroll_second_factor!(user)
      {:ok, user} = Auth.authenticate(%{username: "sage", password: "correct horse battery"})
      throttled = signed_in(user, {192, 0, 2, 60})

      assert AuthPlug.verify_second_factor(throttled, code.()) ==
               {:error, :throttled, throttled}
    end
  end
end
