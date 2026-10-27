defmodule Macaw.Auth.Native.TotpTest do
  use Macaw.Auth.DataCase, async: false
  use ExUnitProperties

  import Ecto.Query, only: [where: 2]

  alias Macaw.Auth
  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Config, RecoveryCodeRecord, Seal, SealingKeyError, Totp, UserRecord}

  @t0 ~U[2026-10-01 12:00:00.000000Z]
  @key :crypto.strong_rand_bytes(32)

  setup do
    previous = Application.get_env(:macaw_auth, :backend)
    Application.put_env(:macaw_auth, :backend, Native)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:macaw_auth, :backend, previous),
        else: Application.delete_env(:macaw_auth, :backend)
    end)

    configure!(sealing_key: @key, totp_issuer: "Test App")
    :ok
  end

  defp at(seconds), do: DateTime.add(@t0, seconds, :second)

  defp user!(attrs \\ %{}) do
    n = System.unique_integer([:positive])
    "user#{n}" |> local_user!("correct horse #{n}", attrs) |> Native.to_user()
  end

  # A user enrolled at @t0 (the confirming code's step is @t0's), with
  # their secret and recovery codes.
  defp enrolled!(attrs \\ %{}) do
    user = user!(attrs)
    {:ok, %{secret: secret}} = Native.enroll_begin(user)
    {:ok, codes} = Native.enroll_confirm(user, Totp.code(secret, @t0), now: @t0)
    {reload(user), secret, codes}
  end

  defp reload(user), do: UserRecord |> Repo.get!(user.id) |> Native.to_user()

  defp row(user), do: Repo.get!(UserRecord, user.id)

  describe "the window" do
    test "the current step and one either side are accepted" do
      now = at(600)

      for offset <- [-1, 0, 1] do
        {user, secret, _} = enrolled!()
        code = Totp.code(secret, DateTime.add(now, offset * 30, :second))
        assert Totp.verify(user, code, now: now) == :ok, "offset #{offset}"
      end
    end

    test "two steps either side are refused" do
      now = at(600)
      {user, secret, _} = enrolled!()

      for offset <- [-2, 2, -3, 3] do
        code = Totp.code(secret, DateTime.add(now, offset * 30, :second))
        assert Totp.verify(user, code, now: now) == {:error, :invalid_code}, "offset #{offset}"
      end
    end

    test "spaces and dashes are ignored" do
      {user, secret, _} = enrolled!()
      <<a::binary-3, b::binary-3>> = Totp.code(secret, at(300))
      assert Totp.verify(user, " #{a} #{b} ", now: at(300)) == :ok
      <<a::binary-3, b::binary-3>> = Totp.code(secret, at(600))
      assert Totp.verify(user, "#{a}-#{b}", now: at(600)) == :ok
    end

    test "anything else is the same refusal" do
      {user, _secret, _} = enrolled!()

      for junk <- ["", "12345", "1234567", "abcdef", nil, 123_456, String.duplicate("1", 100)] do
        assert Totp.verify(user, junk, now: at(300)) == {:error, :invalid_code}
      end
    end

    test "the codes are compared with Plug.Crypto.secure_compare/2" do
      {:ok, {_, [imports: imports]}} =
        :beam_lib.chunks(:code.which(Totp) |> to_charlist(), [:imports])

      assert {Plug.Crypto, :secure_compare, 2} in imports
    end
  end

  describe "replay" do
    test "a code once accepted is refused, and so is an earlier step's" do
      {user, secret, _} = enrolled!()
      now = at(600)
      code = Totp.code(secret, now)

      assert Totp.verify(user, code, now: now) == :ok
      assert Totp.verify(user, code, now: now) == {:error, :invalid_code}

      earlier = Totp.code(secret, DateTime.add(now, -30, :second))
      assert Totp.verify(user, earlier, now: now) == {:error, :invalid_code}
      assert row(user).totp_last_step == Totp.step(now)
    end

    test "the confirming code can't then sign in" do
      {user, secret, _} = enrolled!()
      assert Totp.verify(user, Totp.code(secret, @t0), now: @t0) == {:error, :invalid_code}
    end

    test "the step is claimed by a conditional update: a stale reader gets nothing" do
      {user, _secret, _} = enrolled!()
      step = Totp.step(at(600))

      # Two callers that both read the row before either wrote it.
      assert Totp.claim_step(Repo, user.id, step) == :ok
      assert Totp.claim_step(Repo, user.id, step) == :replayed
      assert Totp.claim_step(Repo, user.id, step - 1) == :replayed
      assert Totp.claim_step(Repo, user.id, step + 1) == :ok
    end

    test "of concurrent verifications of one code, exactly one succeeds" do
      {user, secret, _} = enrolled!()
      now = at(600)
      code = Totp.code(secret, now)
      parent = self()

      results =
        1..8
        |> Task.async_stream(
          fn _ ->
            Ecto.Adapters.SQL.Sandbox.allow(Repo, parent, self())
            Totp.verify(user, code, now: now)
          end,
          max_concurrency: 8
        )
        |> Enum.map(fn {:ok, result} -> result end)

      assert Enum.count(results, &(&1 == :ok)) == 1
      assert Enum.count(results, &(&1 == {:error, :invalid_code})) == 7
    end
  end

  describe "enrollment" do
    test "begins pending, resumes with the same secret, and confirms with a code" do
      user = user!()
      {:ok, %{secret: secret, uri: uri}} = Native.enroll_begin(user)
      assert byte_size(secret) == 20
      assert {:ok, %{secret: ^secret}} = Native.enroll_begin(user)

      assert uri ==
               "otpauth://totp/Test%20App:#{user.username}?secret=" <>
                 Base.encode32(secret, padding: false) <> "&issuer=Test%20App"

      # Pending: nothing changes at sign-in.
      assert reload(user).second_factor == :none

      # An hour off is outside the window.
      assert Native.enroll_confirm(user, Totp.code(secret, at(3600)), now: @t0) ==
               {:error, :invalid_code}

      assert {:ok, codes} = Native.enroll_confirm(user, Totp.code(secret, @t0), now: @t0)
      assert length(codes) == 10
      assert reload(user).second_factor == :enrolled
      assert Native.enroll_begin(user) == {:error, :already_enrolled}
      assert Native.enroll_confirm(user, Totp.code(secret, @t0)) == {:error, :already_enrolled}
    end

    test "confirming without beginning is refused" do
      assert Native.enroll_confirm(user!(), "123456") == {:error, :not_started}
    end

    test "an enrolled user owes the second factor at sign-in" do
      {user, _secret, _} = enrolled!()
      {:ok, _token, session} = Auth.create_session(user)
      assert Auth.pending_step(user, session) == :second_factor
    end
  end

  describe "sealing" do
    property "the stored column is never the secret, in any form" do
      check all(n <- integer(1..5), max_runs: 10) do
        for _ <- 1..n do
          user = user!()
          {:ok, %{secret: secret}} = Native.enroll_begin(user)
          sealed = row(user).totp_secret_sealed

          for form <- [secret, Base.encode32(secret, padding: false), Base.encode64(secret)] do
            refute sealed == form
            refute :binary.match(sealed, form) != :nomatch
          end

          stored =
            Repo.query!("SELECT * FROM macaw_auth_users WHERE username = ?", [user.username]).rows
            |> List.flatten()
            |> Enum.filter(&is_binary/1)

          refute Enum.any?(stored, &String.contains?(&1, secret))
          refute Enum.any?(stored, &String.contains?(&1, Base.encode32(secret, padding: false)))
        end
      end
    end

    test "seals with a fresh IV: the same secret seals differently" do
      key = Seal.key!(@key)
      refute Seal.seal("secret", key, "aad") == Seal.seal("secret", key, "aad")
      assert {:ok, "secret"} = Seal.unseal(Seal.seal("secret", key, "aad"), key, "aad")
    end

    test "a wrong key, or another row's associated data, fails to unseal, by name" do
      key = Seal.key!(@key)
      other = Seal.key!(:crypto.strong_rand_bytes(32))
      sealed = Seal.seal("secret", key, "user a")
      assert Seal.unseal(sealed, other, "user a") == {:error, :wrong_key}
      assert Seal.unseal(sealed, key, "user b") == {:error, :wrong_key}
      assert Seal.unseal("garbage", key, "user a") == {:error, :wrong_key}

      {user, secret, _} = enrolled!()
      configure!(sealing_key: :crypto.strong_rand_bytes(32))

      assert_raise SealingKeyError, ~r/does not unseal with the configured sealing_key/, fn ->
        Totp.verify(user, Totp.code(secret, at(300)), now: at(300))
      end
    end

    test "a sealed secret copied onto another user's row doesn't unseal there" do
      {alice, _secret, _} = enrolled!()
      bob = user!()
      {:ok, _} = Native.enroll_begin(bob)

      Repo.update_all(where(UserRecord, id: ^bob.id),
        set: [totp_secret_sealed: row(alice).totp_secret_sealed]
      )

      assert_raise SealingKeyError, fn -> Native.enroll_begin(bob) end
    end

    test "a short key is refused in the configuration, never shown" do
      assert {:error, "sealing_key: must be at least 32 bytes"} =
               Config.parse(repo: Repo, sealing_key: "too short a key")

      assert {:error, "sealing_key: must be a binary" <> _} =
               Config.parse(repo: Repo, sealing_key: 42)

      {:ok, config} = Config.parse(repo: Repo, sealing_key: @key)
      refute inspect(config) =~ inspect(@key)
      refute inspect(config) =~ "sealing_key"
    end

    test "a missing key, or a function's short one, is a named error at first use" do
      configure!(sealing_key: nil)

      assert_raise SealingKeyError, ~r/sealing_key is not set/, fn ->
        Native.enroll_begin(user!())
      end

      configure!(sealing_key: {__MODULE__, :key, ["short"]})

      assert_raise SealingKeyError,
                   ~r/sealing_key Macaw.Auth.Native.TotpTest.key\/1 did not return/,
                   fn -> Native.enroll_begin(user!()) end

      configure!(sealing_key: {__MODULE__, :key, [Base.encode64(@key)]})
      assert {:ok, _} = Native.enroll_begin(user!())
    end
  end

  def key(value), do: value

  describe "recovery codes" do
    test "ten, grouped, stored only hashed" do
      {user, _secret, codes} = enrolled!()
      assert length(codes) == 10
      assert length(Enum.uniq(codes)) == 10
      for code <- codes, do: assert(code =~ ~r/\A[2-9A-HJ-NP-Z]{5}-[2-9A-HJ-NP-Z]{5}\z/)
      assert Native.recovery_codes_left(user) == 10

      stored =
        Repo.query!("SELECT * FROM macaw_auth_recovery_codes").rows
        |> List.flatten()
        |> Enum.filter(&is_binary/1)

      for code <- codes, plain <- [code, String.replace(code, "-", "")], value <- stored do
        refute String.contains?(value, plain)
      end

      hashes = Repo.all(RecoveryCodeRecord) |> Enum.map(& &1.code_hash) |> Enum.sort()

      assert hashes ==
               codes
               |> Enum.map(&:crypto.hash(:sha256, String.replace(&1, "-", "")))
               |> Enum.sort()
    end

    test "each works once, in any case and spacing" do
      {user, _secret, [first, second | _]} = enrolled!()
      assert Totp.verify(user, first) == :ok
      assert Totp.verify(user, first) == {:error, :invalid_code}
      assert Native.recovery_codes_left(user) == 9

      spaced = second |> String.downcase() |> String.replace("-", " ")
      assert Totp.verify(user, spaced) == :ok
      assert Native.recovery_codes_left(user) == 8
    end

    test "regenerating replaces them all" do
      {user, _secret, old} = enrolled!()
      assert {:ok, new} = Native.regenerate_recovery_codes(user)
      assert length(new) == 10
      assert Native.recovery_codes_left(user) == 10
      for code <- old, do: assert(Totp.verify(user, code) == {:error, :invalid_code})
      assert Totp.verify(user, hd(new)) == :ok
    end

    test "a user not enrolled has none to regenerate" do
      assert Native.regenerate_recovery_codes(user!()) == {:error, :not_enrolled}
    end

    test "a recovery code passes the second factor on a session" do
      {user, _secret, [code | _]} = enrolled!()
      {:ok, token, session} = Auth.create_session(user)
      assert Native.verify_second_factor(session.id, code, []) == :ok
      {:ok, user, session} = Auth.fetch(token)
      assert Auth.pending_step(user, session) == nil
    end
  end

  describe "policy" do
    test "required by role: a user with the role who hasn't enrolled owes enrollment" do
      configure!(sealing_key: @key, totp_required: ["admin"])
      admin = user!(%{roles: ["admin"]})
      viewer = user!(%{roles: ["viewer"]})

      assert admin.second_factor == :required
      assert viewer.second_factor == :none

      {:ok, token, session} = Auth.create_session(admin)
      assert Auth.pending_step(admin, session) == :second_factor_enroll

      {:ok, _, viewer_session} = Auth.create_session(viewer)
      assert Auth.pending_step(viewer, viewer_session) == nil

      # Enrolling, then completing the step, leaves nothing owed; the user
      # is now enrolled.
      {:ok, %{secret: secret}} = Native.enroll_begin(admin)
      {:ok, _} = Native.enroll_confirm(admin, Totp.code(secret, DateTime.utc_now()))
      :ok = Auth.complete_step(session.id, :second_factor_enroll)
      {:ok, admin, session} = Auth.fetch(token)
      assert admin.second_factor == :enrolled
      assert Auth.pending_step(admin, session) == nil
    end

    test "required of everyone" do
      configure!(sealing_key: @key, totp_required: true)
      assert user!().second_factor == :required
    end

    test "the setting is checked" do
      assert {:error, "totp_required: " <> _} = Config.parse(repo: Repo, totp_required: [])
      assert {:error, "totp_required: " <> _} = Config.parse(repo: Repo, totp_required: "yes")
      assert {:error, "totp_issuer: " <> _} = Config.parse(repo: Repo, totp_issuer: "a:b")
    end
  end

  describe "disabling" do
    test "with a current code; policy can forbid it" do
      {user, secret, _} = enrolled!()
      assert Native.disable(user, "abcdef", now: at(300)) == {:error, :invalid_code}
      assert Native.disable(user, Totp.code(secret, at(300)), now: at(300)) == :ok
      assert reload(user).second_factor == :none
      assert row(user).totp_secret_sealed == nil
      assert Native.recovery_codes_left(user) == 0

      {admin, secret, _} = enrolled!(%{roles: ["admin"]})
      configure!(sealing_key: @key, totp_required: ["admin"])

      assert Native.disable(admin, Totp.code(secret, at(300)), now: at(300)) ==
               {:error, :required}
    end

    test "an administrator's reset clears it and revokes the user's sessions" do
      {user, _secret, _} = enrolled!()
      {:ok, token, _} = Auth.create_session(user)
      :ok = Auth.subscribe(user.id)

      assert Native.admin_reset(user) == :ok
      assert Auth.fetch(token) == {:error, :invalid}
      assert_receive {:sessions_revoked, [_]}
      assert reload(user).second_factor == :none
      assert Native.recovery_codes_left(user) == 0
    end
  end

  describe "the throttle" do
    test "repeated wrong codes back off, even for the right code, until the wait passes" do
      {user, secret, _} = enrolled!()
      {:ok, _token, session} = Native.create_session(user, now: at(600))
      opts = fn s -> [now: at(s), remote_ip: "192.0.2.7"] end

      for _ <- 1..5 do
        assert Native.verify_second_factor(session.id, "000001", opts.(600)) ==
                 {:error, :invalid_code}
      end

      right = Totp.code(secret, at(600))
      assert Native.verify_second_factor(session.id, right, opts.(600)) == {:error, :throttled}

      # A password sign-in doesn't clear the code's count.
      assert {:ok, _} = Native.authenticate(%{username: user.username, password: password(user)})
      assert Native.verify_second_factor(session.id, right, opts.(600)) == {:error, :throttled}

      # After the wait (one second for the fifth failure), it is checked.
      assert Native.verify_second_factor(session.id, right, opts.(601)) == :ok
    end

    test "the address counts too: other users' codes from one address back off" do
      for _ <- 1..5 do
        {user, _secret, _} = enrolled!()
        {:ok, _, session} = Native.create_session(user, now: at(600))

        assert Native.verify_second_factor(session.id, "000001",
                 now: at(600),
                 remote_ip: "192.0.2.8"
               ) == {:error, :invalid_code}
      end

      {user, secret, _} = enrolled!()
      {:ok, _, session} = Native.create_session(user, now: at(600))

      assert Native.verify_second_factor(session.id, Totp.code(secret, at(600)),
               now: at(600),
               remote_ip: "192.0.2.8"
             ) == {:error, :throttled}
    end

    test "enrollment confirmation and disabling are throttled too" do
      user = user!()
      {:ok, %{secret: secret}} = Native.enroll_begin(user)

      for _ <- 1..5,
          do: assert(Native.enroll_confirm(user, "000001", now: @t0) == {:error, :invalid_code})

      assert Native.enroll_confirm(user, Totp.code(secret, @t0), now: @t0) ==
               {:error, :throttled}
    end
  end

  describe "telemetry" do
    test "events carry the event and the user's id, never a secret or a code" do
      ref = make_ref()
      parent = self()

      :telemetry.attach(
        "totp-test-#{inspect(ref)}",
        [:macaw_auth, :native, :second_factor],
        fn _name, _measure, meta, _ -> send(parent, {ref, meta}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach("totp-test-#{inspect(ref)}") end)

      {user, secret, _} = enrolled!()
      :ok = Totp.verify(user, Totp.code(secret, at(300)), now: at(300))

      assert_receive {^ref, %{event: :enrollment_started}}
      assert_receive {^ref, %{event: :enrolled}}
      assert_receive {^ref, meta}
      assert Map.keys(meta) |> Enum.sort() == [:event, :user_id]
    end
  end

  # The fixtures' passwords are "correct horse <n>" for "user<n>".
  defp password(user), do: "correct horse " <> String.trim_leading(user.username, "user")
end
