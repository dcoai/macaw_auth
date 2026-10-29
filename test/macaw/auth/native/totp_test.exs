defmodule Macaw.Auth.Native.TotpTest do
  use Macaw.Auth.DataCase, async: false
  use ExUnitProperties

  import Ecto.Query, only: [where: 2]

  alias Macaw.Auth
  alias Macaw.Auth.Native

  alias Macaw.Auth.Native.{
    Config,
    RecoveryCodeRecord,
    Seal,
    SealingKeyError,
    Totp,
    UserRecord
  }

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
    {:ok, %{ticket: ticket, secret: secret}} = Native.enroll_begin(user, now: @t0)
    {:ok, codes} = Native.enroll_confirm(user, ticket, Totp.code(secret, @t0), now: @t0)
    {reload(user), secret, codes}
  end

  defp reload(user), do: UserRecord |> Repo.get!(user.id) |> Native.to_user()

  defp row(user), do: Repo.get!(UserRecord, user.id)

  describe "the window" do
    @tag verifies: "totp-window"
    test "the current step and one either side are accepted; two and three steps away are refused" do
      now = at(600)

      for offset <- [-1, 0, 1] do
        {user, secret, _} = enrolled!()
        code = Totp.code(secret, DateTime.add(now, offset * 30, :second))
        assert Totp.verify(user, code, now: now) == :ok, "offset #{offset}"
      end

      {user, secret, _} = enrolled!()

      for offset <- [-2, 2, -3, 3] do
        code = Totp.code(secret, DateTime.add(now, offset * 30, :second))
        assert Totp.verify(user, code, now: now) == {:error, :invalid_code}, "offset #{offset}"
      end
    end

    @tag verifies: "totp-normalize"
    test "spaces and dashes are ignored; anything else is the same refusal" do
      {user, secret, _} = enrolled!()
      <<a::binary-3, b::binary-3>> = Totp.code(secret, at(300))
      assert Totp.verify(user, " #{a} #{b} ", now: at(300)) == :ok
      <<a::binary-3, b::binary-3>> = Totp.code(secret, at(600))
      assert Totp.verify(user, "#{a}-#{b}", now: at(600)) == :ok

      for junk <- ["", "12345", "1234567", "abcdef", nil, 123_456, String.duplicate("1", 100)] do
        assert Totp.verify(user, junk, now: at(600)) == {:error, :invalid_code}
      end
    end

    @tag verifies: "totp-secure-compare"
    test "the codes are compared with Plug.Crypto.secure_compare/2" do
      {:ok, {_, [imports: imports]}} =
        :beam_lib.chunks(:code.which(Totp) |> to_charlist(), [:imports])

      assert {Plug.Crypto, :secure_compare, 2} in imports
    end
  end

  describe "replay" do
    @tag verifies: "totp-replay"
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

    @tag verifies: "totp-confirming-code"
    test "the confirming code can't then sign in" do
      {user, secret, _} = enrolled!()
      assert Totp.verify(user, Totp.code(secret, @t0), now: @t0) == {:error, :invalid_code}
    end

    @tag verifies: "totp-claim-step"
    test "the step is claimed by a conditional update: a stale reader gets nothing" do
      {user, _secret, _} = enrolled!()
      step = Totp.step(at(600))

      # Two callers that both read the row before either wrote it.
      assert Totp.claim_step(Repo, user.id, step) == :ok
      assert Totp.claim_step(Repo, user.id, step) == :replayed
      assert Totp.claim_step(Repo, user.id, step - 1) == :replayed
      assert Totp.claim_step(Repo, user.id, step + 1) == :ok
    end

    @tag verifies: "totp-concurrent"
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
    @tag verifies: "totp-enroll"
    test "begins with a ticket, shows its secret again, and confirms with a code" do
      user = user!()
      {:ok, %{ticket: ticket, secret: secret, uri: uri}} = Native.enroll_begin(user, now: @t0)
      assert byte_size(secret) == 20
      assert Native.enrollment(ticket, now: at(60)) == {:ok, %{secret: secret, uri: uri}}

      assert uri ==
               "otpauth://totp/Test%20App:#{user.username}?secret=" <>
                 Base.encode32(secret, padding: false) <> "&issuer=Test%20App"

      # Begun: nothing changes at sign-in.
      assert reload(user).second_factor == :none

      # An hour off is outside the window.
      assert Native.enroll_confirm(user, ticket, Totp.code(secret, at(3600)), now: @t0) ==
               {:error, :invalid_code}

      assert {:ok, codes} = Native.enroll_confirm(user, ticket, Totp.code(secret, @t0), now: @t0)
      assert length(codes) == 10
      assert reload(user).second_factor == :enrolled
      assert Native.enroll_begin(user) == {:error, :already_enrolled}

      assert Native.enroll_confirm(user, ticket, Totp.code(secret, at(30)), now: at(30)) ==
               {:error, :invalid_ticket}
    end

    @tag verifies: "totp-not-started"
    test "confirming needs the user's own ticket of its purpose" do
      user = user!()
      {:ok, %{ticket: other, secret: secret}} = Native.enroll_begin(user!(), now: @t0)
      code = Totp.code(secret, @t0)

      for refused <- [nil, "", "not a ticket", other] do
        assert Native.enroll_confirm(user, refused, code, now: @t0) == {:error, :invalid_ticket}
      end

      assert reload(user).second_factor == :none
    end

    @tag verifies: "ticket-nothing-stored"
    test "beginning stores nothing: no table holds the pending secret, or its sealed form" do
      configure!(sealing_key: @key, totp_issuer: "Test App", totp_required: ["admin"])
      chosen = user!()
      owed = user!(%{roles: ["admin"]})

      tables =
        ~w(macaw_auth_users macaw_auth_sessions macaw_auth_recovery_codes macaw_auth_throttle)

      before = for table <- tables, do: Repo.query!("SELECT * FROM #{table}").rows

      {:ok, %{ticket: ticket, secret: secret}} = Native.enroll_begin(chosen, now: @t0)
      {:ok, owed_ticket} = Native.enrollment_ticket(owed, now: @t0)
      {:ok, %{secret: owed_secret}} = Native.enrollment(owed_ticket, now: @t0)

      assert for(table <- tables, do: Repo.query!("SELECT * FROM #{table}").rows) == before
      assert row(chosen).totp_secret_sealed == nil
      assert row(owed).totp_secret_sealed == nil

      {:ok, %{secret: sealed}, _} = Totp.open_ticket(ticket, [:chosen], now: @t0)

      stored =
        for table <- tables,
            value <- List.flatten(Repo.query!("SELECT * FROM #{table}").rows),
            is_binary(value),
            do: value

      for s <- [secret, owed_secret],
          form <- [s, Base.encode32(s, padding: false), sealed],
          value <- stored,
          do: refute(:binary.match(value, form) != :nomatch)
    end

    @tag verifies: "totp-enrolled-owes"
    test "an enrolled user owes the second factor at sign-in" do
      {user, _secret, _} = enrolled!()
      {:ok, _token, session} = Auth.create_session(user)
      assert Auth.pending_step(user, session) == :second_factor
    end
  end

  describe "sealing" do
    @tag verifies: "seal-never-stored"
    property "the stored column is never the secret, in any form" do
      check all(n <- integer(1..5), max_runs: 10) do
        for _ <- 1..n do
          user = user!()
          {:ok, %{ticket: ticket, secret: secret}} = Native.enroll_begin(user, now: @t0)
          assert row(user).totp_secret_sealed == nil
          {:ok, _} = Native.enroll_confirm(user, ticket, Totp.code(secret, @t0), now: @t0)
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

    @tag verifies: "seal-fresh-iv"
    test "seals with a fresh IV: the same secret seals differently" do
      key = Seal.key!(@key)
      refute Seal.seal("secret", key, "aad") == Seal.seal("secret", key, "aad")
      assert {:ok, "secret"} = Seal.unseal(Seal.seal("secret", key, "aad"), key, "aad")
    end

    @tag verifies: "seal-wrong-key"
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

    @tag verifies: "seal-row-bound"
    test "a sealed secret copied onto another user's row doesn't unseal there" do
      {alice, secret, _} = enrolled!()
      {bob, _secret, _} = enrolled!()

      Repo.update_all(where(UserRecord, id: ^bob.id),
        set: [totp_secret_sealed: row(alice).totp_secret_sealed]
      )

      assert_raise SealingKeyError, fn ->
        Totp.verify(bob, Totp.code(secret, at(300)), now: at(300))
      end
    end

    @tag verifies: "seal-short-key-config"
    test "a short key is refused in the configuration, never shown" do
      assert {:error, "sealing_key: must be at least 32 bytes"} =
               Config.parse(repo: Repo, sealing_key: "too short a key")

      assert {:error, "sealing_key: must be a binary" <> _} =
               Config.parse(repo: Repo, sealing_key: 42)

      {:ok, config} = Config.parse(repo: Repo, sealing_key: @key)
      refute inspect(config) =~ inspect(@key)
      refute inspect(config) =~ "sealing_key"
    end

    @tag verifies: "seal-key-missing"
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
    @tag verifies: "recovery-codes"
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

    @tag verifies: "recovery-once"
    test "each works once, in any case and spacing" do
      {user, _secret, [first, second | _]} = enrolled!()
      assert Totp.verify(user, first) == :ok
      assert Totp.verify(user, first) == {:error, :invalid_code}
      assert Native.recovery_codes_left(user) == 9

      spaced = second |> String.downcase() |> String.replace("-", " ")
      assert Totp.verify(user, spaced) == :ok
      assert Native.recovery_codes_left(user) == 8
    end

    @tag verifies: "recovery-regenerate"
    test "regenerating replaces them all; a user not enrolled has none to regenerate" do
      {user, _secret, old} = enrolled!()
      assert {:ok, new} = Native.regenerate_recovery_codes(user)
      assert length(new) == 10
      assert Native.recovery_codes_left(user) == 10
      for code <- old, do: assert(Totp.verify(user, code) == {:error, :invalid_code})
      assert Totp.verify(user, hd(new)) == :ok

      assert Native.regenerate_recovery_codes(user!()) == {:error, :not_enrolled}
    end

    @tag verifies: "totp-recovery-on-session"
    test "a recovery code passes the second factor on a session" do
      {user, _secret, [code | _]} = enrolled!()
      {:ok, token, session} = Auth.create_session(user)
      assert Native.verify_second_factor(session.id, code, []) == :ok
      {:ok, user, session} = Auth.fetch(token)
      assert Auth.pending_step(user, session) == nil
    end
  end

  describe "policy" do
    @tag verifies: "totp-policy-roles"
    test "required by role: a user with the role who hasn't enrolled gets a ticket, not a session" do
      configure!(sealing_key: @key, totp_required: ["admin"])
      admin = user!(%{roles: ["admin"]})
      viewer = user!(%{roles: ["viewer"]})

      assert admin.second_factor == :required
      assert viewer.second_factor == :none

      assert Auth.create_session(admin) == {:error, :enrollment_required}
      assert Auth.list_sessions(admin.id) == []

      {:ok, _, viewer_session} = Auth.create_session(viewer)
      assert Auth.pending_step(viewer, viewer_session) == nil
      assert Auth.enrollment_ticket(viewer, now: @t0) == {:error, :invalid}

      # Enrolling from the ticket makes the admin enrolled; a session then
      # starts with its second factor passed, and owes nothing.
      {:ok, ticket} = Auth.enrollment_ticket(admin, now: @t0)
      {:ok, %{secret: secret}} = Auth.enrollment(ticket, now: @t0)

      {:ok, admin, _codes} =
        Auth.enroll_second_factor(ticket, Totp.code(secret, @t0), now: @t0)

      assert admin.second_factor == :enrolled
      {:ok, _token, session} = Auth.create_session(admin, second_factor_passed: true)
      assert Auth.pending_step(admin, session) == nil
    end

    @tag verifies: "totp-policy-everyone"
    test "required of everyone" do
      configure!(sealing_key: @key, totp_required: true)
      assert user!().second_factor == :required
    end

    @tag verifies: "totp-policy-setting"
    test "the setting is checked" do
      assert {:error, "totp_required: " <> _} = Config.parse(repo: Repo, totp_required: [])
      assert {:error, "totp_required: " <> _} = Config.parse(repo: Repo, totp_required: "yes")
    end

    @tag verifies: "totp-issuer-setting"
    test "the issuer is checked: it prefixes the label, so it has no colon" do
      assert {:error, "totp_issuer: " <> _} = Config.parse(repo: Repo, totp_issuer: "a:b")
    end
  end

  describe "disabling" do
    @tag verifies: "totp-disable"
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

    @tag verifies: "totp-admin-reset"
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
    @tag verifies: "throttle-code-backoff"
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

    @tag verifies: "throttle-code-address"
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

    @tag verifies: "throttle-code-enroll"
    test "enrollment confirmation and disabling are throttled too" do
      user = user!()
      {:ok, %{ticket: ticket, secret: secret}} = Native.enroll_begin(user, now: @t0)

      for _ <- 1..5,
          do:
            assert(
              Native.enroll_confirm(user, ticket, "000001", now: @t0) == {:error, :invalid_code}
            )

      assert Native.enroll_confirm(user, ticket, Totp.code(secret, @t0), now: @t0) ==
               {:error, :throttled}
    end
  end

  describe "telemetry" do
    @tag verifies: "totp-telemetry"
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

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 11" do
    # A step whose code is the same at the step before it: a 20-byte secret
    # found by search, at a fixed time (step s - 1 and step s both give it).
    @collide_secret Base.decode16!("E6B7F7317DC26E5EA880BDF3191978144147F781")
    @collide_now DateTime.from_unix!(div(1_790_000_000, 30) * 30)
    @collide_code "943913"

    # Telemetry events of `names`, sent to the test as `{ref, name, measurements, meta}`.
    defp capture_events(names) do
      ref = make_ref()
      parent = self()

      :telemetry.attach_many(
        "totp-sections-#{inspect(ref)}",
        names,
        fn name, measurements, meta, _ -> send(parent, {ref, name, measurements, meta}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach("totp-sections-#{inspect(ref)}") end)
      ref
    end

    # Runs `fun` once, right after the first query on `table`: between the
    # code under test's read and its write.
    defp after_first_query(table, fun) do
      id = make_ref()

      :telemetry.attach(
        id,
        [:macaw, :auth, :test, :repo, :query],
        fn _event, _measurements, %{source: source}, _config ->
          if source == table do
            :telemetry.detach(id)
            fun.()
          end
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(id) end)
    end

    @tag verifies: "auth-totp"
    test "the Totp functions don't throttle, Native's do; every function honors :now" do
      {user, secret, _} = enrolled!()

      # Straight to Totp: six wrong codes, and the right one is still checked.
      for _ <- 1..6,
          do: assert(Totp.verify(user, "000001", now: at(600)) == {:error, :invalid_code})

      assert Totp.verify(user, Totp.code(secret, at(600)), now: at(600)) == :ok

      # Through Native: five wrong codes, and the right one is refused
      # unchecked, by verify_second_factor/3 and by disable/3 alike.
      {other, other_secret, _} = enrolled!()
      {:ok, _token, session} = Native.create_session(other, now: at(600))

      for _ <- 1..5 do
        assert Native.verify_second_factor(session.id, "000001", now: at(600)) ==
                 {:error, :invalid_code}
      end

      right = Totp.code(other_secret, at(600))
      assert Native.verify_second_factor(session.id, right, now: at(600)) == {:error, :throttled}
      assert Native.disable(other, right, now: at(600)) == {:error, :throttled}

      # :now is the clock: the confirmation's time and step, the codes' time.
      fresh = user!()
      {:ok, %{ticket: ticket, secret: fresh_secret}} = Native.enroll_begin(fresh, now: at(-3600))
      {:ok, term, record} = Totp.open_ticket(ticket, [:chosen], now: at(-3600))
      assert term.issued_at == DateTime.to_unix(at(-3600))

      {:ok, _} =
        Totp.enroll_confirm({term, record}, Totp.code(fresh_secret, at(-3600)), now: at(-3600))

      assert row(fresh).totp_enabled_at == at(-3600)
      assert row(fresh).totp_last_step == Totp.step(at(-3600))

      {:ok, _} = Totp.regenerate_recovery_codes(fresh, now: at(7200))

      assert Repo.all(where(RecoveryCodeRecord, user_id: ^fresh.id))
             |> Enum.map(& &1.inserted_at)
             |> Enum.uniq() == [at(7200)]
    end

    @tag verifies: "auth-totp-codes"
    test "codes are RFC 6238's at six digits, steps are 30 seconds, input is normalized" do
      # RFC 6238 appendix B's SHA-1 secret: 94287082 at 59 s, 07081804 at
      # 1111111109 s, as six digits.
      rfc = "12345678901234567890"
      assert Totp.code(rfc, 59) == "287082"
      assert Totp.code(rfc, 1_111_111_109) == "081804"
      assert Totp.code(rfc, DateTime.from_unix!(1_111_111_109)) == "081804"

      assert Totp.step(59) == 1
      assert Totp.step(60) == 2
      assert Totp.step(DateTime.from_unix!(1_111_111_109)) == div(1_111_111_109, 30)

      # A 160-bit secret.
      {:ok, %{secret: secret}} = Native.enroll_begin(user!(), now: @t0)
      assert byte_size(secret) == 20

      assert Totp.normalize(" ab-cd 12-\t3 ") == "ABCD123"
      assert Totp.normalize(String.duplicate("1", 64)) == String.duplicate("1", 64)
      assert Totp.normalize(String.duplicate("1", 65)) == ""
      assert Totp.normalize(123_456) == ""
      assert Totp.normalize(nil) == ""

      # Ten characters outside the recovery alphabet are neither kind: refused.
      {user, _secret, [code | _]} = enrolled!()
      lookalike = "0" <> binary_part(String.replace(code, "-", ""), 1, 9)
      assert Totp.verify(user, lookalike) == {:error, :invalid_code}
      assert Native.recovery_codes_left(user) == 10
    end

    @tag verifies: "auth-totp-replay"
    test "the earliest matching step later than the stored one is taken; a claim needs an enrollment" do
      {user, _secret, _} = enrolled!()

      sealed =
        Seal.seal(@collide_secret, Seal.key!(@key), "macaw_auth totp_secret " <> user.id)

      Repo.update_all(where(UserRecord, id: ^user.id),
        set: [totp_secret_sealed: sealed, totp_last_step: nil]
      )

      step = Totp.step(@collide_now)
      assert Totp.code(@collide_secret, (step - 1) * 30) == @collide_code
      assert Totp.code(@collide_secret, step * 30) == @collide_code

      # The code matches steps s - 1 and s: the earliest is taken, then the
      # next later one, then none is left.
      assert Totp.verify(user, @collide_code, now: @collide_now) == :ok
      assert row(user).totp_last_step == step - 1
      assert Totp.verify(user, @collide_code, now: @collide_now) == :ok
      assert row(user).totp_last_step == step
      assert Totp.verify(user, @collide_code, now: @collide_now) == {:error, :invalid_code}

      # An enrollment begun but not confirmed has nothing to claim.
      pending = user!()
      {:ok, _} = Native.enroll_begin(pending, now: @t0)
      assert Totp.claim_step(Repo, pending.id, step) == :replayed
      assert row(pending).totp_last_step == nil
    end

    @tag verifies: "auth-totp-enroll"
    test "enrollment: the secret sealed into the ticket, none stored, one of two racing confirmations" do
      user = user!()
      {:ok, %{ticket: ticket, secret: secret, uri: uri}} = Native.enroll_begin(user, now: @t0)

      # The ticket carries the secret sealed as at rest, bound to the user;
      # nothing is written.
      {:ok, %{account_id: id, purpose: :chosen, secret: sealed}, _record} =
        Totp.open_ticket(ticket, [:chosen], now: @t0)

      assert id == user.id

      assert Seal.unseal(sealed, Seal.key!(@key), "macaw_auth totp_secret " <> user.id) ==
               {:ok, secret}

      assert row(user).totp_secret_sealed == nil
      assert row(user).totp_enabled_at == nil
      assert uri =~ "otpauth://totp/Test%20App:#{user.username}?"
      assert uri =~ "issuer=Test%20App"

      assert Native.enroll_begin(%{user | id: Ecto.UUID.generate()}) == {:error, :not_found}

      # Confirmed: the row holds the ticket's sealed secret, as it was.
      {:ok, _} = Native.enroll_confirm(user, ticket, Totp.code(secret, @t0), now: @t0)
      assert row(user).totp_secret_sealed == sealed

      # Two confirmations of one ticket at once: the other's write lands
      # between this one's read and its own; this one is refused.
      racer = user!()
      {:ok, %{ticket: raced, secret: raced_secret}} = Native.enroll_begin(racer, now: @t0)
      code = Totp.code(raced_secret, @t0)
      parent = self()

      after_first_query("macaw_auth_users", fn ->
        send(parent, {:other, Native.enroll_confirm(racer, raced, code, now: @t0)})
      end)

      assert Native.enroll_confirm(racer, raced, code, now: @t0) == {:error, :invalid_ticket}
      assert_received {:other, {:ok, [_ | _]}}
      assert reload(racer).second_factor == :enrolled
      assert Native.recovery_codes_left(racer) == 10

      # Disabled between the confirmation's read and its write: refused,
      # nothing enabled.
      disabled = user!()
      {:ok, %{ticket: late, secret: late_secret}} = Native.enroll_begin(disabled, now: @t0)

      after_first_query("macaw_auth_users", fn ->
        {:ok, _} = Native.disable_user(disabled.username)
      end)

      assert Native.enroll_confirm(disabled, late, Totp.code(late_secret, @t0), now: @t0) ==
               {:error, :invalid_ticket}

      assert row(disabled).totp_enabled_at == nil
      assert Native.recovery_codes_left(disabled) == 0
    end

    @tag verifies: "auth-totp-seal"
    test "the key is derived, the seal bound to the row, versioned, and a key fault never shows the key" do
      assert Seal.min_bytes() == 32
      assert Seal.key!(@key) == :crypto.mac(:hmac, :sha256, @key, "macaw_auth sealing v1")
      refute Seal.key!(@key) == @key

      # The format: version 1, a 12-byte IV, a 16-byte tag, the ciphertext.
      key = Seal.key!(@key)
      <<1, iv::binary-12, tag::binary-16, ciphertext::binary>> = Seal.seal("secret", key, "aad")

      assert :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, "aad", tag, false) ==
               "secret"

      sealed = Seal.seal("secret", key, "aad")
      <<_, rest::binary>> = sealed
      assert Seal.unseal(<<2, rest::binary>>, key, "aad") == {:error, :wrong_key}
      <<head::binary-29, last, tail::binary>> = sealed
      tampered = <<head::binary, Bitwise.bxor(last, 1), tail::binary>>
      assert Seal.unseal(tampered, key, "aad") == {:error, :wrong_key}

      # The function is called at each use.
      counter = :counters.new(1, [])
      configure!(sealing_key: {__MODULE__, :counted_key, [counter, Base.encode64(@key)]})
      {:ok, _} = Native.enroll_begin(user!(), now: @t0)
      {:ok, _} = Native.enroll_begin(user!(), now: @t0)
      assert :counters.get(counter, 1) == 2

      # A short literal key at use, and a function's: named, never shown.
      secret_arg = "a secret argument"

      for source <- ["short literal key", {__MODULE__, :key, [secret_arg]}] do
        error = assert_raise SealingKeyError, fn -> Seal.key!(source) end
        assert error.message =~ "sealing_key"
        refute error.message =~ "short literal key"
        refute error.message =~ secret_arg
      end

      # A stored secret under another key: loud, naming the fault, not the key.
      {user, secret, _} = enrolled!()
      other = :crypto.strong_rand_bytes(32)
      configure!(sealing_key: other)

      error =
        assert_raise SealingKeyError, fn ->
          Totp.verify(user, Totp.code(secret, at(300)), now: at(300))
        end

      assert error.message ==
               "a stored TOTP secret does not unseal with the configured sealing_key: " <>
                 "the key has changed since it was sealed, or the row was altered"
    end

    @tag verifies: "auth-totp-verify"
    test "verifying resolves the session untouched, refuses with the session's reason, and spends the code" do
      {user, secret, _} = enrolled!()
      {:ok, _token, session} = Native.create_session(user, now: at(600))
      used = Repo.get!(Macaw.Auth.Native.SessionRecord, session.id).last_used_at

      assert Native.verify_second_factor(session.id, Totp.code(secret, at(4200)), now: at(4200)) ==
               :ok

      assert Repo.get!(Macaw.Auth.Native.SessionRecord, session.id).last_used_at == used

      # The session's own refusals come first.
      assert Native.verify_second_factor(Ecto.UUID.generate(), "123456", []) ==
               {:error, :invalid}

      {:ok, _} = Native.disable_user(user.username)

      assert Native.verify_second_factor(session.id, Totp.code(secret, at(4230)), now: at(4230)) ==
               {:error, :disabled}

      # Not enrolled (begun, not confirmed), replayed, junk: one refusal.
      pending = user!()
      {:ok, %{secret: pending_secret}} = Native.enroll_begin(pending, now: @t0)

      assert Totp.verify(pending, Totp.code(pending_secret, at(300)), now: at(300)) ==
               {:error, :invalid_code}

      {other, other_secret, _} = enrolled!()
      code = Totp.code(other_secret, at(300))
      assert Totp.verify(other, code, now: at(300)) == :ok
      assert Totp.verify(other, code, now: at(300)) == {:error, :invalid_code}
      assert Totp.verify(other, "junk", now: at(300)) == {:error, :invalid_code}
    end

    @tag verifies: "auth-totp-recovery"
    test "recovery codes: the alphabet, a conditional spend, none for a non-UUID" do
      {user, _secret, codes} = enrolled!()

      for code <- codes,
          <<char <- String.replace(code, "-", "")>>,
          do: assert(<<char>> in String.graphemes("23456789ABCDEFGHJKLMNPQRSTUVWXYZ"))

      # Two submissions of one code at once: exactly one spends it.
      code = hd(codes)
      parent = self()

      results =
        1..4
        |> Task.async_stream(
          fn _ ->
            Ecto.Adapters.SQL.Sandbox.allow(Repo, parent, self())
            Totp.verify(user, code)
          end,
          max_concurrency: 4
        )
        |> Enum.map(fn {:ok, result} -> result end)

      assert Enum.count(results, &(&1 == :ok)) == 1
      assert Native.recovery_codes_left(user) == 9
      assert Native.recovery_codes_left("not a uuid") == 0
      assert Totp.recovery_codes_left(user) == 9
    end

    @tag verifies: "auth-totp-policy"
    test "status: enrolled before required, required by true or by a role, else none" do
      config = fn required -> %{Config.get() | totp_required: required} end
      enrolled = %UserRecord{roles: ["admin"], totp_enabled_at: @t0}
      admin = %UserRecord{roles: ["admin"]}
      viewer = %UserRecord{roles: ["viewer"]}
      nobody = %UserRecord{roles: nil}

      assert Totp.status(enrolled, config.(["admin"])) == :enrolled
      assert Totp.status(enrolled, config.(true)) == :enrolled
      assert Totp.status(admin, config.(["admin", "ops"])) == :required
      assert Totp.status(viewer, config.(["admin"])) == :none
      assert Totp.status(nobody, config.(true)) == :required
      assert Totp.status(nobody, config.(["admin"])) == :none
      assert Totp.status(admin, config.(false)) == :none

      assert Totp.required?(viewer, config.(true))
      refute Totp.required?(viewer, config.(false))
    end

    @tag verifies: "auth-totp-disable"
    test "turning it off: with a recovery code, everything cleared; an admin's reset of one never enrolled" do
      {user, _secret, [code | _]} = enrolled!()
      assert Native.disable(user, code, now: at(300)) == :ok
      cleared = row(user)

      assert {cleared.totp_secret_sealed, cleared.totp_enabled_at, cleared.totp_last_step} ==
               {nil, nil, nil}

      assert Native.recovery_codes_left(user) == 0
      assert Native.disable(user, code, now: at(330)) == {:error, :invalid_code}

      # An administrator's reset, of a user who only began, revokes with its reason.
      pending = user!()
      {:ok, _} = Native.enroll_begin(pending, now: @t0)
      {:ok, token, _} = Native.create_session(pending, [])
      ref = capture_events([[:macaw_auth, :native, :session]])

      assert Native.admin_reset(pending) == :ok
      assert row(pending).totp_secret_sealed == nil
      assert Auth.fetch(token) == {:error, :invalid}
      assert_received {^ref, _, %{count: 1}, %{event: :revoked, reason: :second_factor_reset}}

      assert Native.admin_reset("not a uuid") == :ok
      assert Totp.admin_reset(Ecto.UUID.generate()) == :ok
    end

    @tag verifies: "auth-totp-telemetry"
    test "every second-factor event, counted once, with the event and the user's id only" do
      ref = capture_events([[:macaw_auth, :native, :second_factor]])

      user = user!()
      {:ok, %{ticket: ticket, secret: secret}} = Native.enroll_begin(user, now: @t0)
      {:ok, codes} = Native.enroll_confirm(user, ticket, Totp.code(secret, @t0), now: @t0)
      :ok = Totp.verify(user, Totp.code(secret, at(300)), now: at(300))
      {:error, :invalid_code} = Totp.verify(user, "000000", now: at(300))
      :ok = Totp.verify(user, hd(codes))
      {:ok, new_codes} = Native.regenerate_recovery_codes(user)
      # Disabling verifies the code first, then turns the second factor off.
      :ok = Native.disable(user, hd(new_codes))
      :ok = Native.admin_reset(user)

      events =
        Stream.repeatedly(fn ->
          receive do
            {^ref, name, measurements, meta} -> {name, measurements, meta}
          after
            0 -> nil
          end
        end)
        |> Enum.take_while(& &1)

      assert Enum.map(events, fn {_, _, meta} -> meta.event end) == [
               :enrollment_started,
               :enrolled,
               :verified,
               :refused,
               :recovery_code_used,
               :verified,
               :recovery_codes_regenerated,
               :recovery_code_used,
               :verified,
               :disabled,
               :reset
             ]

      # Exactly the event and the user's id: never a secret or a code.
      for {_name, measurements, meta} <- events do
        assert measurements == %{count: 1}
        assert meta == %{event: meta.event, user_id: user.id}
      end
    end
  end

  def counted_key(counter, value) do
    :counters.add(counter, 1, 1)
    Base.decode64!(value)
  end

  # The fixtures' passwords are "correct horse <n>" for "user<n>".
  defp password(user), do: "correct horse " <> String.trim_leading(user.username, "user")
end
