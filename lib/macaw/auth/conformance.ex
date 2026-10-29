defmodule Macaw.Auth.Conformance do
  @moduledoc """
  The conformance kit: what every `Macaw.Auth.Backend` must do, as tests a
  backend's author runs.

      defmodule MyBackend.ConformanceTest do
        use Macaw.Auth.Conformance, backend: MyBackend, fixtures: MyBackend.Fixtures
      end

  The fixtures module implements `Macaw.Auth.Conformance.Fixtures`: it resets
  the backend's store, makes users, disables and deletes them, says how
  long a session may idle, and lists every value the backend stores for
  sessions, so the kit can prove no token is stored as it is.

  A backend still being built may name a capability it doesn't have yet
  with `pending: [second_factor: "why"]`: the kit's tests that need it
  are then skipped, and say so in every test run's summary, rather than
  removed or passed by a fixture that pretends. The only capability so
  far is `:second_factor` (enrolling, verifying and requiring one).

  The kit checks:
  - valid credentials sign in; a wrong password and an unknown user are the
    same refusal (no enumeration); a disabled user is refused;
  - a session round-trips by token and by id; a garbage token is invalid;
  - a user deleted since signing in gets no session (`{:error, :invalid}`);
  - **no session token is ever stored as it is**;
  - revoking one session, or all but one, ends them, and **tells a
    subscribed process** (an open page) which ids ended;
  - an idle session expires, and a re-check (`touch: false`) never extends
    one; the backend's `session_idle_seconds/1` is the fixture's
    `idle_seconds/0` (the remember cookie's lifetime); a disabled user's
    live session is refused;
  - a user's sessions list newest first (two started a minute apart, by
    `:now`);
  - completing a step of a revoked session is `{:error, :invalid}`;
  - a user with a second factor owes it, and completing the step clears it;
    a user enrolled through the fixture is reported `:enrolled`; a valid
    code passes the step (`Macaw.Auth.verify_second_factor/3`), a wrong
    one doesn't, and **a code is accepted once**;
  - a user whom policy requires to have one **gets no session**, but an
    enrollment ticket, and enrolls from the ticket alone; a ticket is
    refused once expired (ten minutes, by `:now`), tampered, spent by the
    enrollment it completed, or its account disabled;
  - the backend exports `check_config!/0`, the check the application
    makes at start, and it is `:ok` for the configuration the kit's tests
    run under.
  """

  defmodule Fixtures do
    @moduledoc "What a backend gives the conformance kit."

    @doc "Resets the backend's store before each test."
    @callback reset!() :: :ok

    @doc """
    Makes a user; `attrs` may set `:second_factor` (`:none | :enrolled |
    :required`). Returns the user and credentials that sign it in.
    """
    @callback user!(map()) :: {Macaw.Auth.User.t(), map()}

    @doc "Disables a user."
    @callback disable!(Macaw.Auth.User.t()) :: :ok

    @doc """
    Deletes a user from the backend's store, as an administrator would,
    after they signed in: the kit then asks for a session for them.
    """
    @callback delete!(Macaw.Auth.User.t()) :: :ok

    @doc "How long a session may idle before it expires, in seconds."
    @callback idle_seconds() :: pos_integer()

    @doc "Every value the backend stores for sessions (to prove no token is stored as is)."
    @callback stored_session_values() :: [binary()]

    @doc """
    Enrolls `user` in the backend's second factor, the way a user would
    (begin, then confirm with a valid code), and returns a function that
    gives a code the backend accepts at the moment it is called and has
    not yet accepted: a fresh device's current code. (A fixture that
    confirmed with the current step's code should have confirmed with the
    previous step's, so the current one is still unspent.)
    """
    @callback enroll_second_factor!(Macaw.Auth.User.t()) :: (-> String.t())
  end

  defmacro __using__(opts) do
    backend = Keyword.fetch!(opts, :backend)
    fixtures = Keyword.fetch!(opts, :fixtures)
    pending = Keyword.get(opts, :pending, [])

    quote do
      use ExUnit.Case, async: false

      alias Macaw.Auth

      @backend unquote(backend)
      @fixtures unquote(fixtures)
      @second_factor_pending Keyword.get(unquote(pending), :second_factor)

      setup do
        previous = Application.get_env(:macaw_auth, :backend)
        Application.put_env(:macaw_auth, :backend, @backend)
        :ok = @fixtures.reset!()

        on_exit(fn ->
          if previous,
            do: Application.put_env(:macaw_auth, :backend, previous),
            else: Application.delete_env(:macaw_auth, :backend)
        end)

        :ok
      end

      describe "conformance: authenticate" do
        test "valid credentials sign in" do
          {user, creds} = @fixtures.user!(%{})
          assert {:ok, %Auth.User{id: id}} = Auth.authenticate(creds)
          assert id == user.id
        end

        test "a wrong password and an unknown user are the same refusal" do
          {_user, creds} = @fixtures.user!(%{})
          wrong = Auth.authenticate(%{creds | password: creds.password <> "x"})

          unknown =
            Auth.authenticate(%{creds | username: "nobody-#{System.unique_integer([:positive])}"})

          assert wrong == {:error, :invalid_credentials}
          assert unknown == wrong
        end

        test "a disabled user is refused" do
          {user, creds} = @fixtures.user!(%{})
          :ok = @fixtures.disable!(user)
          assert {:error, reason} = Auth.authenticate(creds)
          assert reason in [:disabled, :invalid_credentials]
        end
      end

      describe "conformance: sessions" do
        test "a session round-trips by token and by id" do
          {user, _} = @fixtures.user!(%{})
          {:ok, token, session} = Auth.create_session(user)
          assert {:ok, %{id: uid}, %{id: sid}} = Auth.fetch(token)
          assert {uid, sid} == {user.id, session.id}
          assert {:ok, _, %{id: ^sid}} = Auth.fetch_by_id(session.id)
        end

        test "a user deleted since signing in gets no session" do
          {user, _} = @fixtures.user!(%{})
          :ok = @fixtures.delete!(user)
          assert Auth.create_session(user) == {:error, :invalid}
          assert Auth.list_sessions(user.id) == []
        end

        test "a garbage token is invalid" do
          assert Auth.fetch(:crypto.strong_rand_bytes(32)) == {:error, :invalid}
          assert Auth.fetch(nil) == {:error, :invalid}
        end

        test "no session token is stored as it is" do
          {user, _} = @fixtures.user!(%{})
          tokens = for _ <- 1..3, do: elem(Auth.create_session(user), 1)
          stored = @fixtures.stored_session_values()

          for token <- tokens, value <- stored do
            refute value == token
            refute value == Base.encode64(token)
            refute value == Base.url_encode64(token, padding: false)
          end
        end

        test "revoking a session ends it and tells subscribed processes" do
          {user, _} = @fixtures.user!(%{})
          {:ok, token, session} = Auth.create_session(user)
          :ok = Auth.subscribe(user.id)

          :ok = Auth.revoke(session.id)

          assert Auth.fetch(token) == {:error, :invalid}
          assert_receive {:sessions_revoked, [id]}
          assert id == session.id
        end

        test "revoking all but one keeps that one" do
          {user, _} = @fixtures.user!(%{})
          {:ok, keep, kept} = Auth.create_session(user)
          {:ok, gone1, _} = Auth.create_session(user)
          {:ok, gone2, _} = Auth.create_session(user)
          :ok = Auth.subscribe(user.id)

          :ok = Auth.revoke({:user, user.id}, except: kept.id)

          assert {:ok, _, _} = Auth.fetch(keep)
          assert Auth.fetch(gone1) == {:error, :invalid}
          assert Auth.fetch(gone2) == {:error, :invalid}
          assert_receive {:sessions_revoked, ids}
          assert length(ids) == 2
        end

        test "revoking nothing tells nobody" do
          {user, _} = @fixtures.user!(%{})
          :ok = Auth.subscribe(user.id)
          :ok = Auth.revoke({:user, user.id})
          refute_receive {:sessions_revoked, _}
        end

        test "an idle session expires, and a re-check never extends one" do
          {user, _} = @fixtures.user!(%{})
          {:ok, token, _} = Auth.create_session(user)
          idle = @fixtures.idle_seconds()
          now = DateTime.utc_now()

          almost = DateTime.add(now, idle - 5, :second)
          assert {:ok, _, _} = Auth.fetch(token, touch: false, now: almost)

          past = DateTime.add(now, idle + 5, :second)
          assert Auth.fetch(token, touch: false, now: past) == {:error, :expired}
        end

        test "the backend reports the idle limit it expires sessions by" do
          assert Auth.session_idle_seconds() == @fixtures.idle_seconds()
        end

        test "a disabled user's live session is refused" do
          {user, _} = @fixtures.user!(%{})
          {:ok, token, _} = Auth.create_session(user)
          :ok = @fixtures.disable!(user)
          assert {:error, reason} = Auth.fetch(token)
          assert reason in [:disabled, :invalid]
        end

        test "a user's sessions list newest first" do
          {user, _} = @fixtures.user!(%{})
          # A minute apart by `:now`, not by waiting on the clock.
          earlier = DateTime.utc_now()
          later = DateTime.add(earlier, 60, :second)
          {:ok, _, first} = Auth.create_session(user, now: earlier)
          {:ok, _, second} = Auth.create_session(user, now: later)
          assert [%{id: a}, %{id: b}] = Auth.list_sessions(user.id)
          assert {a, b} == {second.id, first.id}
        end
      end

      describe "conformance: steps" do
        test "a user without a second factor owes nothing" do
          {user, _} = @fixtures.user!(%{})
          {:ok, _token, session} = Auth.create_session(user)
          assert Auth.pending_step(user, session) == nil
        end

        test "completing a step of a revoked session is invalid" do
          {user, _} = @fixtures.user!(%{})
          {:ok, token, session} = Auth.create_session(user)
          :ok = Auth.revoke(session.id)

          assert Auth.complete_step(session.id, :password_change) == {:error, :invalid}
          assert Auth.fetch(token) == {:error, :invalid}
        end
      end

      describe "conformance: second factor" do
        if @second_factor_pending,
          do: @describetag(skip: "pending (second factor): " <> @second_factor_pending)

        test "an enrolled second factor is owed until completed" do
          {user, creds} = @fixtures.user!(%{second_factor: :enrolled})
          {:ok, user} = Auth.authenticate(creds)
          {:ok, token, session} = Auth.create_session(user)
          assert Auth.pending_step(user, session) == :second_factor

          :ok = Auth.complete_step(session.id, :second_factor)
          {:ok, user, session} = Auth.fetch(token)
          assert Auth.pending_step(user, session) == nil
        end

        test "an enrolled user is reported so, and a valid code passes the step" do
          {user, creds} = @fixtures.user!(%{})
          next_code = @fixtures.enroll_second_factor!(user)
          {:ok, user} = Auth.authenticate(creds)
          assert user.second_factor == :enrolled

          {:ok, token, session} = Auth.create_session(user)
          assert Auth.pending_step(user, session) == :second_factor

          assert Auth.verify_second_factor(session.id, next_code.()) == :ok
          {:ok, user, session} = Auth.fetch(token)
          assert Auth.pending_step(user, session) == nil
        end

        test "a wrong code is refused, and the step is still owed" do
          {user, creds} = @fixtures.user!(%{})
          next_code = @fixtures.enroll_second_factor!(user)
          {:ok, user} = Auth.authenticate(creds)
          {:ok, token, session} = Auth.create_session(user)

          assert {:error, _} = Auth.verify_second_factor(session.id, wrong(next_code.()))
          {:ok, user, session} = Auth.fetch(token)
          assert Auth.pending_step(user, session) == :second_factor
        end

        test "a code is accepted once" do
          {user, creds} = @fixtures.user!(%{})
          next_code = @fixtures.enroll_second_factor!(user)
          {:ok, user} = Auth.authenticate(creds)
          {:ok, _, first} = Auth.create_session(user)
          {:ok, token, second} = Auth.create_session(user)
          code = next_code.()

          assert Auth.verify_second_factor(first.id, code) == :ok
          assert {:error, _} = Auth.verify_second_factor(second.id, code)
          {:ok, user, session} = Auth.fetch(token)
          assert Auth.pending_step(user, session) == :second_factor
        end

        test "a user whom policy requires to have one gets no session, and enrolls from a ticket alone" do
          {user, creds} = @fixtures.user!(%{second_factor: :required})
          {:ok, user} = Auth.authenticate(creds)
          assert user.second_factor == :required
          assert Auth.create_session(user) == {:error, :enrollment_required}

          assert Auth.create_session(user, second_factor_passed: true) ==
                   {:error, :enrollment_required}

          now = DateTime.utc_now()
          {:ok, ticket} = Auth.enrollment_ticket(user, now: now)
          assert is_binary(ticket)

          assert {:ok, %{secret: secret, uri: "otpauth://totp/" <> _}} =
                   Auth.enrollment(ticket, now: now)

          assert Auth.enroll_second_factor(ticket, wrong(code(secret, now)), now: now) ==
                   {:error, :invalid_code}

          assert {:ok, %Auth.User{id: id, second_factor: :enrolled}, codes} =
                   Auth.enroll_second_factor(ticket, code(secret, now), now: now)

          assert id == user.id
          assert is_list(codes)
          assert Auth.list_sessions(user.id) == []
          assert {:ok, %Auth.User{second_factor: :enrolled}} = Auth.authenticate(creds)
        end

        test "an expired or tampered enrollment ticket is refused" do
          {user, _} = @fixtures.user!(%{second_factor: :required})
          now = DateTime.utc_now()
          {:ok, ticket} = Auth.enrollment_ticket(user, now: now)
          {:ok, %{secret: secret}} = Auth.enrollment(ticket, now: now)

          almost = DateTime.add(now, 599, :second)
          late = DateTime.add(now, 600, :second)
          assert {:ok, %{secret: ^secret}} = Auth.enrollment(ticket, now: almost)
          assert Auth.enrollment(ticket, now: late) == {:error, :invalid_ticket}

          assert Auth.enroll_second_factor(ticket, code(secret, late), now: late) ==
                   {:error, :invalid_ticket}

          for refused <- [tampered(ticket), :crypto.strong_rand_bytes(64), "", nil] do
            assert Auth.enrollment(refused, now: now) == {:error, :invalid_ticket}

            assert Auth.enroll_second_factor(refused, code(secret, now), now: now) ==
                     {:error, :invalid_ticket}
          end

          assert {:ok, _user, _codes} =
                   Auth.enroll_second_factor(ticket, code(secret, now), now: now)
        end

        test "an enrollment ticket is spent by the enrollment it completes" do
          {user, _} = @fixtures.user!(%{second_factor: :required})
          now = DateTime.utc_now()
          {:ok, ticket} = Auth.enrollment_ticket(user, now: now)
          {:ok, %{secret: secret}} = Auth.enrollment(ticket, now: now)
          {:ok, _user, _codes} = Auth.enroll_second_factor(ticket, code(secret, now), now: now)

          next = DateTime.add(now, 30, :second)
          assert Auth.enrollment(ticket, now: next) == {:error, :invalid_ticket}

          assert Auth.enroll_second_factor(ticket, code(secret, next), now: next) ==
                   {:error, :invalid_ticket}

          # The account is enrolled now: no further ticket is issued for it.
          assert {:error, _} = Auth.enrollment_ticket(user, now: next)
        end

        test "an enrollment ticket of an account disabled during its lifetime is refused" do
          {user, _} = @fixtures.user!(%{second_factor: :required})
          now = DateTime.utc_now()
          {:ok, ticket} = Auth.enrollment_ticket(user, now: now)
          {:ok, %{secret: secret}} = Auth.enrollment(ticket, now: now)
          :ok = @fixtures.disable!(user)

          assert Auth.enrollment(ticket, now: now) == {:error, :invalid_ticket}

          assert Auth.enroll_second_factor(ticket, code(secret, now), now: now) ==
                   {:error, :invalid_ticket}

          assert {:error, _} = Auth.enrollment_ticket(user, now: now)
        end
      end

      describe "conformance: configuration" do
        test "the backend checks its configuration" do
          Code.ensure_loaded!(@backend)
          assert function_exported?(@backend, :check_config!, 0)
          assert @backend.check_config!() == :ok
        end
      end

      # Every digit changed, so the code differs from the valid one.
      defp wrong(code),
        do: for(<<d <- code>>, into: "", do: <<?0 + rem(d - ?0 + 5, 10)>>)

      # A ticket's secret is TOTP (RFC 6238, 30 s, six digits): its code at `time`.
      defp code(secret, time), do: NimbleTOTP.verification_code(secret, time: time)

      # The last byte flipped: a ticket that no longer authenticates.
      defp tampered(ticket) do
        size = byte_size(ticket) - 1
        <<head::binary-size(^size), last>> = ticket
        <<head::binary, Bitwise.bxor(last, 1)>>
      end
    end
  end
end
