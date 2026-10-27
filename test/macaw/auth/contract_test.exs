defmodule Macaw.Auth.ContractTest.Recorder do
  @moduledoc """
  A backend that records each call it gets, sending `{:backend, call}` to
  the calling process, and answers each callback with a fixed value: what
  the facade passes through, and what it returns, is then exactly visible.
  """

  @behaviour Macaw.Auth.Backend

  alias Macaw.Auth.{Session, User}

  def user, do: %User{id: 1, username: "recorded"}
  def session, do: %Session{id: 7, user_id: 1}

  @impl true
  def authenticate(credentials, opts),
    do: reply({:authenticate, credentials, opts}, {:ok, user()})

  @impl true
  def create_session(user, opts),
    do: reply({:create_session, user, opts}, {:ok, "a token", session()})

  @impl true
  def fetch_session(token, opts),
    do: reply({:fetch_session, token, opts}, {:ok, user(), session()})

  @impl true
  def fetch_session_by_id(id, opts),
    do: reply({:fetch_session_by_id, id, opts}, {:error, :expired})

  @impl true
  def session_idle_seconds(opts), do: reply({:session_idle_seconds, opts}, 42)

  @impl true
  def list_sessions(user_id, opts), do: reply({:list_sessions, user_id, opts}, [session()])

  @impl true
  def revoke_sessions(target, opts), do: reply({:revoke_sessions, target, opts}, {1, [7]})

  @impl true
  def complete_step(id, step, opts), do: reply({:complete_step, id, step, opts}, :ok)

  @impl true
  def verify_second_factor(id, code, opts),
    do: reply({:verify_second_factor, id, code, opts}, {:error, :invalid_code})

  defp reply(call, answer) do
    send(self(), {:backend, call})
    answer
  end
end

defmodule Macaw.Auth.ContractTest do
  # The contract (spec 01) as every backend keeps it: what the facade owns,
  # and what each backend must do, checked against the in-memory test
  # backend and the native backend alike.
  use ExUnit.Case, async: false

  alias Macaw.Auth
  alias Macaw.Auth.{Backend, Native, Session, User}
  alias Macaw.Auth.ContractTest.Recorder
  alias Macaw.Auth.Native.Config
  alias Macaw.Auth.Test.MemoryBackend, as: Mem
  alias Macaw.Auth.Test.{NativeFixtures, Repo}

  @backends [{Mem, Mem}, {Native, NativeFixtures}]

  # A test tagged `backend: {backend, fixtures}` runs against that backend,
  # its store reset; any other, against the in-memory one.
  setup context do
    previous = Application.get_env(:macaw_auth, :backend)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:macaw_auth, :backend, previous),
        else: Application.delete_env(:macaw_auth, :backend)

      Application.delete_env(:macaw_auth, :pubsub)
    end)

    {backend, fixtures} = Map.get(context, :backend, {Mem, Mem})
    Application.put_env(:macaw_auth, :backend, backend)
    :ok = fixtures.reset!()
    :ok
  end

  defp user(fields \\ %{}), do: struct!(User, Map.merge(%{id: 1, username: "u"}, fields))
  defp session(fields \\ %{}), do: struct!(Session, Map.merge(%{id: 7, user_id: 1}, fields))

  describe "the facade" do
    setup do
      Application.put_env(:macaw_auth, :backend, Recorder)
      :ok
    end

    @tag verifies: "facade-fetch-non-binary"
    test "fetch/2 of anything but a binary is invalid, the backend never asked" do
      assert Auth.fetch(nil) == {:error, :invalid}
      assert Auth.fetch(:x) == {:error, :invalid}
      refute_received {:backend, _}
    end

    @tag verifies: "facade-complete-step-guard"
    test "complete_step/3 takes only a step, and passes each step on" do
      # Through apply/3: the compiler would refuse the call as written.
      assert_raise FunctionClauseError, fn -> apply(Auth, :complete_step, [7, :not_a_step]) end
      refute_received {:backend, _}

      for step <- [:second_factor, :second_factor_enroll, :password_change] do
        assert Auth.complete_step(7, step) == :ok
        assert_received {:backend, {:complete_step, 7, ^step, []}}
      end
    end

    @tag verifies: "auth-contract-facade"
    test "each function calls its callback with its arguments and opts unchanged, and returns its answer" do
      now = ~U[2026-10-01 12:00:00Z]
      opts = [now: now, remote_ip: "192.0.2.1"]
      user = Recorder.user()
      session = Recorder.session()
      creds = %{username: "a", password: "b"}

      assert Auth.authenticate(creds, opts) == {:ok, user}
      assert_received {:backend, {:authenticate, ^creds, ^opts}}

      # The facade adds second_factor_passed (§5); everything else passes as given.
      assert Auth.create_session(user, opts) == {:ok, "a token", session}
      assert_received {:backend, {:create_session, ^user, given}}
      assert Keyword.delete(given, :second_factor_passed) == opts

      assert Auth.fetch("t", opts) == {:ok, user, session}
      assert_received {:backend, {:fetch_session, "t", ^opts}}

      assert Auth.fetch_by_id(7, opts) == {:error, :expired}
      assert_received {:backend, {:fetch_session_by_id, 7, ^opts}}

      assert Auth.session_idle_seconds(opts) == 42
      assert_received {:backend, {:session_idle_seconds, ^opts}}

      assert Auth.list_sessions(1, opts) == [session]
      assert_received {:backend, {:list_sessions, 1, ^opts}}

      assert Auth.complete_step(7, :password_change, opts) == :ok
      assert_received {:backend, {:complete_step, 7, :password_change, ^opts}}

      assert Auth.verify_second_factor(7, "123456", opts) == {:error, :invalid_code}
      assert_received {:backend, {:verify_second_factor, 7, "123456", ^opts}}

      # revoke/2: revoke_sessions/2, then the push to the user's pages.
      :ok = Auth.subscribe(1)
      assert Auth.revoke({:user, 1}, opts) == :ok
      assert_received {:backend, {:revoke_sessions, {:user, 1}, ^opts}}
      assert_received {:sessions_revoked, [7]}
    end
  end

  describe "choosing the backend" do
    @tag verifies: "backend-unset"
    test "with :backend unset, backend/0 raises; set, it is that module" do
      Application.delete_env(:macaw_auth, :backend)
      assert_raise ArgumentError, fn -> Auth.backend() end

      Application.put_env(:macaw_auth, :backend, Mem)
      assert Auth.backend() == Mem
    end

    @tag verifies: "auth-backend-config"
    test "read at each call: unset, every call through it raises; changed, the next call goes to the new one" do
      Application.delete_env(:macaw_auth, :backend)
      assert_raise ArgumentError, fn -> Auth.authenticate(%{username: "a", password: "b"}) end
      assert_raise ArgumentError, fn -> Auth.fetch("a token") end
      assert_raise ArgumentError, fn -> Auth.revoke({:user, 1}) end

      Application.put_env(:macaw_auth, :backend, Mem)
      assert Auth.fetch("a token") == {:error, :invalid}
      refute_received {:backend, _}

      Application.put_env(:macaw_auth, :backend, Recorder)
      assert Auth.fetch("a token") == {:ok, Recorder.user(), Recorder.session()}
      assert_received {:backend, {:fetch_session, "a token", []}}
    end
  end

  describe "every backend" do
    @tag verifies: "auth-backend"
    test "nine callbacks; :now moves the clock; refusals are values; only a hash of a token is stored" do
      assert Enum.sort(Backend.behaviour_info(:callbacks)) ==
               Enum.sort(
                 authenticate: 2,
                 create_session: 2,
                 fetch_session: 2,
                 fetch_session_by_id: 2,
                 session_idle_seconds: 1,
                 list_sessions: 2,
                 revoke_sessions: 2,
                 complete_step: 3,
                 verify_second_factor: 3
               )

      for {backend, fixtures} <- @backends do
        Application.put_env(:macaw_auth, :backend, backend)
        :ok = fixtures.reset!()
        {user, creds} = fixtures.user!(%{})
        t0 = ~U[2026-10-01 12:00:00.000000Z]
        idle = fixtures.idle_seconds()

        # :now overrides the clock: idle expiry follows it, not the wall's.
        {:ok, token, _} = Auth.create_session(user, now: t0)
        assert {:ok, _, _} = Auth.fetch(token, now: DateTime.add(t0, idle))
        assert Auth.fetch(token, now: DateTime.add(t0, idle + 1)) == {:error, :expired}

        # An ordinary refusal is a value, never a raise.
        assert Auth.authenticate(%{creds | password: "wrong"}) == {:error, :invalid_credentials}
        assert Auth.fetch("no such token") == {:error, :invalid}
        assert Auth.fetch_by_id("no such id") == {:error, :invalid}
        assert Auth.complete_step("no such id", :password_change) == {:error, :invalid}

        # No more than a hash of a token is stored.
        {:ok, token, _} = Auth.create_session(user)
        stored = fixtures.stored_session_values()
        refute token in stored
        refute Base.encode64(token) in stored
        refute Base.url_encode64(token, padding: false) in stored

        # A disabled user's session is refused.
        :ok = fixtures.disable!(user)
        assert {:error, _} = Auth.fetch(token)
      end
    end

    for {backend, fixtures} <- @backends do
      @tag backend: {backend, fixtures}
      @tag verifies: "backend-one-refusal"
      test "a wrong password and an unknown username are one refusal: #{inspect(backend)}",
           %{backend: {_, fixtures}} do
        {_user, creds} = fixtures.user!(%{})
        wrong = Auth.authenticate(%{creds | password: creds.password <> "x"})
        unknown = Auth.authenticate(%{creds | username: "nobody-at-all"})

        assert wrong == {:error, :invalid_credentials}
        assert unknown == {:error, :invalid_credentials}
      end
    end

    for {backend, fixtures} <- @backends do
      @tag backend: {backend, fixtures}
      @tag verifies: "auth-backend-authenticate"
      test "a user signs in as a User; a disabled one is told so only with the right password: #{inspect(backend)}",
           %{backend: {_, fixtures}} do
        {user, creds} = fixtures.user!(%{})

        assert {:ok, %User{id: id, username: name}} =
                 Auth.authenticate(creds, remote_ip: "192.0.2.1")

        assert {id, name} == {user.id, user.username}

        :ok = fixtures.disable!(user)
        assert Auth.authenticate(creds) == {:error, :disabled}

        assert Auth.authenticate(%{creds | password: creds.password <> "x"}) ==
                 {:error, :invalid_credentials}
      end
    end

    for {backend, fixtures} <- @backends do
      @tag backend: {backend, fixtures}
      @tag verifies: "create-session-deleted-user"
      test "a user deleted after signing in gets no session: #{inspect(backend)}",
           %{backend: {_, fixtures}} do
        {_user, creds} = fixtures.user!(%{})
        {:ok, user} = Auth.authenticate(creds)
        :ok = fixtures.delete!(user)

        assert Auth.create_session(user) == {:error, :invalid}
        assert Auth.list_sessions(user.id) == []
      end
    end

    for {backend, fixtures} <- @backends do
      @tag backend: {backend, fixtures}
      @tag verifies: "auth-backend-create-session"
      test "create_session gives the client a token and records the client and the clock: #{inspect(backend)}",
           %{backend: {_, fixtures}} do
        {user, _} = fixtures.user!(%{})
        now = ~U[2026-10-01 12:00:00.000000Z]

        assert {:ok, token, %Session{} = session} =
                 Auth.create_session(user,
                   remote_ip: "192.0.2.1",
                   user_agent: "a browser",
                   second_factor_passed: false,
                   now: now
                 )

        assert is_binary(token)
        assert session.user_id == user.id
        assert {session.remote_ip, session.user_agent} == {"192.0.2.1", "a browser"}
        assert session.second_factor_passed == false
        assert session.last_used_at == now

        # The token is the client's only: the session it resolves to doesn't carry it.
        refute token in Map.values(session)
        assert {:ok, _, %{id: id}} = Auth.fetch(token, now: now)
        assert id == session.id
      end
    end

    for {backend, fixtures} <- @backends do
      @tag backend: {backend, fixtures}
      @tag verifies: "auth-backend-fetch"
      test "touch: true extends an idle session, touch: false never does; each refusal by its reason: #{inspect(backend)}",
           %{backend: {_, fixtures}} do
        {user, _} = fixtures.user!(%{})
        t0 = ~U[2026-10-01 12:00:00.000000Z]
        idle = fixtures.idle_seconds()
        at = &DateTime.add(t0, &1)

        {:ok, token, session} = Auth.create_session(user, now: t0)

        # A re-check, however late, never extends it.
        assert {:ok, _, _} = Auth.fetch(token, touch: false, now: at.(idle - 5))
        assert {:ok, _, _} = Auth.fetch_by_id(session.id, touch: false, now: at.(idle - 5))
        # A request records its use, which extends it.
        assert {:ok, _, _} = Auth.fetch(token, touch: true, now: at.(idle - 5))
        assert {:ok, _, %{id: id}} = Auth.fetch_by_id(session.id, now: at.(idle + 5))
        assert id == session.id
        assert Auth.fetch(token, now: at.(2 * idle)) == {:error, :expired}

        # Garbage, a revoked session and a disabled user's.
        assert Auth.fetch(:crypto.strong_rand_bytes(32)) == {:error, :invalid}
        {:ok, revoked, gone} = Auth.create_session(user)
        :ok = Auth.revoke(gone.id)
        assert Auth.fetch(revoked) == {:error, :invalid}
        assert Auth.fetch_by_id(gone.id) == {:error, :invalid}

        {:ok, live, _} = Auth.create_session(user)
        :ok = fixtures.disable!(user)
        assert Auth.fetch(live) == {:error, :disabled}
      end
    end

    for {backend, fixtures} <- @backends do
      @tag backend: {backend, fixtures}
      @tag verifies: "auth-backend-list"
      test "a user's sessions list newest first: #{inspect(backend)}", %{backend: {_, fixtures}} do
        {user, _} = fixtures.user!(%{})
        {other, _} = fixtures.user!(%{})
        t0 = ~U[2026-10-01 12:00:00.000000Z]

        ids =
          for n <- 0..2 do
            {:ok, _, s} = Auth.create_session(user, now: DateTime.add(t0, n))
            s.id
          end

        {:ok, _, _} = Auth.create_session(other, now: t0)

        listed = Auth.list_sessions(user.id, now: DateTime.add(t0, 3))
        assert Enum.map(listed, & &1.id) == Enum.reverse(ids)
      end
    end

    for {backend, fixtures} <- @backends do
      @tag backend: {backend, fixtures}
      @tag verifies: "auth-backend-revoke"
      test "revoke_sessions/2 ends one or a user's all but one, answers the ids, and pushes nothing: #{inspect(backend)}",
           %{backend: {backend, fixtures}} do
        {user, _} = fixtures.user!(%{})
        uid = user.id
        :ok = Auth.subscribe(uid)
        {:ok, _, one} = Auth.create_session(user)
        {:ok, kept_token, kept} = Auth.create_session(user)
        {:ok, gone_token, gone} = Auth.create_session(user)

        assert backend.revoke_sessions(one.id, []) == {uid, [one.id]}

        assert backend.revoke_sessions({:user, uid}, except: kept.id) == {uid, [gone.id]}
        assert {:ok, _, _} = Auth.fetch(kept_token)
        assert Auth.fetch(gone_token) == {:error, :invalid}

        assert {_, []} = backend.revoke_sessions({:user, uid}, except: kept.id)
        assert {_, []} = backend.revoke_sessions(gone.id, [])

        # The push is the facade's: the backend told no page.
        refute_received {:sessions_revoked, _}
      end
    end

    for {backend, fixtures} <- @backends do
      @tag backend: {backend, fixtures}
      @tag verifies: "complete-step-revoked"
      test "completing a step of a revoked session is invalid, and it stays gone: #{inspect(backend)}",
           %{backend: {_, fixtures}} do
        {user, _} = fixtures.user!(%{})
        {:ok, token, session} = Auth.create_session(user)
        :ok = Auth.revoke(session.id)

        assert Auth.complete_step(session.id, :password_change) == {:error, :invalid}
        assert Auth.fetch(token) == {:error, :invalid}
      end
    end

    for {backend, fixtures} <- @backends do
      @tag backend: {backend, fixtures}
      @tag verifies: "auth-backend-complete-step"
      test "a second-factor step marks the factor passed; a password change joins the completed steps: #{inspect(backend)}",
           %{backend: {_, fixtures}} do
        {user, _} = fixtures.user!(%{})

        for step <- [:second_factor, :second_factor_enroll] do
          {:ok, token, session} = Auth.create_session(user, second_factor_passed: false)
          assert Auth.complete_step(session.id, step) == :ok
          assert {:ok, _, %{second_factor_passed: true, completed_steps: []}} = Auth.fetch(token)
        end

        {:ok, token, session} = Auth.create_session(user)
        assert Auth.complete_step(session.id, :password_change) == :ok
        assert {:ok, _, %{completed_steps: [:password_change]}} = Auth.fetch(token)
      end
    end

    for {backend, fixtures} <- @backends do
      @tag backend: {backend, fixtures}
      @tag verifies: "auth-backend-verify"
      test "a valid code completes the step once; a wrong one and a spent one are refused: #{inspect(backend)}",
           %{backend: {_, fixtures}} do
        {user, creds} = fixtures.user!(%{})
        next_code = fixtures.enroll_second_factor!(user)
        {:ok, user} = Auth.authenticate(creds)
        {:ok, token, first} = Auth.create_session(user)
        {:ok, _, second} = Auth.create_session(user)
        code = next_code.()

        assert Auth.verify_second_factor(first.id, "not a code") == {:error, :invalid_code}
        assert Auth.verify_second_factor(first.id, code, remote_ip: "192.0.2.1") == :ok
        assert {:ok, user, session} = Auth.fetch(token)
        assert Auth.pending_step(user, session) == nil

        # Accepted once: the same code on another session is refused.
        assert Auth.verify_second_factor(second.id, code) == {:error, :invalid_code}

        # The session's own refusal, for a session that is gone.
        :ok = Auth.revoke(second.id)
        assert Auth.verify_second_factor(second.id, next_code.()) == {:error, :invalid}
      end
    end

    @tag backend: {Native, NativeFixtures}
    @tag verifies: "auth-backend-verify"
    test "the native backend throttles second-factor attempts as it does sign-ins" do
      {user, creds} = NativeFixtures.user!(%{})
      next_code = NativeFixtures.enroll_second_factor!(user)
      {:ok, user} = Auth.authenticate(creds)
      {:ok, _, session} = Auth.create_session(user)

      for _ <- 1..5, do: Auth.verify_second_factor(session.id, "000000")
      assert Auth.verify_second_factor(session.id, next_code.()) == {:error, :throttled}
    end

    @tag verifies: "backend-idle-seconds"
    test "session_idle_seconds/0: the native backend's days in seconds, the memory backend's 3 600, each its fixtures'" do
      Application.put_env(:macaw_auth, :backend, Native)
      :ok = NativeFixtures.reset!()
      assert Auth.session_idle_seconds() == 14 * 86_400
      assert Auth.session_idle_seconds() == NativeFixtures.idle_seconds()

      {:ok, config} = Config.parse(repo: Repo, session_idle_days: 1)
      Config.put(config)
      assert Auth.session_idle_seconds() == 86_400
      assert Auth.session_idle_seconds() == NativeFixtures.idle_seconds()

      Application.put_env(:macaw_auth, :backend, Mem)
      assert Auth.session_idle_seconds() == 3_600
      assert Auth.session_idle_seconds() == Mem.idle_seconds()
    end

    for {backend, fixtures} <- @backends do
      @tag backend: {backend, fixtures}
      @tag verifies: "auth-backend-idle"
      test "a session unused longer than the idle limit is expired, one unused exactly that long is not: #{inspect(backend)}",
           %{backend: {_, fixtures}} do
        idle = Auth.session_idle_seconds()
        assert is_integer(idle) and idle > 0

        {user, _} = fixtures.user!(%{})
        t0 = ~U[2026-10-01 12:00:00.000000Z]
        {:ok, token, _} = Auth.create_session(user, now: t0)

        assert {:ok, _, _} = Auth.fetch(token, now: DateTime.add(t0, idle))
        assert Auth.fetch(token, now: DateTime.add(t0, idle + 1)) == {:error, :expired}
      end
    end
  end

  describe "steps" do
    @tag verifies: "pending-step-order"
    test "the second factor before a password change, one step at a time" do
      user = user(%{second_factor: :enrolled, must_change_password: true})

      assert Auth.pending_step(user, session(%{second_factor_passed: false})) == :second_factor
      assert Auth.pending_step(user, session(%{second_factor_passed: true})) == :password_change

      assert Auth.pending_step(
               user,
               session(%{second_factor_passed: true, completed_steps: [:password_change]})
             ) == nil
    end

    @tag verifies: "pending-step-required"
    test "a required second factor is owed as enrollment until passed; none, nothing" do
      required = user(%{second_factor: :required})

      assert Auth.pending_step(required, session(%{second_factor_passed: false})) ==
               :second_factor_enroll

      assert Auth.pending_step(required, session(%{second_factor_passed: true})) == nil

      assert Auth.pending_step(
               user(%{second_factor: :none}),
               session(%{second_factor_passed: false})
             ) == nil
    end

    @tag verifies: "allowed-paths"
    test "while a step is owed, only its page and sign-out" do
      assert Auth.allowed_paths(:second_factor) == [
               Auth.path(:second_factor),
               Auth.path(:sign_out)
             ]
    end

    @tag verifies: "auth-steps"
    test "steps/0 in order; each step's page and sign-out; enrollment comes before a password change" do
      assert Auth.steps() == [:second_factor, :second_factor_enroll, :password_change]

      for step <- Auth.steps(),
          do: assert(Auth.allowed_paths(step) == [Auth.path(step), Auth.path(:sign_out)])

      user = user(%{second_factor: :required, must_change_password: true})

      assert Auth.pending_step(user, session(%{second_factor_passed: false})) ==
               :second_factor_enroll

      assert Auth.pending_step(user, session(%{second_factor_passed: true})) == :password_change
      assert Auth.pending_step(user(%{must_change_password: true}), session()) == :password_change
      assert Auth.pending_step(user(), session()) == nil
    end
  end

  describe "starting a session" do
    @tag verifies: "create-session-owes"
    test "an enrolled user's session owes the second factor; none owes nothing; an explicit option wins" do
      {enrolled, _} = Mem.user!(%{second_factor: :enrolled})
      {:ok, _, session} = Auth.create_session(enrolled)
      assert Auth.pending_step(enrolled, session) == :second_factor

      {plain, _} = Mem.user!(%{})
      {:ok, _, session} = Auth.create_session(plain)
      assert Auth.pending_step(plain, session) == nil

      {:ok, _, session} = Auth.create_session(enrolled, second_factor_passed: true)
      assert Auth.pending_step(enrolled, session) == nil
    end

    @tag verifies: "auth-create-session"
    test "second_factor_passed is the option when given, else true only for :none" do
      Application.put_env(:macaw_auth, :backend, Recorder)

      for {factor, passed} <- [none: true, enrolled: false, required: false] do
        Auth.create_session(user(%{second_factor: factor}))
        assert_received {:backend, {:create_session, _, opts}}
        assert Keyword.fetch!(opts, :second_factor_passed) == passed
      end

      Auth.create_session(user(%{second_factor: :none}), second_factor_passed: false)
      assert_received {:backend, {:create_session, _, opts}}
      assert Keyword.fetch!(opts, :second_factor_passed) == false
    end
  end

  describe "revocation" do
    @tag verifies: "auth-revocation"
    test "the user's topic, in the Registry or on the PubSub; expiry announces nothing" do
      # Without :pubsub, this node: registered under the user's topic.
      :ok = Auth.subscribe("topic-user")

      assert [{pid, nil}] =
               Registry.lookup(Macaw.Auth.Registry, "macaw_auth:user_sessions:topic-user")

      assert pid == self()

      # With :pubsub, the host's PubSub, on the same topic.
      start_supervised!({Phoenix.PubSub, name: Macaw.Auth.ContractTest.PubSub})
      Application.put_env(:macaw_auth, :pubsub, Macaw.Auth.ContractTest.PubSub)
      :ok = Auth.subscribe("pubsub-user")

      Phoenix.PubSub.broadcast(
        Macaw.Auth.ContractTest.PubSub,
        "macaw_auth:user_sessions:pubsub-user",
        :on_the_topic
      )

      assert_receive :on_the_topic
      :ok = Auth.announce_revoked("pubsub-user", [:a])
      assert_receive {:sessions_revoked, [:a]}

      # A session ended by expiry, or by its user's disabling, tells nobody.
      {user, _} = Mem.user!(%{})
      :ok = Auth.subscribe(user.id)
      t0 = ~U[2026-10-01 12:00:00Z]
      {:ok, token, _} = Auth.create_session(user, now: t0)

      assert Auth.fetch(token, now: DateTime.add(t0, 2 * Mem.idle_seconds())) ==
               {:error, :expired}

      {:ok, token, _} = Auth.create_session(user)
      :ok = Mem.disable!(user)
      assert {:error, _} = Auth.fetch(token)
      refute_receive {:sessions_revoked, _}
    end
  end

  describe "the structs" do
    @tag verifies: "structs-enforce"
    test "the required keys are enforced, and every other field has its default" do
      assert_raise ArgumentError, fn -> struct!(User, %{username: "a"}) end
      assert_raise ArgumentError, fn -> struct!(Session, %{id: 1}) end

      assert struct!(User, %{id: 1, username: "a"}) == %User{
               id: 1,
               username: "a",
               display_name: nil,
               source: nil,
               roles: [],
               disabled: false,
               second_factor: :none,
               must_change_password: false,
               extra: %{}
             }

      assert struct!(Session, %{id: 1, user_id: 2}) == %Session{
               id: 1,
               user_id: 2,
               created_at: nil,
               last_used_at: nil,
               remote_ip: nil,
               user_agent: nil,
               second_factor_passed: true,
               completed_steps: []
             }
    end

    @tag verifies: "auth-user"
    test "the user's fields are the table's, and every backend reports its users as one" do
      assert User.__struct__() |> Map.keys() |> Enum.sort() ==
               Enum.sort([
                 :__struct__,
                 :id,
                 :username,
                 :display_name,
                 :source,
                 :roles,
                 :disabled,
                 :second_factor,
                 :must_change_password,
                 :extra
               ])

      for {backend, fixtures} <- @backends do
        Application.put_env(:macaw_auth, :backend, backend)
        :ok = fixtures.reset!()
        {user, creds} = fixtures.user!(%{roles: ["admin"]})
        assert {:ok, %User{} = signed_in} = Auth.authenticate(creds)
        assert signed_in.id == user.id
        assert signed_in.roles == ["admin"]
        assert Enum.all?(signed_in.roles, &is_binary/1)
        assert signed_in.source == "local"
        assert signed_in.second_factor == :none
      end
    end

    @tag verifies: "auth-session"
    test "the session's fields are the table's; it carries its id, never the token" do
      assert Session.__struct__() |> Map.keys() |> Enum.sort() ==
               Enum.sort([
                 :__struct__,
                 :id,
                 :user_id,
                 :created_at,
                 :last_used_at,
                 :remote_ip,
                 :user_agent,
                 :second_factor_passed,
                 :completed_steps
               ])

      for {backend, fixtures} <- @backends do
        Application.put_env(:macaw_auth, :backend, backend)
        :ok = fixtures.reset!()
        {user, _} = fixtures.user!(%{})
        {:ok, token, %Session{} = session} = Auth.create_session(user)
        refute token in Map.values(session)
        assert %DateTime{} = session.created_at
        assert %DateTime{} = session.last_used_at
        assert {:ok, _, %Session{id: id}} = Auth.fetch_by_id(session.id)
        assert id == session.id
      end
    end
  end

  describe "the viewer" do
    @tag verifies: "auth-viewer"
    test "from a conn, a socket or assigns: identity and roles only, nil when signed out" do
      user =
        user(%{
          roles: ["admin"],
          source: "local",
          display_name: "Ada",
          extra: %{theme: "dark"}
        })

      viewer = %{id: 1, username: "u", roles: ["admin"], source: "local"}

      assert Auth.viewer(%{current_user: user}) == viewer
      assert Auth.viewer(%{assigns: %{current_user: user, current_session: session()}}) == viewer
      assert Auth.viewer(%Phoenix.LiveView.Socket{assigns: %{current_user: user}}) == viewer

      assert Auth.viewer(%{current_user: nil}) == nil
      assert Auth.viewer(%{assigns: %{}}) == nil
    end
  end

  describe "authorization" do
    setup do
      on_exit(fn -> Application.delete_env(:macaw_auth, :authorizer) end)
      :ok
    end

    @tag verifies: "auth-authorize"
    test "read at each call; the action must be an atom and the user a User" do
      {admin, _} = Mem.user!(%{roles: ["admin"]})

      Application.delete_env(:macaw_auth, :authorizer)
      refute Auth.authorize(admin, :manage, nil)
      Application.put_env(:macaw_auth, :authorizer, Macaw.Auth.Test.Authorizer)
      assert Auth.authorize(admin, :manage, nil)

      # Called through apply/3: the compiler would refuse these calls as written.
      for args <- [
            [admin, "manage", nil],
            [nil, :manage, nil],
            [%{id: admin.id, roles: ["admin"]}, :manage, nil]
          ],
          do: assert_raise(FunctionClauseError, fn -> apply(Auth, :authorize, args) end)
    end
  end
end
