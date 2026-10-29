defmodule Macaw.Auth.Native.TicketTest do
  use Macaw.Auth.DataCase, async: false

  alias Macaw.Auth
  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Seal, SessionRecord, Throttle, Ticket, Totp, UserRecord}

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

    configure!(sealing_key: @key, totp_issuer: "Test App", totp_required: ["admin"])
    :ok
  end

  defp at(seconds), do: DateTime.add(@t0, seconds, :second)

  # An account that owes enrollment at sign-in (policy requires it of admins).
  defp owing! do
    n = System.unique_integer([:positive])
    "user#{n}" |> local_user!("correct horse #{n}", %{roles: ["admin"]}) |> Native.to_user()
  end

  defp ticket!(user, at \\ @t0) do
    {:ok, ticket} = Native.enrollment_ticket(user, now: at)
    {:ok, %{secret: secret}} = Native.enrollment(ticket, now: at)
    {ticket, secret}
  end

  defp row(user), do: Repo.get!(UserRecord, user.id)

  defp flip(ticket) do
    size = byte_size(ticket) - 1
    <<head::binary-size(^size), last>> = ticket
    <<head::binary, Bitwise.bxor(last, 1)>>
  end

  describe "the ticket" do
    @tag verifies: "ticket-term"
    test "its internal form is a term, sealed at the edge: only its sealed bytes leave" do
      user = owing!()
      {:ok, ticket} = Native.enrollment_ticket(user, now: @t0)
      assert is_binary(ticket)

      {:ok, plain} = Seal.unseal(ticket, Seal.key!(@key), "macaw_auth enrollment_ticket")

      assert %{account_id: id, purpose: :owed, issued_at: issued, secret: sealed} =
               :erlang.binary_to_term(plain)

      assert map_size(:erlang.binary_to_term(plain)) == 4
      assert {id, issued} == {user.id, DateTime.to_unix(@t0)}

      # The pending secret inside is sealed as at rest, bound to the account.
      {:ok, %{secret: secret}} = Native.enrollment(ticket, now: @t0)

      assert Seal.unseal(sealed, Seal.key!(@key), "macaw_auth totp_secret " <> id) ==
               {:ok, secret}

      # The ticket's bytes don't hold the secret in any form.
      for form <- [secret, Base.encode32(secret, padding: false), Base.encode64(secret)],
          do: assert(:binary.match(ticket, form) == :nomatch)
    end

    @tag verifies: "ticket-ttl"
    test "ten minutes, a constant: accepted a second before, refused at, by the injected clock" do
      assert Ticket.ttl_seconds() == 600

      user = owing!()
      {ticket, secret} = ticket!(user)
      assert {:ok, %{secret: ^secret}} = Native.enrollment(ticket, now: at(599))
      assert Native.enrollment(ticket, now: at(600)) == {:error, :invalid_ticket}

      assert Native.enroll_second_factor(ticket, Totp.code(secret, at(600)), now: at(600)) ==
               {:error, :invalid_ticket}

      assert {:ok, _user, _codes} =
               Native.enroll_second_factor(ticket, Totp.code(secret, at(599)), now: at(599))
    end

    @tag verifies: "ticket-tampered"
    test "tampered, under another key, or another sealed value: refused" do
      user = owing!()
      {ticket, secret} = ticket!(user)
      code = Totp.code(secret, @t0)

      # A term with every field right, sealed under the right key but not
      # as a ticket (another purpose's associated data).
      {:ok, plain} = Seal.unseal(ticket, Seal.key!(@key), "macaw_auth enrollment_ticket")
      not_a_ticket = Seal.seal(plain, Seal.key!(@key), "macaw_auth totp_secret " <> user.id)

      other_key =
        Seal.seal(plain, Seal.key!(:crypto.strong_rand_bytes(32)), "macaw_auth enrollment_ticket")

      for refused <- [
            flip(ticket),
            not_a_ticket,
            other_key,
            binary_part(ticket, 0, 20),
            "",
            nil,
            42
          ] do
        assert Native.enrollment(refused, now: @t0) == {:error, :invalid_ticket}
        assert Native.enroll_second_factor(refused, code, now: @t0) == {:error, :invalid_ticket}
      end

      assert row(user).totp_enabled_at == nil
    end

    @tag verifies: "ticket-purpose"
    test "each confirmation takes its own purpose's ticket only" do
      owed = owing!()
      {owed_ticket, owed_secret} = ticket!(owed)

      chosen =
        "chooser#{System.unique_integer([:positive])}"
        |> local_user!("correct horse")
        |> Native.to_user()

      {:ok, %{ticket: chosen_ticket, secret: chosen_secret}} =
        Native.enroll_begin(chosen, now: @t0)

      # Owed at sign-in, presented as a choice; chosen, presented at sign-in.
      assert Native.enroll_confirm(owed, owed_ticket, Totp.code(owed_secret, @t0), now: @t0) ==
               {:error, :invalid_ticket}

      assert Native.enroll_second_factor(chosen_ticket, Totp.code(chosen_secret, @t0), now: @t0) ==
               {:error, :invalid_ticket}

      # A page shows either.
      assert {:ok, %{secret: ^chosen_secret}} = Native.enrollment(chosen_ticket, now: @t0)
      assert {:ok, %{secret: ^owed_secret}} = Native.enrollment(owed_ticket, now: @t0)

      assert row(owed).totp_enabled_at == nil
      assert row(chosen).totp_enabled_at == nil
    end

    @tag verifies: "ticket-from-alone"
    test "enrollment owed at sign-in completes from the ticket alone, with no session before it" do
      user = owing!()
      assert Auth.create_session(user) == {:error, :enrollment_required}
      {ticket, secret} = ticket!(user)
      assert Repo.aggregate(SessionRecord, :count) == 0

      assert {:ok, %Auth.User{second_factor: :enrolled} = enrolled, codes} =
               Native.enroll_second_factor(ticket, Totp.code(secret, @t0), now: @t0)

      assert enrolled.id == user.id
      assert length(codes) == 10
      assert Native.recovery_codes_left(user) == 10
      assert Repo.aggregate(SessionRecord, :count) == 0

      # The confirming code is spent: it can't then pass a session's step.
      {:ok, _token, session} = Native.create_session(enrolled, now: @t0)

      assert Native.verify_second_factor(session.id, Totp.code(secret, @t0), now: @t0) ==
               {:error, :invalid_code}
    end

    @tag verifies: "ticket-spent"
    test "a ticket is spent by the enrollment it completes" do
      user = owing!()
      {ticket, secret} = ticket!(user)
      {:ok, _user, _codes} = Native.enroll_second_factor(ticket, Totp.code(secret, @t0), now: @t0)

      assert Native.enrollment(ticket, now: at(30)) == {:error, :invalid_ticket}

      assert Native.enroll_second_factor(ticket, Totp.code(secret, at(30)), now: at(30)) ==
               {:error, :invalid_ticket}

      assert Native.enrollment_ticket(user, now: at(30)) == {:error, :invalid}
    end

    @tag verifies: "ticket-account"
    test "an account disabled, deleted or no longer required during the ticket's lifetime: refused" do
      disabled = owing!()
      {ticket, secret} = ticket!(disabled)
      {:ok, _} = Native.disable_user(disabled.username)
      assert Native.enrollment(ticket, now: @t0) == {:error, :invalid_ticket}

      assert Native.enroll_second_factor(ticket, Totp.code(secret, @t0), now: @t0) ==
               {:error, :invalid_ticket}

      assert Native.enrollment_ticket(disabled, now: @t0) == {:error, :invalid}

      deleted = owing!()
      {ticket, secret} = ticket!(deleted)
      {:ok, _} = Native.delete_user(deleted.username, announce: false)

      assert Native.enroll_second_factor(ticket, Totp.code(secret, @t0), now: @t0) ==
               {:error, :invalid_ticket}

      # A role change: policy no longer requires it, so the ticket owed at
      # sign-in is owed no more; signing in again gives a session.
      moved = owing!()
      {ticket, secret} = ticket!(moved)
      {:ok, _} = Native.set_roles(moved.username, ["viewer"])

      assert Native.enroll_second_factor(ticket, Totp.code(secret, @t0), now: @t0) ==
               {:error, :invalid_ticket}

      # And no ticket for a user who owes none.
      viewer =
        "viewer#{System.unique_integer([:positive])}"
        |> local_user!("correct horse")
        |> Native.to_user()

      assert Native.enrollment_ticket(viewer, now: @t0) == {:error, :invalid}

      assert Native.enrollment_ticket(%{viewer | id: Ecto.UUID.generate()}, now: @t0) ==
               {:error, :invalid}
    end

    @tag verifies: "ticket-throttle"
    test "second-factor failures at enrollment count on the account's second-factor key and the address" do
      user = owing!()
      {ticket, secret} = ticket!(user)
      opts = [now: @t0, remote_ip: "192.0.2.60"]

      # A refused ticket is not a code check: not counted.
      assert Native.enroll_second_factor(flip(ticket), "000001", opts) ==
               {:error, :invalid_ticket}

      assert Throttle.rows() == []

      for _ <- 1..5,
          do:
            assert(Native.enroll_second_factor(ticket, "000001", opts) == {:error, :invalid_code})

      ms = DateTime.to_unix(@t0, :millisecond)

      assert Enum.filter(Throttle.rows(), &(elem(&1, 0) == {:user, {:second_factor, user.id}})) ==
               [{{:user, {:second_factor, user.id}}, 5, ms}]

      assert [{_, 5, _}] = Enum.filter(Throttle.rows(), &(elem(&1, 0) == {:ip, "192.0.2.60"}))

      # The right code waits too, unchecked; after the wait it is checked
      # and resets the account's key.
      right = Totp.code(secret, @t0)
      assert Native.enroll_second_factor(ticket, right, opts) == {:error, :throttled}

      assert {:ok, _user, _codes} =
               Native.enroll_second_factor(ticket, right, now: at(1), remote_ip: "192.0.2.60")

      assert Enum.filter(Throttle.rows(), &(elem(&1, 0) == {:user, {:second_factor, user.id}})) ==
               []
    end
  end
end
