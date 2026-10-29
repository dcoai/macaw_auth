defmodule Macaw.Auth.Test.NativeFixtures do
  @moduledoc """
  What the conformance kit needs of `Macaw.Auth.Native`, over the test
  repo: each test in its own sandboxed transaction, the backend configured
  with a password source and its default idle period, the throttle empty.

  `stored_session_values/0` is every value of every column of every
  session row, read with plain SQL rather than through the schema, so the
  kit's "no token stored as it is" sees what the database holds, not what
  the schema chooses to load.
  """

  @behaviour Macaw.Auth.Conformance.Fixtures

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Config, Throttle, Totp, UserRecord}
  alias Macaw.Auth.Test.Repo

  @required_role "second-factor-required"

  @doc "The sealing key the fixtures configure: random, per test run."
  def sealing_key do
    case :persistent_term.get({__MODULE__, :sealing_key}, nil) do
      nil ->
        key = :crypto.strong_rand_bytes(32)
        :persistent_term.put({__MODULE__, :sealing_key}, key)
        key

      key ->
        key
    end
  end

  @impl true
  def reset! do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    previous = :persistent_term.get(Config, nil)

    ExUnit.Callbacks.on_exit(fn ->
      if previous,
        do: :persistent_term.put(Config, previous),
        else: :persistent_term.erase(Config)
    end)

    {:ok, config} =
      Config.parse(repo: Repo, sealing_key: sealing_key(), totp_required: [@required_role])

    Config.put(config)
    Throttle.reset()
  end

  @impl true
  def user!(attrs) do
    n = System.unique_integer([:positive])
    password = "correct horse #{n}"
    factor = Map.get(attrs, :second_factor, :none)
    roles = Map.get(attrs, :roles, ["viewer"])

    {:ok, record} =
      Native.create_user(%{
        username: Map.get(attrs, :username, "user#{n}"),
        password: password,
        roles: if(factor == :required, do: [@required_role | roles], else: roles),
        must_change_password: Map.get(attrs, :must_change_password, false)
      })

    user = Native.to_user(record)
    if factor == :enrolled, do: enroll_second_factor!(user)

    {Native.to_user(Repo.get!(UserRecord, record.id)),
     %{username: record.username, password: password}}
  end

  @impl true
  def enroll_second_factor!(user) do
    {:ok, %{ticket: ticket, secret: secret}} = Native.enroll_begin(user)
    # The previous step's code (inside the ±1 window), so the current
    # step's is still unspent for the kit.
    previous = System.os_time(:second) - 30
    {:ok, _codes} = Native.enroll_confirm(user, ticket, Totp.code(secret, previous))
    fn -> Totp.code(secret, System.os_time(:second)) end
  end

  @impl true
  def disable!(user) do
    UserRecord
    |> Repo.get!(user.id)
    |> Ecto.Changeset.change(disabled_at: DateTime.utc_now())
    |> Repo.update!()

    :ok
  end

  @impl true
  def delete!(user) do
    Repo.delete!(Repo.get!(UserRecord, user.id))
    :ok
  end

  @impl true
  def idle_seconds, do: Config.get().session_idle_days * 86_400

  @impl true
  def stored_session_values do
    Repo.query!("SELECT * FROM macaw_auth_sessions").rows
    |> List.flatten()
    |> Enum.filter(&is_binary/1)
  end
end
