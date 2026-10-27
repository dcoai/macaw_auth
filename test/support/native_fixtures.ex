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
  alias Macaw.Auth.Native.{Config, Throttle, UserRecord}
  alias Macaw.Auth.Test.Repo

  @impl true
  def reset! do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    previous = :persistent_term.get(Config, nil)

    ExUnit.Callbacks.on_exit(fn ->
      if previous,
        do: :persistent_term.put(Config, previous),
        else: :persistent_term.erase(Config)
    end)

    {:ok, config} = Config.parse(repo: Repo)
    Config.put(config)
    Throttle.reset()
  end

  @impl true
  def user!(attrs) do
    n = System.unique_integer([:positive])
    password = "correct horse #{n}"

    {:ok, record} =
      Native.create_user(%{
        username: Map.get(attrs, :username, "user#{n}"),
        password: password,
        roles: Map.get(attrs, :roles, ["viewer"]),
        must_change_password: Map.get(attrs, :must_change_password, false)
      })

    {Native.to_user(record), %{username: record.username, password: password}}
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
  def idle_seconds, do: Config.get().session_idle_days * 86_400

  @impl true
  def stored_session_values do
    Repo.query!("SELECT * FROM macaw_auth_sessions").rows
    |> List.flatten()
    |> Enum.filter(&is_binary/1)
  end
end
