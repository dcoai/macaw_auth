defmodule Macaw.Auth.DataCase do
  @moduledoc """
  Tests against the test repo, each in a sandboxed transaction, with the
  native backend configured from `sources` (default: a password source).
  Not async: the configuration is node-wide (`:persistent_term`).
  """

  use ExUnit.CaseTemplate

  alias Macaw.Auth.Native.Config
  alias Macaw.Auth.Test.Repo

  using do
    quote do
      import Macaw.Auth.DataCase
      alias Macaw.Auth.Test.Repo
    end
  end

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    previous = :persistent_term.get(Config, nil)
    configure!()

    on_exit(fn ->
      if previous,
        do: :persistent_term.put(Config, previous),
        else: :persistent_term.erase(Config)
    end)

    :ok
  end

  @doc "Configures the native backend with `settings` over the test repo."
  def configure!(settings \\ []) do
    {:ok, config} = Config.parse(Keyword.merge([repo: Repo], settings))
    Config.put(config)
  end

  @doc "A local user with `password`, made through the backend."
  def local_user!(username, password, attrs \\ %{}) do
    {:ok, record} =
      Macaw.Auth.Native.create_user(Map.merge(%{username: username, password: password}, attrs))

    record
  end
end
