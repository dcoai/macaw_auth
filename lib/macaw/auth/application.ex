defmodule Macaw.Auth.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    # The local revocation channel, used when no `:pubsub` is configured.
    Supervisor.start_link([{Registry, keys: :duplicate, name: Macaw.Auth.Registry}],
      strategy: :one_for_one,
      name: Macaw.Auth.Supervisor
    )
  end
end
