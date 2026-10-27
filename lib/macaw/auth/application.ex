defmodule Macaw.Auth.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    # The configured backend's configuration is checked at boot, so a fault
    # in it refuses to start, named, rather than failing a sign-in. With no
    # backend configured, none is asked (Macaw.Auth.backend/0 then raises at
    # each call).
    case Application.get_env(:macaw_auth, :backend) do
      nil -> :ok
      backend -> :ok = backend.check_config!()
    end

    children = [
      # The local revocation channel, used when no `:pubsub` is configured.
      {Registry, keys: :duplicate, name: Macaw.Auth.Registry},
      # The native backend's sign-in failure counts: one small ETS table,
      # started whichever backend is configured, so it is there the moment
      # one is.
      Macaw.Auth.Native.Throttle
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Macaw.Auth.Supervisor)
  end
end
