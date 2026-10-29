defmodule Macaw.Auth.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    # The host's public URL, when declared, is read first, so a value that
    # is not an http or https URL refuses to start, named.
    _scheme = Macaw.Auth.Plug.public_scheme()

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
      # The sweep of the native backend's sign-in failure counts (rows in its
      # repo), started whichever backend is configured, so it runs the
      # moment one is; with none, it sweeps nothing.
      Macaw.Auth.Native.Throttle
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Macaw.Auth.Supervisor)
  end
end
