defmodule Macaw.Auth.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    # The native backend's configuration is read at boot, so a fault in it
    # refuses to start, naming the key, rather than failing a sign-in.
    if Application.get_env(:macaw_auth, :backend) == Macaw.Auth.Native,
      do: Macaw.Auth.Native.Config.load!()

    # The local revocation channel, used when no `:pubsub` is configured.
    Supervisor.start_link([{Registry, keys: :duplicate, name: Macaw.Auth.Registry}],
      strategy: :one_for_one,
      name: Macaw.Auth.Supervisor
    )
  end
end
