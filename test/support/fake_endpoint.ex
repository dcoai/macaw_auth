defmodule Macaw.Auth.Test.FakeEndpoint do
  @moduledoc """
  Stands in for a host's Phoenix endpoint where `config :macaw_auth,
  :endpoint` names one: `broadcast/3` sends `{:endpoint_broadcast, topic,
  event, payload}` to the process named by `listen/0`, so a test sees
  exactly what was broadcast.
  """

  @doc "Makes the calling process the one that hears broadcasts."
  def listen, do: :persistent_term.put(__MODULE__, self())

  @doc "As `Phoenix.Endpoint.broadcast/3`."
  def broadcast(topic, event, payload) do
    send(:persistent_term.get(__MODULE__), {:endpoint_broadcast, topic, event, payload})
    :ok
  end
end
