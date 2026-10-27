defmodule Macaw.Auth.Test.FaultyBackend do
  @moduledoc """
  Stands in for a backend whose configuration has a fault: its
  `check_config!/0` raises, naming it, as a real backend's would. Nothing
  gets past that check, so it implements nothing else.
  """

  def check_config!,
    do: raise(ArgumentError, "config :macaw_auth, FaultyBackend: idle: must be positive, got 0")
end
