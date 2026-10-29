defmodule Macaw.Auth.Test.MigrationRepo do
  @moduledoc """
  A second host repo, for a test that migrates a database of its own step
  by step (a host on an earlier release): started with its own SQLite file
  (`database:`), never sandboxed.
  """
  use Ecto.Repo, otp_app: :macaw_auth, adapter: Ecto.Adapters.SQLite3
end
