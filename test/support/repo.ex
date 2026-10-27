defmodule Macaw.Auth.Test.Repo do
  @moduledoc "The test suite's host repo: SQLite, standing in for a host's."
  use Ecto.Repo, otp_app: :macaw_auth, adapter: Ecto.Adapters.SQLite3
end
