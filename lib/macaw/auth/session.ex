defmodule Macaw.Auth.Session do
  @moduledoc """
  One signed-in session, as every backend reports it.

  The client holds only the session's token; the backend stores no more
  than a hash of it. An open LiveView holds the session's `id`, never its
  token, and re-checks it by id.

  `second_factor_passed` is false between a password and a second factor;
  `completed_steps` lists the steps the session has finished
  (`Macaw.Auth.pending_step/2`).
  """

  @enforce_keys [:id, :user_id]
  defstruct [
    :id,
    :user_id,
    :created_at,
    :last_used_at,
    :remote_ip,
    :user_agent,
    second_factor_passed: true,
    completed_steps: []
  ]

  @type t :: %__MODULE__{
          id: term(),
          user_id: term(),
          created_at: DateTime.t() | nil,
          last_used_at: DateTime.t() | nil,
          remote_ip: String.t() | nil,
          user_agent: String.t() | nil,
          second_factor_passed: boolean(),
          completed_steps: [Macaw.Auth.step()]
        }
end
