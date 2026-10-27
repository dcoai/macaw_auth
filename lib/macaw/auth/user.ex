defmodule Macaw.Auth.User do
  @moduledoc """
  The signed-in user, as every backend reports it.

  - `id`: the backend's id, stable for the account's life.
  - `username`: what the person signs in with.
  - `display_name`: how the app shows them.
  - `roles`: the roles the app's authorization reads, as strings. The
    library only checks membership (`Macaw.Auth.Plug.require_role/2`); what
    a role allows is the app's.
  - `source`: where the identity came from (`"local"`, an LDAP source's
    name, an OAuth provider).
  - `disabled`: a disabled user has no live session.
  - `second_factor`: `:none`, `:enrolled`, or `:required` (policy demands
    one the user hasn't enrolled).
  - `must_change_password`: the next step is a password change.
  - `extra`: the backend's or app's own fields, untouched by the library.
  """

  @enforce_keys [:id, :username]
  defstruct [
    :id,
    :username,
    :display_name,
    :source,
    roles: [],
    disabled: false,
    second_factor: :none,
    must_change_password: false,
    extra: %{}
  ]

  @type t :: %__MODULE__{
          id: term(),
          username: String.t(),
          display_name: String.t() | nil,
          source: String.t() | nil,
          roles: [String.t()],
          disabled: boolean(),
          second_factor: :none | :enrolled | :required,
          must_change_password: boolean(),
          extra: map()
        }
end
