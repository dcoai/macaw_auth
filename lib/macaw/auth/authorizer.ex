defmodule Macaw.Auth.Authorizer do
  @moduledoc """
  What an app implements to decide what a user may do: one callback,
  `authorize/3`. It is the app's, not the backend's: a backend says who
  someone is, the app says what they may do. The app names its module:

      config :macaw_auth, authorizer: MyApp.Authorizer

  and asks through `Macaw.Auth.authorize/3`, the plug
  `Macaw.Auth.Plug.authorize/2` or the hook `{:authorize, action}` of
  `Macaw.Auth.Live`.

  **Closed by default:** with no authorizer configured, nothing is
  allowed. Roles stay the app's too; a plain membership check is
  `require_role`.

  The answer is `true` or `false`. Anything else, and anything the
  callback raises, is a fault in the app and crashes the request or page;
  nothing catches it.
  """

  alias Macaw.Auth.User

  @doc """
  Whether `user` may do `action` (an atom the app chooses) to `resource`
  (the app's own term, nil when the guard names none).
  """
  @callback authorize(user :: User.t(), action :: atom(), resource :: term()) :: boolean()
end
