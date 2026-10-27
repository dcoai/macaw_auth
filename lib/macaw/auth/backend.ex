defmodule Macaw.Auth.Backend do
  @moduledoc """
  What a backend implements: who someone is, and their sessions. Nothing
  else. The plugs, hooks, steps, paths and the revocation push are
  `Macaw.Auth`'s, the same for every backend, so a backend never
  reimplements them.

  Every function takes `opts`; `:now` (a `DateTime`) overrides the clock,
  so expiry is testable. A backend never raises for an ordinary refusal: it
  returns an error value. It must:

  - store no more than a hash of a session token;
  - spend the same time refusing an unknown user as a wrong password;
  - refuse a disabled user's sessions, and expire idle ones.

  The conformance kit (`Macaw.Auth.Conformance`) checks these.
  """

  alias Macaw.Auth.{Session, User}

  @type opts :: keyword()
  @type credentials :: %{optional(atom()) => term()}
  @type refusal :: :invalid_credentials | :disabled | :throttled | {:unavailable, String.t()}

  @doc """
  Checks credentials (`%{username: _, password: _}` at least). `context`
  carries `:remote_ip`, for throttling by address.
  """
  @callback authenticate(credentials(), opts()) :: {:ok, User.t()} | {:error, refusal()}

  @doc """
  Starts a session for a user who passed `authenticate/2`; returns the
  token for the client. Options: `:remote_ip`, `:user_agent`,
  `:second_factor_passed`.
  """
  @callback create_session(User.t(), opts()) :: {:ok, binary(), Session.t()}

  @doc """
  Resolves a token. `touch: true` (a request) may record use, no more than
  the backend's interval; `touch: false` (a re-check) never extends a
  session.
  """
  @callback fetch_session(binary(), opts()) ::
              {:ok, User.t(), Session.t()} | {:error, :invalid | :expired | :disabled}

  @doc "As `fetch_session/2`, by session id: what an open page re-checks with."
  @callback fetch_session_by_id(term(), opts()) ::
              {:ok, User.t(), Session.t()} | {:error, :invalid | :expired | :disabled}

  @doc "A user's sessions, newest first."
  @callback list_sessions(term(), opts()) :: [Session.t()]

  @doc """
  Revokes sessions: one id, or every session of a user (`{:user, id}`),
  with `:except` keeping one. Returns `{user_id, revoked_ids}`, the ids
  empty when there was nothing to revoke.
  """
  @callback revoke_sessions(term() | {:user, term()}, opts()) :: {term(), [term()]}

  @doc "Records that a session has completed a step (`:second_factor`, `:password_change`)."
  @callback complete_step(term(), Macaw.Auth.step(), opts()) :: :ok

  @doc """
  Checks a second-factor code for the user of a session (a TOTP code or a
  recovery code); on success completes the session's `:second_factor`
  step. A code is accepted once: the same code again is refused. A
  backend throttles these attempts as it does sign-ins. `:ok`, or
  `{:error, :invalid_code | :throttled}`, or the session's own refusal.
  Options: `:remote_ip`, `:now`.
  """
  @callback verify_second_factor(term(), term(), opts()) ::
              :ok | {:error, :invalid_code | :throttled | :invalid | :expired | :disabled}
end
