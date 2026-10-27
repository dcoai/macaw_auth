defmodule Macaw.Auth.Backend do
  @moduledoc """
  What a backend implements: who someone is, and their sessions. Nothing
  else. The plugs, hooks, steps, paths and the revocation push are
  `Macaw.Auth`'s, the same for every backend, so a backend never
  reimplements them. And one check: `check_config!/0`, which the
  application calls at start, so a misconfigured backend refuses boot.

  Every function but `check_config!/0` takes `opts`; `:now` (a
  `DateTime`) overrides the clock, so expiry is testable. A backend never
  raises for an ordinary refusal: it returns an error value. Only
  `check_config!/0` raises, for a fault in its configuration. It must:

  - store no more than a hash of a session token;
  - spend the same time refusing an unknown user as a wrong password, and
    give both the same refusal;
  - refuse a disabled user's sessions, and expire idle ones.

  The conformance kit (`Macaw.Auth.Conformance`) checks what it can of
  these: no token stored as it is, the same refusal, disabled and idle
  sessions refused. It does not check timing; a backend's own suite does.
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
  token for the client, or `{:error, :invalid}` when the user no longer
  exists (deleted since signing in), never a session for them. Options:
  `:remote_ip`, `:user_agent`, `:second_factor_passed`.
  """
  @callback create_session(User.t(), opts()) ::
              {:ok, binary(), Session.t()} | {:error, :invalid}

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

  @doc """
  How long a session may go unused before it expires, in seconds: the
  idle limit `fetch_session/2` expires sessions by. The remember cookie
  lives this long (`Macaw.Auth.Plug.log_in/3`).
  """
  @callback session_idle_seconds(opts()) :: pos_integer()

  @doc "A user's sessions, newest first."
  @callback list_sessions(term(), opts()) :: [Session.t()]

  @doc """
  Revokes sessions: one id, or every session of a user (`{:user, id}`),
  with `:except` keeping one. Returns `{user_id, revoked_ids}`, the ids
  empty when there was nothing to revoke.
  """
  @callback revoke_sessions(term() | {:user, term()}, opts()) :: {term(), [term()]}

  @doc """
  Records that a session has completed a step (`:second_factor`,
  `:password_change`): `:ok`, or `{:error, :invalid}` when the session
  doesn't exist (revoked meanwhile), never a raise.
  """
  @callback complete_step(term(), Macaw.Auth.step(), opts()) :: :ok | {:error, :invalid}

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

  @doc """
  Checks the backend's whole configuration, as its first sign-in would
  read it: `:ok`, or a raise naming the fault (the setting, and what is
  wrong with it). `Macaw.Auth.Application` calls it at start for the
  configured backend, and matches its `:ok`, so a fault refuses boot
  rather than failing a sign-in.
  """
  @callback check_config!() :: :ok
end
