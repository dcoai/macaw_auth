defmodule Macaw.Auth.Native.Source do
  @moduledoc """
  Where `Macaw.Auth.Native` checks a password: a behavior, and the chain
  that tries the configured sources in order.

  A source is a struct, made from its configuration by `parse/2` and
  dispatched on its module, so adding one is a module, not a case in the
  chain. Two ship: `Macaw.Auth.Native.Source.Password` (local users with a
  password hash) and `Macaw.Auth.Native.Source.Ldap` (a directory).

  **The chain** (ported from exio's `sign_in/3`). The sources are tried in
  their configured order, and **the first that knows the user decides**:
  its acceptance signs them in, and its refusal is final. A wrong password
  at a source that knows the user never falls through to the next, or one
  account's password could be guessed against another's. A source that
  doesn't know the user (`knows?/2` of its refusal is false: no such user,
  a directory it couldn't reach, a direct-bind directory that can't tell a
  wrong password from a missing user) passes the attempt on.

  **Who owns the row.** A source that keeps the user's row returns it as
  `:record` (`Password`). Any other returns what it knows about the user
  (`:username`, `:display_name`, `:roles`, `:extra`, and a directory's
  `:external_id`, the binary it identifies the entry by) and the chain
  provisions the row just in time (`Macaw.Auth.Native.Provision`).
  """

  alias Macaw.Auth.Native.{Provision, UserRecord}

  @type t :: struct()

  @typedoc """
  What a source says about a user it accepted: their row, or what the
  chain makes one from.
  """
  @type attrs ::
          %{record: UserRecord.t()}
          | %{
              required(:username) => String.t(),
              required(:display_name) => String.t() | nil,
              required(:roles) => [String.t()],
              required(:extra) => map(),
              optional(:external_id) => binary()
            }

  @doc """
  Makes the source's struct from its configuration (a map with atom or
  string keys): `{:ok, source}`, or `{:error, "sources[<name>].<key>: …"}`
  naming what is wrong. `context` carries `:repo` and `:hasher`, and
  `:env` (the environment, for `{:env, VAR}` secrets).
  """
  @callback parse(config :: map(), context :: keyword()) :: {:ok, t()} | {:error, String.t()}

  @doc "Checks a password: what the source knows about the user, or why not."
  @callback authenticate(t(), username :: String.t(), password :: String.t(), opts :: keyword()) ::
              {:ok, attrs()} | {:error, atom()}

  @doc """
  Whether a refusal with `reason` means the source knows the user, and so
  decides; false passes the attempt to the next source.
  """
  @callback knows?(t(), reason :: atom()) :: boolean()

  @doc "A sentence explaining a refusal's reason, for logs and diagnostics."
  @callback explain(reason :: atom()) :: String.t()

  @doc """
  Runs the chain: `{:ok, record, source}` for the user signed in, or
  `{:error, reason, source}` with the deciding source's reason (or the last
  source's, when none knew the user; `source` is nil with no sources).
  """
  @spec run([t()], module(), String.t(), String.t(), keyword()) ::
          {:ok, UserRecord.t(), t()} | {:error, atom(), t() | nil}
  def run(sources, repo, username, password, opts) do
    Enum.reduce_while(sources, {:error, :invalid_credentials, nil}, fn source, _last ->
      module = source.__struct__

      case module.authenticate(source, username, password, opts) do
        {:ok, %{record: %UserRecord{} = record}} ->
          {:halt, {:ok, record, source}}

        {:ok, attrs} ->
          case Provision.directory_user(repo, source.name, attrs) do
            {:ok, record} -> {:halt, {:ok, record, source}}
            {:error, reason} -> {:halt, {:error, reason, source}}
          end

        {:error, reason} ->
          if module.knows?(source, reason),
            do: {:halt, {:error, reason, source}},
            else: {:cont, {:error, reason, source}}
      end
    end)
  end
end
