defmodule Macaw.Auth.Native.Release do
  @moduledoc """
  The native backend's user commands as release entry points, for an
  app's `<app>-ctl` (macaw_host's generated script), on macaw_host's
  release protocol (`Macaw.Host.Release`):

  - **the arguments** arrive as a JSON array of strings in
    `<PREFIX>_CTL_ARGS`, **the password** in `<PREFIX>_CTL_PASSWORD`,
    never on a command line;
  - **the output** is one JSON object per line on stdout;
  - **a failure** is one line on stderr, `{"ok": false, "error": "…"}`,
    and exit status 1; malformed arguments fail as `Macaw.Host.Release`
    says (`"<PREFIX>_CTL_ARGS must be a JSON array of strings"`).

  `<PREFIX>` is the app's `:env_prefix` (macaw_host's ctl description):

      config :macaw_auth, Macaw.Auth.Native.Release, env_prefix: "MY_APP"

  There is no default: without it, the entry points fail naming the
  setting. `bootstrap/1` and `user/1` take the prefix instead, for an
  app's release module to delegate to.

  The app's `Ctl.AppCommands` runs them in a throwaway container of the
  image (`bin/<app> eval`, macaw_host's `Ctl.Docker.eval_args/3`), the
  password passed by name (`-e <PREFIX>_CTL_PASSWORD`), so they work with
  the app stopped:

      eval_args(env, "Macaw.Auth.Native.Release.user()",
        [{"MY_APP_CTL_ARGS", JSON.encode!(["add", name, "--role", "admin"])},
         {"MY_APP_CTL_PASSWORD", password}])

  That VM is not the app's node: a revocation (`password`,
  `reset-second-factor`, `delete`) deletes the sessions, and the user's open pages
  leave at their next re-check.
  """

  alias Macaw.Auth.Native.UserCommands
  alias Macaw.Host.Release, as: Protocol

  @doc """
  `bootstrap NAME --role R`: the first admin, made only when no user
  exists (`Macaw.Auth.Native.bootstrap_admin/1`), so it is safe to run at
  every deployment. The prefix from the configuration.
  """
  @spec bootstrap() :: :ok
  def bootstrap, do: bootstrap(prefix())

  @doc "`bootstrap/0` with the prefix given."
  @spec bootstrap(String.t()) :: :ok
  def bootstrap(prefix), do: run(prefix, &UserCommands.bootstrap/3)

  @doc """
  The user commands (`list`, `add NAME --role R…`, `disable NAME`,
  `enable NAME`, `delete NAME`, `password NAME`, `roles NAME R…`,
  `reset-second-factor NAME`), as `mix macaw_auth.user` runs them
  (`Macaw.Auth.Native.UserCommands`). The prefix from the configuration.
  """
  @spec user() :: :ok
  def user, do: user(prefix())

  @doc "`user/0` with the prefix given."
  @spec user(String.t()) :: :ok
  def user(prefix), do: run(prefix, &UserCommands.run/3)

  defp run(prefix, command) do
    args = Protocol.ctl_args!(prefix)
    opts = [password_var: prefix <> "_CTL_PASSWORD", announce: false]

    case command.(args, Protocol.ctl_password(prefix), opts) do
      {:ok, objects} -> Enum.each(objects, &Protocol.emit/1)
      {:error, message} -> fail(message)
    end
  end

  defp prefix do
    Application.load(:macaw_auth)

    case Application.get_env(:macaw_auth, __MODULE__, [])[:env_prefix] do
      prefix when is_binary(prefix) and prefix != "" -> prefix
      _ -> fail("config :macaw_auth, Macaw.Auth.Native.Release, env_prefix: is not set")
    end
  end

  defp fail(message), do: Protocol.fail(JSON.encode!(%{ok: false, error: message}))
end
