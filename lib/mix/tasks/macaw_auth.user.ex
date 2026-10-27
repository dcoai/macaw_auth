defmodule Mix.Tasks.MacawAuth.User do
  @shortdoc "Lists and administers the native backend's users"

  @moduledoc """
  Administers the native backend's users, against the configured repo:

      mix macaw_auth.user list
      MACAW_AUTH_USER_PASSWORD='…' mix macaw_auth.user add NAME --role R [--role R…]
      mix macaw_auth.user disable NAME
      mix macaw_auth.user enable NAME
      MACAW_AUTH_USER_PASSWORD='…' mix macaw_auth.user password NAME
      mix macaw_auth.user roles NAME R…
      mix macaw_auth.user reset-second-factor NAME

  The output is one JSON object per line on stdout, as the release entry
  points' (`Macaw.Auth.Native.Release`) is. An error is one JSON object,
  `{"ok": false, "error": "…"}`, on stderr, and the task exits with status 1.

  **The password comes from the `MACAW_AUTH_USER_PASSWORD` environment
  variable, never the command line,** where `ps` and shell history would
  show it; a `--password` or `-p` among the arguments is refused. It
  appears nowhere in the output.

  `password` and `reset-second-factor` revoke the user's sessions; this
  task runs apart from the app, so their open pages leave at their next
  re-check rather than at once. The commands are
  `Macaw.Auth.Native.UserCommands`.
  """

  use Mix.Task

  alias Macaw.Auth.Native.UserCommands

  @password_var "MACAW_AUTH_USER_PASSWORD"

  @impl true
  def run(argv) do
    Mix.Task.run("app.config")
    opts = [password_var: @password_var, announce: false]

    case UserCommands.run(argv, System.get_env(@password_var), opts) do
      {:ok, objects} ->
        Enum.each(objects, &Mix.shell().info(JSON.encode!(&1)))

      {:error, message} ->
        Mix.shell().error(JSON.encode!(%{ok: false, error: message}))
        exit({:shutdown, 1})
    end
  end
end
