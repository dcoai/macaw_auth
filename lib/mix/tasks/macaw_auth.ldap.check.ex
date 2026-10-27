defmodule Mix.Tasks.MacawAuth.Ldap.Check do
  @shortdoc "Checks an LDAP source by signing a user in, step by step"

  @moduledoc """
  Runs an LDAP source's sign-in flow for a user without signing them in,
  and prints how each step went (connect, TLS, finding the DN, bind,
  attributes, groups, required group, roles), stopping at the first that
  failed:

      MACAW_AUTH_CHECK_PASSWORD='…' mix macaw_auth.ldap.check nas alice

  The password comes from the `MACAW_AUTH_CHECK_PASSWORD` environment
  variable, never the command line, where `ps` and shell history would
  show it; it appears nowhere in the output. The source is one of
  `config :macaw_auth, Macaw.Auth.Native, sources: [...]`, by name. Exits
  non-zero when a step failed.
  """

  use Mix.Task

  alias Macaw.Auth.Native.Config
  alias Macaw.Auth.Native.Source.Ldap

  @password_var "MACAW_AUTH_CHECK_PASSWORD"

  @impl true
  def run([name, username]) do
    Mix.Task.run("app.config")
    {:ok, _} = Application.ensure_all_started([:ssl, :eldap])

    with {:ok, config} <- parsed(),
         {:ok, source} <- source(config, name),
         {:ok, password} <- password() do
      steps = Ldap.diagnose(source, username, password)

      for {step, status, detail} <- steps do
        Mix.shell().info("#{if status == :ok, do: "ok    ", else: "FAILED"} #{step}: #{detail}")
      end

      if Enum.any?(steps, &(elem(&1, 1) == :error)), do: exit({:shutdown, 1})
    else
      {:error, message} -> Mix.raise(message)
    end
  end

  def run(_argv), do: Mix.raise("usage: mix macaw_auth.ldap.check SOURCE USERNAME")

  defp parsed do
    case Config.parse(Application.get_env(:macaw_auth, Macaw.Auth.Native, [])) do
      {:ok, config} -> {:ok, config}
      {:error, message} -> {:error, "config :macaw_auth, Macaw.Auth.Native: " <> message}
    end
  end

  defp source(config, name) do
    ldap = for %Ldap{} = s <- config.sources, do: s

    case Enum.find(ldap, &(&1.name == name)) do
      %Ldap{} = source ->
        {:ok, source}

      nil ->
        {:error,
         "no LDAP source #{inspect(name)}; configured: #{Enum.map_join(ldap, ", ", & &1.name)}"}
    end
  end

  defp password do
    case System.get_env(@password_var) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, "set #{@password_var} to the user's password (it is never read from argv)"}
    end
  end
end
