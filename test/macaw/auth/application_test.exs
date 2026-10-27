defmodule Macaw.Auth.ApplicationTest do
  # The library's dependencies and what its application starts (spec 00 §3).
  use ExUnit.Case, async: false

  alias Macaw.Auth.Native.{Config, Throttle}

  @tag verifies: "application-children"
  test "the application starts the Registry and the throttle's table; subscribing and checking then work" do
    children =
      for {id, pid, _, _} <- Supervisor.which_children(Macaw.Auth.Supervisor),
          is_pid(pid),
          do: id

    assert Enum.sort(children) == Enum.sort([Macaw.Auth.Registry, Throttle])
    assert is_pid(Process.whereis(Macaw.Auth.Registry))
    assert is_pid(Process.whereis(Throttle))

    assert Application.get_env(:macaw_auth, :pubsub) == nil
    assert Macaw.Auth.subscribe("application-children-user") == :ok
    assert Throttle.check("application-children-user", "192.0.2.1", Throttle.now()) == :ok
  end

  @tag verifies: "auth-dependencies"
  test "the dependencies and OTP applications are the spec's; a native configuration fault refuses boot" do
    deps = Map.new(Mix.Project.config()[:deps], &{elem(&1, 0), Tuple.delete_at(&1, 0)})

    for {dep, requirement} <- [
          phoenix: "~> 1.7",
          phoenix_live_view: "~> 1.0",
          phoenix_pubsub: "~> 2.1",
          bcrypt_elixir: "~> 3.2",
          argon2_elixir: "~> 4.1"
        ],
        do: assert(elem(deps[dep], 0) == requirement, inspect(dep))

    for dep <- [:plug, :telemetry, :ecto_sql, :nimble_totp], do: assert(Map.has_key?(deps, dep))
    assert elem(deps.macaw_plug, 0)[:tag] == "v0.1.0"
    assert elem(deps.macaw_host, 0)[:tag] == "v0.1.1"

    for dep <- [:bcrypt_elixir, :argon2_elixir],
        do: assert(elem(deps[dep], 1)[:optional] == true)

    for dep <- [:ecto_sqlite3, :stream_data], do: assert(elem(deps[dep], 1)[:only] == :test)

    assert Mix.Project.config()[:elixir] == "~> 1.18"

    assert Enum.sort(Application.spec(:macaw_auth, :applications) -- [:kernel, :stdlib, :elixir]) --
             Enum.map(Map.keys(deps), & &1) ==
             Enum.sort([:logger, :crypto, :eldap, :ssl, :public_key])

    # No LDAP library: :eldap, OTP's. And no module of the library calls macaw_plug.
    refute Map.has_key?(deps, :exldap) or Map.has_key?(deps, :paddle)

    for module <- Application.spec(:macaw_auth, :modules) do
      {:ok, {_, imports: calls}} = :beam_lib.chunks(:code.which(module), [:imports])
      called = for {callee, _, _} <- calls, uniq: true, do: inspect(callee)
      refute Enum.any?(called, &String.starts_with?(&1, "Macaw.Plug.")), inspect(module)
    end

    # With the native backend configured, its configuration is read at boot,
    # and a fault refuses to start.
    previous_backend = Application.get_env(:macaw_auth, :backend)
    previous_native = Application.get_env(:macaw_auth, Macaw.Auth.Native)
    previous_config = :persistent_term.get(Config, nil)

    on_exit(fn ->
      restore(:backend, previous_backend)
      restore(Macaw.Auth.Native, previous_native)
      if previous_config, do: Config.put(previous_config)
      {:ok, _} = Application.ensure_all_started(:macaw_auth)
    end)

    :ok = Application.stop(:macaw_auth)
    Application.put_env(:macaw_auth, :backend, Macaw.Auth.Native)

    Application.put_env(
      :macaw_auth,
      Macaw.Auth.Native,
      Keyword.put(previous_native, :session_idle_days, 0)
    )

    assert {:error,
            {:macaw_auth, {:bad_return, {_, {:EXIT, {%Config.Error{message: message}, _}}}}}} =
             Application.ensure_all_started(:macaw_auth)

    assert message =~ "session_idle_days"
  end

  defp restore(key, nil), do: Application.delete_env(:macaw_auth, key)
  defp restore(key, value), do: Application.put_env(:macaw_auth, key, value)
end
