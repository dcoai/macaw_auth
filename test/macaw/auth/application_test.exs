defmodule Macaw.Auth.ApplicationTest.UnsureBackend do
  @moduledoc "Stands in for a backend whose check answers neither :ok nor a raise."
  def check_config!, do: :maybe
end

defmodule Macaw.Auth.ApplicationTest do
  # The library's dependencies and what its application starts (spec 00 §3),
  # and the backend's configuration checked at its start (spec 01 §2.9).
  use ExUnit.Case, async: false

  alias Macaw.Auth.ApplicationTest.UnsureBackend
  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Config, Throttle}
  alias Macaw.Auth.Test.{FaultyBackend, MemoryBackend, Repo}

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

    # The throttle's counts are the native backend's repo's rows.
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    kept = :persistent_term.get(Config, nil)
    on_exit(fn -> keep(kept) end)
    {:ok, config} = Config.parse(repo: Repo)
    Config.put(config)

    assert Throttle.check({:name, "application-children-user"}, "192.0.2.1", Throttle.now()) ==
             :ok
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
    assert deps.macaw_plug == {"~> 0.2.0"}
    assert deps.macaw_host == {"~> 0.3.0"}

    for dep <- [:bcrypt_elixir, :argon2_elixir],
        do: assert(elem(deps[dep], 1)[:optional] == true)

    for dep <- [:ecto_sqlite3, :stream_data], do: assert(elem(deps[dep], 1)[:only] == :test)

    for {dep, requirement} <- [extla: "~> 0.6.0", surfex: "~> 0.10.0"] do
      assert deps[dep] == {requirement, [only: [:dev, :test], runtime: false]}, inspect(dep)
    end

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

  describe "the backend's configuration, checked at start" do
    @tag verifies: "backend-check-config-boot"
    test "the configured backend's check_config!/0 decides whether :macaw_auth starts" do
      # A required callback of every backend.
      assert {:check_config!, 0} in Macaw.Auth.Backend.behaviour_info(:callbacks)
      refute {:check_config!, 0} in Macaw.Auth.Backend.behaviour_info(:optional_callbacks)

      # A fault refuses boot, with the backend's own error, naming it.
      assert {:error, {:macaw_auth, {:bad_return, {_, {:EXIT, {%ArgumentError{} = e, _}}}}}} =
               boot_with(backend: FaultyBackend)

      assert Exception.message(e) ==
               "config :macaw_auth, FaultyBackend: idle: must be positive, got 0"

      # An answer but :ok refuses it too: nothing is taken for a pass.
      assert {:error, {:macaw_auth, {:bad_return, {_, {:EXIT, {{:badmatch, :maybe}, _}}}}}} =
               boot_with(backend: UnsureBackend)

      # A backend whose configuration is sound starts, its processes with it.
      assert {:ok, _} = boot_with(backend: MemoryBackend)
      assert MemoryBackend.check_config!() == :ok

      # With no backend configured, no backend is asked, and it starts.
      assert {:ok, _} = boot_with(backend: nil)
    end

    @tag verifies: "native-check-config"
    test "the native backend's check is Config.load!/0: a fault refuses boot; a sound one starts, and the check keeps it" do
      assert {:error, {:macaw_auth, {:bad_return, {_, {:EXIT, {%Config.Error{} = e, _}}}}}} =
               boot_with([{:backend, Native}, {Native, repo: Repo, session_idle_days: 0}])

      assert e.message ==
               "config :macaw_auth, Macaw.Auth.Native: session_idle_days: must be an integer in 1..3650, got 0"

      assert {:ok, _} =
               boot_with([{:backend, Native}, {Native, repo: Repo, session_idle_days: 3}])

      # check_config!/0 is :ok, and keeps the configuration it read.
      kept = :persistent_term.get(Config, nil)
      on_exit(fn -> keep(kept) end)
      with_env(Native, repo: Repo, session_idle_days: 5)
      assert Native.check_config!() == :ok
      assert %Config{session_idle_days: 5} = Config.get()
    end
  end

  describe "the host's public URL, read at start" do
    @tag verifies: "plug-public-url-checked"
    test "one that is not an http or https URL refuses boot, named; a sound one starts" do
      assert {:error, {:macaw_auth, {:bad_return, {_, {:EXIT, {%ArgumentError{} = e, _}}}}}} =
               boot_with(public_url: "ftp://app.example.com")

      assert Exception.message(e) =~ "config :macaw_auth, public_url:"
      assert {:ok, _} = boot_with(public_url: "https://app.example.com")
      assert Application.get_env(:macaw_auth, :public_url) == nil
    end
  end

  # Stops :macaw_auth, starts it again with `env` (each key's value, nil to
  # delete it), and gives that start's answer. Before answering, it puts back
  # the environment and the native configuration kept in :persistent_term,
  # and starts :macaw_auth as it was, so nothing after it sees the change;
  # on_exit does the same if the test fails first.
  defp boot_with(env) do
    previous = for {key, _} <- env, do: {key, Application.get_env(:macaw_auth, key)}
    kept = :persistent_term.get(Config, nil)
    put_back = fn -> put_back(previous, kept) end
    on_exit(put_back)

    :ok = Application.stop(:macaw_auth)
    Enum.each(env, fn {key, value} -> restore(key, value) end)
    result = Application.ensure_all_started(:macaw_auth)
    put_back.()
    result
  end

  defp put_back(previous, kept) do
    if List.keymember?(Application.started_applications(), :macaw_auth, 0),
      do: :ok = Application.stop(:macaw_auth)

    Enum.each(previous, fn {key, value} -> restore(key, value) end)
    keep(kept)
    {:ok, _} = Application.ensure_all_started(:macaw_auth)
  end

  defp keep(nil), do: :persistent_term.erase(Config)
  defp keep(config), do: Config.put(config)

  defp with_env(key, value) do
    previous = Application.get_env(:macaw_auth, key)
    on_exit(fn -> restore(key, previous) end)
    Application.put_env(:macaw_auth, key, value)
  end

  defp restore(key, nil), do: Application.delete_env(:macaw_auth, key)
  defp restore(key, value), do: Application.put_env(:macaw_auth, key, value)
end
