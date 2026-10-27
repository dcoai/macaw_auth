defmodule Macaw.Auth.PathsTest do
  use ExUnit.Case, async: false

  alias Macaw.Auth

  setup do
    previous = Application.get_env(:macaw_auth, :paths)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:macaw_auth, :paths, previous),
        else: Application.delete_env(:macaw_auth, :paths)
    end)

    :ok
  end

  @tag verifies: "paths-unknown"
  test "a path neither configured nor known raises ArgumentError naming it" do
    Application.put_env(:macaw_auth, :paths, %{reports: "/reports"})
    assert Auth.path(:reports) == "/reports"

    error = assert_raise ArgumentError, fn -> Auth.path(:no_such_path) end
    assert error.message =~ ":no_such_path"
  end

  @tag verifies: "paths-defaults"
  test "each name has its default; a configured map changes only what it names" do
    Application.delete_env(:macaw_auth, :paths)

    assert Map.new(
             [
               :sign_in,
               :sign_out,
               :home,
               :second_factor,
               :second_factor_enroll,
               :password_change
             ],
             &{&1, Auth.path(&1)}
           ) == %{
             sign_in: "/login",
             sign_out: "/logout",
             home: "/",
             second_factor: "/login/second-factor",
             second_factor_enroll: "/second-factor/enroll",
             password_change: "/password"
           }

    Application.put_env(:macaw_auth, :paths, %{home: "/home"})
    assert Auth.path(:home) == "/home"
    assert Auth.path(:sign_in) == "/login"
  end

  @tag verifies: "auth-paths"
  test "an unknown name's message names it, the setting and every known name" do
    Application.put_env(:macaw_auth, :paths, %{reports: "/reports"})
    error = assert_raise ArgumentError, fn -> Auth.path(:no_such_path) end

    assert error.message ==
             "unknown path :no_such_path: neither configured (config :macaw_auth, paths:) " <>
               "nor one of :home, :password_change, :second_factor, :second_factor_enroll, " <>
               ":sign_in, :sign_out"
  end
end
