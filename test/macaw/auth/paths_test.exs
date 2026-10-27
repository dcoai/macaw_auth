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

  test "a path neither configured nor known raises ArgumentError naming it" do
    Application.put_env(:macaw_auth, :paths, %{reports: "/reports"})
    assert Auth.path(:reports) == "/reports"

    error = assert_raise ArgumentError, fn -> Auth.path(:no_such_path) end
    assert error.message =~ ":no_such_path"
  end
end
