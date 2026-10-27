defmodule Macaw.Auth.Test.FakeDirectory do
  @moduledoc """
  A directory source for the chain's tests, without a directory: its
  `entries` map usernames to `%{password, display_name, groups}`, and
  `roles` maps groups to roles as an LDAP source's `role_mapping` does.
  `reachable: false` makes it fail as an unreachable directory. It tells
  the calling process each time it is asked.
  """

  @behaviour Macaw.Auth.Native.Source

  defstruct name: "dir", entries: %{}, roles: %{}, reachable: true

  @impl true
  def parse(config, _context), do: {:ok, struct!(__MODULE__, config)}

  @impl true
  def authenticate(source, username, password, _opts) do
    send(self(), {:asked, source.name})

    case {source.reachable, Map.get(source.entries, username)} do
      {false, _} ->
        {:error, :connect_failed}

      {true, nil} ->
        {:error, :user_not_found}

      {true, %{password: ^password} = entry} ->
        {:ok,
         %{
           username: username,
           display_name: entry[:display_name],
           roles: entry |> Map.get(:groups, []) |> Enum.flat_map(&Map.get(source.roles, &1, [])),
           extra: %{"groups" => Map.get(entry, :groups, [])}
         }}

      {true, _} ->
        {:error, :invalid_credentials}
    end
  end

  @impl true
  def knows?(_source, reason), do: reason not in [:user_not_found, :connect_failed]

  @impl true
  def explain(reason), do: to_string(reason)
end
