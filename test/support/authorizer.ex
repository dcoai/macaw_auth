defmodule Macaw.Auth.Test.Authorizer do
  @moduledoc """
  An app's authorizer, for the tests: `:manage` for an admin, `:edit` of a
  post for its owner, `:explode` raises, `:maybe` answers neither true nor
  false, and nothing else is allowed. `post/1` and `post/2` are the plug's
  and the hook's resource functions: the post the `"owner"` parameter names.
  """

  @behaviour Macaw.Auth.Authorizer

  alias Macaw.Auth.User

  @impl Macaw.Auth.Authorizer
  def authorize(%User{roles: roles}, :manage, _resource), do: "admin" in roles
  def authorize(%User{id: id}, :edit, %{owner_id: owner}), do: id == owner
  def authorize(_user, :explode, _resource), do: raise("the authorizer failed")
  def authorize(_user, :maybe, _resource), do: :yes
  def authorize(_user, _action, _resource), do: false

  @doc "The plug's resource: the post the request's `owner` parameter names."
  def post(conn),
    do: conn |> Plug.Conn.fetch_query_params() |> Map.get(:query_params) |> post_of()

  @doc "The hook's resource: the post the page's `owner` parameter names."
  def post(params, _socket), do: post_of(params)

  defp post_of(%{"owner" => owner}), do: %{owner_id: String.to_integer(owner)}
end
