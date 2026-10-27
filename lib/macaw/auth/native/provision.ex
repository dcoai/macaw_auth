defmodule Macaw.Auth.Native.Provision do
  @moduledoc """
  Just-in-time provisioning of directory users (ported from exio's
  `External.resolve/2`): a directory user signing in for the first time
  gets a `macaw_auth_users` row, with `source` the directory's name and no
  password, and at every later sign-in the directory's word replaces the
  row's roles and display name. The directory is the authority on who is
  in which group, so a user removed from an admin group loses the role at
  their next sign-in, not whenever someone remembers to edit the row.

  Two refusals keep identities apart:

  - a row with the username that another source owns (a local user, or
    another directory's) is never taken over (`:username_taken`): a
    directory that happens to have an `owner` entry doesn't become the
    local `owner`;
  - a disabled row stays refused (`:disabled`), whatever the directory
    says, and is left as it is.
  """

  alias Macaw.Auth.Native.UserRecord

  @doc """
  The row for a directory user the source `name` accepted, made or
  refreshed: `{:ok, record}` or `{:error, :username_taken | :disabled |
  :invalid_username}`.
  """
  @spec directory_user(module(), String.t(), map()) ::
          {:ok, UserRecord.t()} | {:error, :username_taken | :disabled | :invalid_username}
  def directory_user(repo, name, attrs), do: directory_user(repo, name, attrs, true)

  defp directory_user(repo, name, attrs, retry) do
    with {:ok, username} <- UserRecord.normalize_username(attrs.username) do
      case repo.get_by(UserRecord, username: username) do
        nil -> insert(repo, name, %{attrs | username: username}, retry)
        %UserRecord{source: ^name, disabled_at: nil} = record -> refresh(repo, record, attrs)
        %UserRecord{source: ^name} -> {:error, :disabled}
        %UserRecord{} -> {:error, :username_taken}
      end
    end
  end

  defp insert(repo, name, attrs, retry) do
    %UserRecord{}
    |> UserRecord.changeset(%{
      username: attrs.username,
      display_name: attrs[:display_name],
      source: name,
      roles: attrs.roles,
      extra: Map.get(attrs, :extra, %{})
    })
    |> repo.insert()
    |> case do
      {:ok, record} ->
        {:ok, record}

      # Two first sign-ins at once: the other made the row, so use it.
      {:error, changeset} ->
        cond do
          not taken?(changeset) ->
            raise Ecto.InvalidChangesetError, action: :insert, changeset: changeset

          retry ->
            directory_user(repo, name, attrs, false)

          true ->
            {:error, :username_taken}
        end
    end
  end

  defp taken?(%Ecto.Changeset{errors: errors}) do
    case errors[:username] do
      {_message, opts} -> opts[:constraint] == :unique
      nil -> false
    end
  end

  # A changeset of a row that loaded can only fail through a bug: raised.
  defp refresh(repo, record, attrs) do
    {:ok,
     record
     |> UserRecord.changeset(%{
       display_name: attrs[:display_name],
       roles: attrs.roles,
       extra: Map.merge(record.extra || %{}, Map.get(attrs, :extra, %{}))
     })
     |> repo.update!()}
  end
end
