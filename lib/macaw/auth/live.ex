defmodule Macaw.Auth.Live do
  @moduledoc """
  The LiveView side of `Macaw.Auth`:

      live_session :signed_in, on_mount: [{Macaw.Auth.Live, :require_authenticated}] do
        live "/", DashboardLive
      end

      live_session :admin, on_mount: [{Macaw.Auth.Live, {:require_role, ["admin"]}}] do
        live "/admin", AdminLive
      end

  `:mount_current_user` only assigns. The others also guard an open page:
  it subscribes to its user's revocations and disconnects at once when its
  session is revoked, and re-checks its session every `:revalidate_ms`
  (default 60 s) without extending it. The re-check refreshes the user and
  applies the mount's guard again: a page whose user lost its role goes
  home, and one whose session now owes a step goes to that step.

  With `config :macaw_auth, endpoint: MyAppWeb.Endpoint`, a revocation
  also has Phoenix drop the session's sockets, by the `live_socket_id`
  `Macaw.Auth.Plug.log_in/3` put in the session (`Macaw.Auth.announce_revoked/2`).
  """

  import Phoenix.Component, only: [assign: 2]

  alias Macaw.Auth

  @doc false
  def on_mount(:mount_current_user, _params, session, socket) do
    case fetch(session) do
      {:ok, user, user_session} ->
        {:cont, assign(socket, current_user: user, current_session: user_session)}

      {:error, _} ->
        {:cont, assign(socket, current_user: nil, current_session: nil)}
    end
  end

  def on_mount(:require_authenticated, _params, session, socket),
    do: mount(session, socket, :any)

  def on_mount({:require_role, roles}, _params, session, socket) when is_list(roles),
    do: mount(session, socket, roles)

  defp fetch(session), do: Auth.fetch(session[Macaw.Auth.Plug.token_key()], touch: false)

  defp mount(session, socket, roles) do
    case session |> fetch() |> admit(roles) do
      {:ok, user, user_session} ->
        socket =
          socket
          |> assign(current_user: user, current_session: user_session)
          |> Phoenix.LiveView.put_private(:macaw_auth_roles, roles)
          |> guard()

        {:cont, socket}

      {:redirect, to} ->
        {:halt, Phoenix.LiveView.redirect(socket, to: to)}
    end
  end

  # The guard, the same at mount and at every re-check: a session, then no
  # step owed, then one of `roles` (`:any` for a signed-in page).
  defp admit({:ok, user, user_session} = found, roles) do
    cond do
      step = Auth.pending_step(user, user_session) -> {:redirect, Auth.path(step)}
      not role?(user, roles) -> {:redirect, Auth.path(:home)}
      true -> found
    end
  end

  defp admit({:error, _}, _roles), do: {:redirect, Auth.path(:sign_in)}

  defp role?(_user, :any), do: true
  defp role?(user, roles), do: Enum.any?(user.roles, &(&1 in roles))

  defp guard(socket) do
    if Phoenix.LiveView.connected?(socket) do
      :ok = Auth.subscribe(socket.assigns.current_user.id)
      schedule_recheck()
      Phoenix.LiveView.attach_hook(socket, :macaw_auth_guard, :handle_info, &handle_guard/2)
    else
      socket
    end
  end

  @doc false
  def handle_guard({:sessions_revoked, ids}, socket) do
    if socket.assigns.current_session.id in ids,
      do: {:halt, Phoenix.LiveView.redirect(socket, to: Auth.path(:sign_in))},
      else: {:halt, socket}
  end

  def handle_guard(:macaw_auth_recheck, socket) do
    socket.assigns.current_session.id
    |> Auth.fetch_by_id(touch: false)
    |> admit(socket.private.macaw_auth_roles)
    |> case do
      {:ok, user, user_session} ->
        schedule_recheck()
        {:halt, assign(socket, current_user: user, current_session: user_session)}

      {:redirect, to} ->
        {:halt, Phoenix.LiveView.redirect(socket, to: to)}
    end
  end

  def handle_guard(_message, socket), do: {:cont, socket}

  defp schedule_recheck,
    do:
      Process.send_after(
        self(),
        :macaw_auth_recheck,
        Application.get_env(:macaw_auth, :revalidate_ms, 60_000)
      )
end
