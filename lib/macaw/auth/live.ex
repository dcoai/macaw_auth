if Code.ensure_loaded?(Phoenix.LiveView) do
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
    (default 60 s) without extending it, which also refreshes the user, so a
    role change shows at once.
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
      with {:ok, user, user_session} <- fetch(session),
           nil <- Auth.pending_step(user, user_session),
           :ok <- role(user, roles) do
        socket = socket |> assign(current_user: user, current_session: user_session) |> guard()
        {:cont, socket}
      else
        :forbidden ->
          {:halt, Phoenix.LiveView.redirect(socket, to: Auth.path(:home))}

        step when is_atom(step) and not is_nil(step) ->
          {:halt, Phoenix.LiveView.redirect(socket, to: Auth.path(step))}

        {:error, _} ->
          {:halt, Phoenix.LiveView.redirect(socket, to: Auth.path(:sign_in))}
      end
    end

    defp role(_user, :any), do: :ok

    defp role(user, roles),
      do: if(Enum.any?(user.roles, &(&1 in roles)), do: :ok, else: :forbidden)

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
      case Auth.fetch_by_id(socket.assigns.current_session.id, touch: false) do
        {:ok, user, user_session} ->
          schedule_recheck()
          {:halt, assign(socket, current_user: user, current_session: user_session)}

        {:error, _} ->
          {:halt, Phoenix.LiveView.redirect(socket, to: Auth.path(:sign_in))}
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
end
