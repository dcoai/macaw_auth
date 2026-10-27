defmodule Macaw.Auth.Live do
  @moduledoc """
  The LiveView side of `Macaw.Auth`:

      live_session :signed_in, on_mount: [{Macaw.Auth.Live, :require_authenticated}] do
        live "/", DashboardLive
      end

      live_session :admin, on_mount: [{Macaw.Auth.Live, {:require_role, ["admin"]}}] do
        live "/admin", AdminLive
      end

      live_session :posts,
        on_mount: [{Macaw.Auth.Live, {:authorize, :edit, resource: &MyAppWeb.Posts.post/2}}] do
        live "/posts/:id/edit", PostEditLive
      end

  `{:authorize, action}` asks the app's authorizer (`Macaw.Auth.authorize/3`)
  whether the user may do `action` to the resource: what the `:resource`
  option's function (a remote capture, `&Mod.fun/2`) gives of the page's
  params and socket at mount, else nil. With no authorizer configured,
  every such page is refused.

  `:mount_current_user` only assigns. The others also guard an open page:
  it subscribes to its user's revocations and disconnects at once when its
  session is revoked, and re-checks its session every `:revalidate_ms`
  (default 60 s) without extending it. The re-check refreshes the user and
  applies the mount's guard again: a page whose user lost its role, or
  whose authorizer now refuses it (asked about the resource the page
  mounted with), goes home, and one whose session now owes a step goes to
  that step.

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
    do: mount(session, socket, {:roles, roles})

  def on_mount({:authorize, action}, params, session, socket) when is_atom(action),
    do: on_mount({:authorize, action, []}, params, session, socket)

  def on_mount({:authorize, action, opts}, params, session, socket)
      when is_atom(action) and is_list(opts) do
    resource = opts |> Keyword.validate!(resource: nil) |> Keyword.fetch!(:resource)
    mount(session, socket, {:authorize_unresolved, action, resource, params, socket})
  end

  defp fetch(session), do: Auth.fetch(session[Macaw.Auth.Plug.token_key()], touch: false)

  defp mount(session, socket, guard) do
    case session |> fetch() |> admit(guard) do
      {:ok, user, user_session, guard} ->
        socket =
          socket
          |> assign(current_user: user, current_session: user_session)
          |> Phoenix.LiveView.put_private(:macaw_auth_guard, guard)
          |> guard()

        {:cont, socket}

      {:redirect, to} ->
        {:halt, Phoenix.LiveView.redirect(socket, to: to)}
    end
  end

  # The guard, the same at mount and at every re-check: a session, then no
  # step owed, then the page's own check: `:any` (a signed-in page),
  # `{:roles, roles}` (one of them), or `{:authorize, action, resource}`
  # (the app's authorizer). An authorize hook mounts with
  # `{:authorize_unresolved, …}`: its resource is resolved once, at mount and
  # only for a session admitted so far, and the guard kept for the re-checks
  # is the resolved one.
  defp admit({:ok, user, user_session}, guard) do
    if step = Auth.pending_step(user, user_session) do
      {:redirect, Auth.path(step)}
    else
      guard = resolve(guard)

      if allowed?(user, guard),
        do: {:ok, user, user_session, guard},
        else: {:redirect, Auth.path(:home)}
    end
  end

  defp admit({:error, _}, _guard), do: {:redirect, Auth.path(:sign_in)}

  defp resolve({:authorize_unresolved, action, nil, _params, _socket}),
    do: {:authorize, action, nil}

  defp resolve({:authorize_unresolved, action, fun, params, socket}) when is_function(fun, 2),
    do: {:authorize, action, fun.(params, socket)}

  defp resolve(guard), do: guard

  defp allowed?(_user, :any), do: true
  defp allowed?(user, {:roles, roles}), do: Enum.any?(user.roles, &(&1 in roles))
  defp allowed?(user, {:authorize, action, resource}), do: Auth.authorize(user, action, resource)

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
    |> admit(socket.private.macaw_auth_guard)
    |> case do
      {:ok, user, user_session, _guard} ->
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
