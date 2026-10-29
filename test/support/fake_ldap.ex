defmodule Macaw.Auth.Test.FakeLdap do
  @moduledoc """
  A directory for the LDAP source's own flow, without the fixture: a TCP
  listener on 127.0.0.1 speaking plain LDAP through `:eldap`'s own ASN.1
  codec (`ELDAPv3`), so the real `Macaw.Auth.Native.Source.Ldap` runs
  against it unchanged (`ssl: false, allow_plaintext: true`).

  The directory is a map:
  - `binds`: DN => password, the binds it accepts;
  - `entries`: DN => `%{attribute => [value]}`, read by a base-object search;
  - `groups`: `[%{dn, cn, members}]`, found by an equality match on any
    member attribute whose value is in `members`;
  - `group_readers`: the DNs whose bind may read the groups (`:anyone`, the
    default, for any bind). Any other bind's group search finds nothing, as
    a directory restricting reads does.

  It tells the process that started it each bind, `{:fake_ldap, :bind, dn,
  password}`, and each group search, `{:fake_ldap, :group_search, bound_dn}`.
  """

  import ExUnit.Callbacks, only: [start_supervised!: 1]

  @doc "Starts the directory under the test's supervisor; its port."
  @spec start(map()) :: :inet.port_number()
  def start(directory) do
    owner = self()

    directory =
      Map.merge(%{binds: %{}, entries: %{}, groups: [], group_readers: :anyone}, directory)

    start_supervised!(
      Supervisor.child_spec(
        {Task,
         fn ->
           {:ok, listen} =
             :gen_tcp.listen(0, [:binary, packet: :asn1, active: false, ip: {127, 0, 0, 1}])

           {:ok, port} = :inet.port(listen)
           send(owner, {:fake_ldap, :port, port})
           accept(listen, directory, owner)
         end},
        id: make_ref()
      )
    )

    receive do
      {:fake_ldap, :port, port} -> port
    end
  end

  defp accept(listen, directory, owner) do
    {:ok, socket} = :gen_tcp.accept(listen)
    # Linked, so a request it can't answer fails the test.
    pid = spawn_link(fn -> serve(socket, directory, owner) end)
    :ok = :gen_tcp.controlling_process(socket, pid)
    send(pid, :go)
    accept(listen, directory, owner)
  end

  defp serve(socket, directory, owner) do
    receive do
      :go -> loop(socket, directory, owner, nil)
    end
  end

  defp loop(socket, directory, owner, bound) do
    case :gen_tcp.recv(socket, 0) do
      {:ok, data} ->
        {:ok, {:LDAPMessage, id, op, _controls}} = :ELDAPv3.decode(:LDAPMessage, data)

        case handle(op, directory, owner, bound) do
          {:reply, replies, bound} ->
            for reply <- replies do
              {:ok, bytes} =
                :ELDAPv3.encode(:LDAPMessage, {:LDAPMessage, id, reply, :asn1_NOVALUE})

              :ok = :gen_tcp.send(socket, bytes)
            end

            loop(socket, directory, owner, bound)

          :close ->
            :gen_tcp.close(socket)
        end

      {:error, :closed} ->
        :ok
    end
  end

  defp handle({:bindRequest, {:BindRequest, _version, dn, {:simple, password}}}, dir, owner, _) do
    {dn, password} = {to_string(dn), to_string(password)}
    send(owner, {:fake_ldap, :bind, dn, password})

    case Map.fetch(dir.binds, dn) do
      {:ok, ^password} -> {:reply, [bind_response(:success)], dn}
      _ -> {:reply, [bind_response(:invalidCredentials)], nil}
    end
  end

  defp handle({:searchRequest, request}, dir, owner, bound) do
    {:SearchRequest, base, scope, _deref, _size, _time, _types, filter, _attrs} = request
    base = to_string(base)

    found =
      case {scope, filter} do
        {:baseObject, _} ->
          case Map.fetch(dir.entries, base) do
            {:ok, attrs} -> [{base, attrs}]
            :error -> []
          end

        {:wholeSubtree, {:equalityMatch, {:AttributeValueAssertion, _attr, value}}} ->
          send(owner, {:fake_ldap, :group_search, bound})
          groups(dir, bound, to_string(value))
      end

    entries =
      for {dn, attrs} <- found do
        {:searchResEntry,
         {:SearchResultEntry, dn,
          for({name, values} <- attrs, do: {:PartialAttribute, name, values})}}
      end

    {:reply, entries ++ [{:searchResDone, result(:success)}], bound}
  end

  defp handle({:unbindRequest, _}, _dir, _owner, _bound), do: :close

  defp groups(dir, bound, value) do
    if dir.group_readers == :anyone or bound in dir.group_readers,
      do: for(g <- dir.groups, value in g.members, do: {g.dn, %{"cn" => [g.cn]}}),
      else: []
  end

  defp bind_response(code),
    do: {:bindResponse, {:BindResponse, code, "", "", :asn1_NOVALUE, :asn1_NOVALUE}}

  defp result(code), do: {:LDAPResult, code, "", "", :asn1_NOVALUE}
end
