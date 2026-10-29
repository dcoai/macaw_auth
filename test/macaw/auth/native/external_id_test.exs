defmodule Macaw.Auth.Native.ExternalIdTest do
  @moduledoc """
  A directory user's external id: the binary the directory gave, one
  spelling in the column (`Macaw.Auth.Native.ExternalId`), written at
  sign-in from `Macaw.Auth.Test.FakeLdap` through the chain.
  """

  use Macaw.Auth.DataCase, async: false
  use ExUnitProperties

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{ExternalId, UserRecord}
  alias Macaw.Auth.Native.Source.Ldap
  alias Macaw.Auth.Test.FakeLdap
  alias Macaw.Auth.User

  @base "dc=example,dc=test"
  @uuid "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
  # An objectGUID: sixteen bytes, most of them not printable.
  @guid <<0x12, 0x34, 0x56, 0x78, 0, 255, 16, 1, 0x9A, 0xBC, 0xDE, 0xF0, 7, 8, 9, 10>>

  defp dn(name), do: "uid=#{name},cn=users,#{@base}"

  defp directory do
    %{
      binds: %{dn("uma") => "uma-pw", dn("gus") => "gus-pw", dn("hex") => "hex-pw"},
      entries: %{
        dn("uma") => %{"uid" => ["uma"], "entryUUID" => [@uuid], "objectGUID" => ["text"]},
        dn("gus") => %{"uid" => ["gus"], "objectGUID" => [@guid]},
        # Printable text that looks like hex.
        dn("hex") => %{"uid" => ["hex"], "objectGUID" => ["00ff"]}
      }
    }
  end

  defp source(port, attrs \\ %{}) do
    Map.merge(
      %{
        type: :ldap,
        name: "nas",
        host: "127.0.0.1",
        port: port,
        ssl: false,
        allow_plaintext: true,
        user_dn_template: "uid={username},cn=users,#{@base}",
        default_role: "viewer"
      },
      attrs
    )
  end

  defp column(username) do
    Repo.query!("SELECT external_id FROM macaw_auth_users WHERE username = ?", [username]).rows
  end

  @tag verifies: "external-id-spelling"
  test "printable and binary ids are both stored as lower-case hex, and read back as given" do
    port = FakeLdap.start(directory())
    configure!(sources: [source(port, %{id_attr: "objectGUID"})])

    assert {:ok, %User{}} = Native.authenticate(%{username: "gus", password: "gus-pw"})
    assert {:ok, %User{}} = Native.authenticate(%{username: "hex", password: "hex-pw"})

    configure!(sources: [source(port)])

    assert {:ok, %User{extra: extra}} =
             Native.authenticate(%{username: "uma", password: "uma-pw"})

    refute Map.has_key?(extra, "external_id")

    # The column: one spelling for every value.
    assert column("uma") == [[Base.encode16(@uuid, case: :lower)]]
    assert column("gus") == [["12345678" <> "00ff10019abcdef0" <> "0708090a"]]
    assert column("hex") == [["30306666"]]

    # Read back: the directory's binary.
    assert Repo.get_by!(UserRecord, username: "uma").external_id == @uuid
    assert Repo.get_by!(UserRecord, username: "gus").external_id == @guid
    assert Repo.get_by!(UserRecord, username: "hex").external_id == "00ff"
    assert Repo.get_by!(UserRecord, external_id: @guid).username == "gus"

    # The source hands over the binary itself; the DN without the attribute.
    assert {:ok, %{external_id: @guid}} =
             Ldap.authenticate(ldap(port, %{id_attr: "objectGUID"}), "gus", "gus-pw", [])

    assert {:ok, %{external_id: "uid=gus,cn=users," <> _}} =
             Ldap.authenticate(ldap(port), "gus", "gus-pw", [])

    # Every later sign-in writes the directory's word: an id the directory changed is replaced.
    configure!(sources: [source(port, %{id_attr: "objectGUID"})])
    assert {:ok, %User{}} = Native.authenticate(%{username: "uma", password: "uma-pw"})
    assert Repo.get_by!(UserRecord, username: "uma").external_id == "text"
    assert Repo.aggregate(UserRecord, :count) == 3

    # A local user has none.
    assert local_user!("lou", "local password").external_id == nil
    assert column("lou") == [[nil]]
  end

  defp ldap(port, attrs \\ %{}) do
    {:ok, source} = Ldap.parse(source(port, attrs), [])
    source
  end

  @tag verifies: "external-id-load"
  test "a column value that isn't lower-case hex fails the load" do
    for bad <- ["ABCD", "abc", "zz", "1b4e28ba-2fa1"], do: assert(ExternalId.load(bad) == :error)
    assert ExternalId.load("") == {:ok, ""}
    assert ExternalId.cast(:atom) == :error
    assert ExternalId.dump(42) == :error

    record = local_user!("ivy", "local password")
    Repo.query!("UPDATE macaw_auth_users SET external_id = 'NOT HEX' WHERE username = 'ivy'")
    assert_raise ArgumentError, fn -> Repo.get!(UserRecord, record.id) end
  end

  @tag verifies: "external-id-one-spelling"
  property "every binary has one spelling, read back as itself, and no two share one" do
    check all(a <- binary(), b <- binary(), max_runs: 50) do
      spelling = ExternalId.encode(a)
      assert spelling =~ ~r/\A[0-9a-f]*\z/
      assert {:ok, ^spelling} = ExternalId.dump(a)
      assert ExternalId.decode(spelling) == {:ok, a}
      assert ExternalId.load(spelling) == {:ok, a}
      assert a == b or ExternalId.encode(b) != spelling
    end

    # Printable and not alike, and text that looks like another value's spelling.
    values = ["00ff", <<0, 255>>, "abcd", <<0xAB, 0xCD>>, "", " ", "é", <<233>>]
    spellings = Enum.map(values, &ExternalId.encode/1)
    assert length(Enum.uniq(spellings)) == length(values)
  end

  describe "the sections of spec 06" do
    @tag verifies: "auth-external-id"
    test "only provisioning writes the id: the changeset never casts it" do
      changeset =
        UserRecord.changeset(%UserRecord{}, %{
          username: "kim",
          source: "local",
          external_id: @guid
        })

      refute Map.has_key?(changeset.changes, :external_id)

      record = local_user!("kim", "local password", %{external_id: @guid})
      assert record.external_id == nil
      assert column("kim") == [[nil]]
      assert UserRecord.__schema__(:type, :external_id) == ExternalId
      assert ExternalId.type() == :string
    end
  end
end
