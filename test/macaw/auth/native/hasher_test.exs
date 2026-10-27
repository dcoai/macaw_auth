defmodule Macaw.Auth.Native.HasherTest do
  use Macaw.Auth.DataCase, async: false

  alias Macaw.Auth.Native
  alias Macaw.Auth.Native.{Hasher, UserRecord}
  alias Macaw.Auth.Native.Hasher.{Argon2, Bcrypt}

  defp with_env(app, key, value) do
    previous = Application.get_env(app, key)
    Application.put_env(app, key, value)
    on_exit(fn -> Application.put_env(app, key, previous) end)
  end

  test "each algorithm owns its own hashes and verifies them" do
    for module <- [Bcrypt, Argon2] do
      hash = module.hash("secret")
      assert module.owns?(hash)
      assert module.verify("secret", hash)
      refute module.verify("other", hash)
      refute module.needs_rehash?(hash)
      assert module.no_user_verify() == false
    end

    refute Bcrypt.owns?(Argon2.hash("x"))
    refute Argon2.owns?(Bcrypt.hash("x"))
  end

  test "a changed bcrypt cost or argon2 parameter needs a rehash" do
    bcrypt = Bcrypt.hash("secret")
    argon2 = Argon2.hash("secret")
    with_env(:bcrypt_elixir, :log_rounds, 5)
    with_env(:argon2_elixir, :t_cost, 2)
    assert Bcrypt.needs_rehash?(bcrypt)
    assert Argon2.needs_rehash?(argon2)
  end

  test "a hash by the other algorithm verifies with it, and needs a rehash" do
    bcrypt = Bcrypt.hash("secret")
    assert Hasher.verify(Argon2, "secret", bcrypt)
    refute Hasher.verify(Argon2, "wrong", bcrypt)
    assert Hasher.needs_rehash?(Argon2, bcrypt)
    refute Hasher.needs_rehash?(Bcrypt, bcrypt)
    refute Hasher.verify(Bcrypt, "secret", "not a hash")
    refute Hasher.verify(Bcrypt, "secret", nil)
  end

  test "a hasher that isn't one is refused by name" do
    assert Hasher.check(Bcrypt) == :ok
    assert {:error, "hasher: String is not a Macaw.Auth.Native.Hasher"} = Hasher.check(String)
    assert {:error, "hasher: must be a module" <> _} = Hasher.check("bcrypt")
  end

  defmodule OnlyHash do
    def hash(password), do: password
  end

  test "a module with hash/1 but not the whole behavior is refused" do
    assert Hasher.check(OnlyHash) ==
             {:error, "hasher: #{inspect(OnlyHash)} is not a Macaw.Auth.Native.Hasher"}

    assert Hasher.check(Macaw.Auth.Test.CountingHasher) == :ok
  end

  test "every callback is required: a module lacking any one of them is refused" do
    {:docs_v1, _, _, _, _, _, docs} = Code.fetch_docs(Hasher)
    callbacks = for {{:callback, name, arity}, _, _, _, _} <- docs, do: {name, arity}
    assert length(callbacks) == 5

    for {name, arity} = lacking <- callbacks do
      module = Module.concat(__MODULE__, "Lacking#{name}#{arity}")

      defs =
        for {n, a} <- callbacks, {n, a} != lacking do
          args = for i <- 1..a//1, do: Macro.var(:"_arg#{i}", nil)
          quote do: def(unquote(n)(unquote_splicing(args)), do: nil)
        end

      Module.create(module, defs, Macro.Env.location(__ENV__))
      assert {:error, "hasher: " <> _} = Hasher.check(module)
    end
  end

  describe "rehash at sign-in" do
    test "a hash at an old cost is replaced on a successful sign-in" do
      local_user!("cost", "a long password")
      old = Repo.get_by!(UserRecord, username: "cost").hashed_password
      assert old =~ ~r/^\$2b\$04\$/

      with_env(:bcrypt_elixir, :log_rounds, 5)
      assert {:ok, _} = Native.authenticate(%{username: "cost", password: "a long password"})
      new = Repo.get_by!(UserRecord, username: "cost").hashed_password
      assert new =~ ~r/^\$2b\$05\$/
      assert Bcrypt.verify("a long password", new)
    end

    test "a wrong password changes nothing" do
      local_user!("same", "a long password")
      old = Repo.get_by!(UserRecord, username: "same").hashed_password
      with_env(:bcrypt_elixir, :log_rounds, 5)

      assert {:error, :invalid_credentials} =
               Native.authenticate(%{username: "same", password: "x"})

      assert Repo.get_by!(UserRecord, username: "same").hashed_password == old
    end

    test "moving from bcrypt to argon2: the bcrypt hash signs in, and becomes argon2" do
      local_user!("mover", "a long password")
      configure!(hasher: Argon2)

      assert {:ok, _} = Native.authenticate(%{username: "mover", password: "a long password"})
      hash = Repo.get_by!(UserRecord, username: "mover").hashed_password
      assert Argon2.owns?(hash)
      assert {:ok, _} = Native.authenticate(%{username: "mover", password: "a long password"})
      assert Repo.get_by!(UserRecord, username: "mover").hashed_password == hash
    end
  end
end
