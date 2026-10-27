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

  @tag verifies: "hasher-own"
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

  @tag verifies: "hasher-params"
  test "a changed bcrypt cost or argon2 parameter needs a rehash" do
    bcrypt = Bcrypt.hash("secret")
    argon2 = Argon2.hash("secret")
    with_env(:bcrypt_elixir, :log_rounds, 5)
    with_env(:argon2_elixir, :t_cost, 2)
    assert Bcrypt.needs_rehash?(bcrypt)
    assert Argon2.needs_rehash?(argon2)
  end

  @tag verifies: "hasher-cross"
  test "a hash by the other algorithm verifies with it, and needs a rehash" do
    bcrypt = Bcrypt.hash("secret")
    assert Hasher.verify(Argon2, "secret", bcrypt)
    refute Hasher.verify(Argon2, "wrong", bcrypt)
    assert Hasher.needs_rehash?(Argon2, bcrypt)
    refute Hasher.needs_rehash?(Bcrypt, bcrypt)
    refute Hasher.verify(Bcrypt, "secret", "not a hash")
    refute Hasher.verify(Bcrypt, "secret", nil)
  end

  @tag verifies: "hasher-check"
  test "a hasher that isn't one is refused by name" do
    assert Hasher.check(Bcrypt) == :ok
    assert {:error, "hasher: String is not a Macaw.Auth.Native.Hasher"} = Hasher.check(String)
    assert {:error, "hasher: must be a module" <> _} = Hasher.check("bcrypt")
  end

  defmodule OnlyHash do
    def hash(password), do: password
  end

  @tag verifies: "hasher-check-whole-behavior"
  test "a module with hash/1 but not the whole behavior is refused" do
    assert Hasher.check(OnlyHash) ==
             {:error, "hasher: #{inspect(OnlyHash)} is not a Macaw.Auth.Native.Hasher"}

    assert Hasher.check(Macaw.Auth.Test.CountingHasher) == :ok
  end

  @tag verifies: "hasher-check-each-callback"
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
    @tag verifies: "hasher-rehash-cost"
    test "a hash at an old cost is replaced on a successful sign-in, and a wrong password changes nothing" do
      local_user!("cost", "a long password")
      old = Repo.get_by!(UserRecord, username: "cost").hashed_password
      assert old =~ ~r/^\$2b\$04\$/

      with_env(:bcrypt_elixir, :log_rounds, 5)

      assert {:error, :invalid_credentials} =
               Native.authenticate(%{username: "cost", password: "x"})

      assert Repo.get_by!(UserRecord, username: "cost").hashed_password == old

      assert {:ok, _} = Native.authenticate(%{username: "cost", password: "a long password"})
      new = Repo.get_by!(UserRecord, username: "cost").hashed_password
      assert new =~ ~r/^\$2b\$05\$/
      assert Bcrypt.verify("a long password", new)
    end

    @tag verifies: "hasher-rehash-algorithm"
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

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 08" do
    @tag verifies: "auth-hasher"
    test "a behavior with two implementations, and a host can move between them" do
      for module <- [Bcrypt, Argon2] do
        assert Hasher.check(module) == :ok
      end

      # Whichever is configured, a hash by either verifies.
      for configured <- [Bcrypt, Argon2], made_by <- [Bcrypt, Argon2] do
        assert Hasher.verify(configured, "secret", made_by.hash("secret"))
      end
    end

    @tag verifies: "auth-hasher-behavior"
    test "the five callbacks; each implementation is compiled with its library; check/1's answers" do
      assert Enum.sort(Hasher.behaviour_info(:callbacks)) ==
               [hash: 1, needs_rehash?: 1, no_user_verify: 0, owns?: 1, verify: 2]

      # Compiled exactly when its library is (both are, in this suite).
      assert Code.ensure_loaded?(Bcrypt) == Code.ensure_loaded?(Elixir.Bcrypt)
      assert Code.ensure_loaded?(Argon2) == Code.ensure_loaded?(Elixir.Argon2)

      assert Hasher.check(Bcrypt) == :ok
      assert Hasher.check(Argon2) == :ok

      assert Hasher.check(OnlyHash) ==
               {:error, "hasher: #{inspect(OnlyHash)} is not a Macaw.Auth.Native.Hasher"}

      assert Hasher.check("bcrypt") == {:error, ~s(hasher: must be a module, got "bcrypt")}
      assert Hasher.check(42) == {:error, "hasher: must be a module, got 42"}

      # The configuration checks its hasher with it, when it is read.
      assert Macaw.Auth.Native.Config.parse(repo: Repo, hasher: OnlyHash) ==
               {:error, "hasher: #{inspect(OnlyHash)} is not a Macaw.Auth.Native.Hasher"}
    end

    @tag verifies: "auth-hasher-algorithms"
    test "each algorithm's prefixes, and the parameters that make a hash need a rehash" do
      bcrypt = Bcrypt.hash("secret")
      <<"$2b$", rest::binary>> = bcrypt

      for prefix <- ["$2a$", "$2b$", "$2y$"], do: assert(Bcrypt.owns?(prefix <> rest))
      refute Bcrypt.owns?("$2x$" <> rest)

      # The cost is the two digits after the second $; a hash it can't read needs a rehash.
      refute Bcrypt.needs_rehash?("$2y$" <> rest)
      assert Bcrypt.needs_rehash?(String.replace(bcrypt, "$04$", "$12$"))
      assert Bcrypt.needs_rehash?("$2b$garbage")

      argon2 = Argon2.hash("secret")
      assert argon2 =~ ~r/^\$argon2id\$v=19\$m=256,t=1,p=1\$/
      assert Argon2.owns?(argon2)
      refute Argon2.owns?(bcrypt)

      # Another type, or other m, t or p, or a hash it can't read, needs a rehash.
      refute Argon2.needs_rehash?(argon2)
      assert Argon2.needs_rehash?(String.replace(argon2, "$argon2id$", "$argon2i$"))
      assert Argon2.needs_rehash?(String.replace(argon2, "m=256,", "m=512,"))
      assert Argon2.needs_rehash?(String.replace(argon2, ",p=1$", ",p=4$"))
      assert Argon2.needs_rehash?("$argon2id")

      # The parameters are the libraries' own settings.
      # (argon2_type is unset here: argon2_elixir's own default, 2.)
      Application.put_env(:argon2_elixir, :argon2_type, 1)
      on_exit(fn -> Application.delete_env(:argon2_elixir, :argon2_type) end)
      assert Argon2.needs_rehash?(argon2)
    end

    @tag verifies: "auth-hasher-rehash"
    test "verify/3 tries the configured hasher first; needs_rehash?/2" do
      alias Macaw.Auth.Test.CountingHasher

      # The configured one first: a bcrypt hash goes to the counting hasher, which owns it.
      assert Hasher.verify(CountingHasher, "secret", Bcrypt.hash("secret"))
      assert_received {:hasher, :verify}

      # Then any other available: an argon2 hash, which the configured one doesn't own.
      assert Hasher.verify(CountingHasher, "secret", Argon2.hash("secret"))
      refute_received {:hasher, :verify}

      # A hash no algorithm owns, or none: the configured hasher's no-user time, and false.
      refute Hasher.verify(CountingHasher, "secret", "not a hash")
      assert_received {:hasher, :no_user_verify}
      refute Hasher.verify(CountingHasher, "secret", nil)
      assert_received {:hasher, :no_user_verify}

      # needs_rehash?/2: not the configured algorithm's, or its parameters changed.
      bcrypt = Bcrypt.hash("secret")
      refute Hasher.needs_rehash?(Bcrypt, bcrypt)
      assert Hasher.needs_rehash?(Argon2, bcrypt)
      with_env(:bcrypt_elixir, :log_rounds, 5)
      assert Hasher.needs_rehash?(Bcrypt, bcrypt)
    end
  end
end
