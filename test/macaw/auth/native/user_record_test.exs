defmodule Macaw.Auth.Native.UserRecordTest do
  use Macaw.Auth.DataCase, async: false

  alias Macaw.Auth.Native.UserRecord

  @tag verifies: "username-normalize"
  test "normalize_username trims and lower-cases, and refuses anything else" do
    assert UserRecord.normalize_username(" Alice ") == {:ok, "alice"}

    for bad <- ["not a name!", "", String.duplicate("a", 65), "-x", nil] do
      assert UserRecord.normalize_username(bad) == {:error, :invalid_username}, inspect(bad)
    end
  end

  # Each section's own text, beside the hints inside it.
  describe "the sections of spec 06" do
    @tag verifies: "auth-user-record"
    test "the users row: its defaults, what changeset/2 casts and checks, and what is redacted" do
      # The usernames that are valid: 1–64 of a-z 0-9 . _ @ + -, from a letter or digit.
      long = String.duplicate("a", 64)
      assert UserRecord.normalize_username(long) == {:ok, long}
      assert UserRecord.normalize_username("9.a_b@c+d-e") == {:ok, "9.a_b@c+d-e"}
      assert UserRecord.normalize_username("_x") == {:error, :invalid_username}
      # Nothing else is rewritten: inner spaces stay, and refuse.
      assert UserRecord.normalize_username("a b") == {:error, :invalid_username}

      # The defaults, and the username stored normalized.
      changeset =
        UserRecord.changeset(%UserRecord{}, %{
          username: " Ada ",
          totp_secret_sealed: "sealed",
          totp_enabled_at: DateTime.utc_now(),
          totp_last_step: 7
        })

      assert changeset.valid?
      row = Repo.insert!(changeset)

      assert %UserRecord{
               username: "ada",
               hashed_password: nil,
               source: "local",
               roles: [],
               disabled_at: nil,
               must_change_password: false,
               extra: %{},
               # The second factor's columns are never cast.
               totp_secret_sealed: nil,
               totp_enabled_at: nil,
               totp_last_step: nil
             } = row

      # username and source are required; an invalid username is named.
      errors = UserRecord.changeset(%UserRecord{}, %{source: nil}).errors
      assert {"can't be blank", _} = errors[:username]
      assert {"can't be blank", _} = errors[:source]

      assert {"must be 1–64 of a-z 0-9 . _ @ + -", _} =
               UserRecord.changeset(%UserRecord{}, %{username: "not a name!"}).errors[:username]

      # Unique: " ADA" is the same user.
      assert {:error, taken} =
               Repo.insert(UserRecord.changeset(%UserRecord{}, %{username: " ADA"}))

      assert {"has already been taken", _} = taken.errors[:username]

      # The hash and the sealed secret are redacted from inspection.
      shown =
        inspect(%UserRecord{
          username: "ada",
          hashed_password: "$2b$04$hash-value",
          totp_secret_sealed: "sealed-value"
        })

      refute shown =~ "hash-value"
      refute shown =~ "sealed-value"
    end
  end
end
