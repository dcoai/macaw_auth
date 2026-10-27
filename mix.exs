defmodule Macaw.Auth.MixProject do
  use Mix.Project

  @version "0.4.0"

  def project do
    [
      app: :macaw_auth,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "Authentication for Phoenix hosts: a narrow contract with a native backend " <>
          "(passwords, LDAP, hashed sessions, throttling, TOTP).",
      package: [licenses: ["MIT"]],
      docs: [main: "readme", extras: ["README.md"]]
    ]
  end

  def application do
    [
      mod: {Macaw.Auth.Application, []},
      extra_applications: [:logger, :crypto, :eldap, :ssl, :public_key]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:macaw_plug, git: "git@gitlab.conet.yarina.org:dco-tek/macaw_plug.git", tag: "v0.1.0"},
      # The release side of <app>-ctl's protocol (Macaw.Host.Release), for the
      # user commands' release entry points (macaw_compose#75).
      {:macaw_host, git: "git@gitlab.conet.yarina.org:dco-tek/macaw_host.git", tag: "v0.1.1"},
      {:plug, "~> 1.16"},
      {:telemetry, "~> 1.2"},
      {:nimble_totp, "~> 1.0"},
      {:ecto_sql, "~> 3.12"},
      {:bcrypt_elixir, "~> 3.2", optional: true},
      {:argon2_elixir, "~> 4.1", optional: true},
      # Required (owner decision 2026-10-27, macaw_compose#32): every host is a
      # Phoenix app, so the plugs use Phoenix.Controller and the hooks always
      # compile.
      {:phoenix, "~> 1.7"},
      {:phoenix_live_view, "~> 1.0"},
      {:phoenix_pubsub, "~> 2.1"},
      {:ecto_sqlite3, "~> 0.17", only: :test},
      {:stream_data, "~> 1.1", only: :test},
      # Spec, tests and code kept aligned (macaw_compose spec/00 §4.1); dev/test only.
      {:surfex, "~> 0.10.0", only: [:dev, :test], runtime: false}
    ]
  end
end
