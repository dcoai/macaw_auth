defmodule Macaw.Auth.MixProject do
  use Mix.Project

  @source_url "https://github.com/dcoai/macaw_auth"
  @version "0.4.3"

  def project do
    [
      app: :macaw_auth,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: ["auth.verify": &verify_models/1],
      description:
        "Authentication for Phoenix hosts: a narrow contract with a native backend " <>
          "(passwords, LDAP, hashed sessions, throttling, TOTP).",
      source_url: @source_url,
      package: package(),
      docs: [
        main: "readme",
        extras: ["README.md", "CHANGELOG.md"],
        source_ref: "v#{@version}",
        logo: "brand/logo/macaw_scarlet.svg",
        assets: %{"brand/logo" => "brand/logo"}
      ]
    ]
  end

  def application do
    [
      mod: {Macaw.Auth.Application, []},
      extra_applications: [:logger, :crypto, :eldap, :ssl, :public_key]
    ]
  end

  # `specs/` holds the extla models (spec/10 §7), dev and test only, so a host
  # never compiles them.
  defp elixirc_paths(:test), do: ["lib", "specs", "test/support"]
  defp elixirc_paths(:dev), do: ["lib", "specs"]
  defp elixirc_paths(_), do: ["lib"]

  # Published on Hex from its public home, mirrored from GitLab (dco-tek/macaw/macaw#155).
  defp package do
    [
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "https://hexdocs.pm/macaw_auth/changelog.html"
      },
      files: ~w(lib spec mix.exs README.md LICENSE CHANGELOG.md .formatter.exs)
    ]
  end

  defp deps do
    [
      {:macaw_plug, "~> 0.2.0"},
      # The release side of <app>-ctl's protocol (Macaw.Host.Release), for the
      # user commands' release entry points (macaw_compose#75).
      {:macaw_host, "~> 0.2.0"},
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
      # Docs for Hex (macaw_compose#155); dev only.
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      # Spec, tests and code kept aligned (macaw_compose spec/00 §4.1); dev/test only.
      {:surfex, "~> 0.10.0", only: [:dev, :test], runtime: false},
      # `mix auth.verify` (spec/10 §7): the model of the throttle, from Hex.
      # `only:` is load-bearing: dev and test deps are not transitive, so nothing
      # here reaches a host.
      {:extla, "~> 0.6.0", only: [:dev, :test], runtime: false}
    ]
  end

  # Every model, checked one at a time. `Mix.Task.rerun/2`, not a list alias: Mix
  # remembers a task by name and silently skips it the second time.
  @models ~w(Macaw.Auth.Specs.Throttle)
  defp verify_models(_args), do: Enum.each(@models, &Mix.Task.rerun("extla.check", [&1]))
end
