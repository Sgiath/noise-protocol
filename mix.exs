defmodule Noise.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      # Library
      app: :noise_protocol,
      version: @version,
      elixir: "~> 1.14",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      consolidate_protocols: Mix.env() != :test,
      deps: deps(),

      # Docs
      name: "Noise Protocol",
      source_url: "https://github.com/Sgiath/noise-protocol",
      homepage_url: "https://sgiath.dev/libraries#noise",
      description: """
      Library implementing Noise protocol
      """,
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      # for secp256k1 curve
      {:lib_secp256k1, "~> 0.4"},
      # for chacha encryption
      {:enacl, "~> 1.2"},

      # Development
      {:ex_check, "~> 0.15", only: [:dev], runtime: false},
      {:credo, "~> 1.7", only: [:dev], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.31", only: [:dev], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev], runtime: false},
      {:mix_test_watch, "~> 1.1", only: [:dev], runtime: false}
    ]
  end

  defp package do
    [
      name: "noise_protocol",
      maintainers: ["Sgiath <noise@sgiath.dev>"],
      files: ~w(lib LICENSE mix.exs README* CHANGELOG*),
      licenses: ["WTFPL"],
      links: %{
        "Noise Homepage" => "https://noiseprotocol.org/",
        "GitHub" => "https://github.com/Sgiath/noise-protocol"
      }
    ]
  end

  defp docs do
    [
      authors: ["sgiath <noise@sgiath.dev>"],
      main: "readme",
      api_reference: false,
      extras: [
        "README.md": [filename: "readme", title: "Overview"],
        "CHANGELOG.md": [filename: "changelog", title: "Changelog"]
      ],
      formatters: ["html"],
      source_ref: "v#{@version}",
      source_url: "https://github.com/Sgiath/noise-protocol"
    ]
  end
end
