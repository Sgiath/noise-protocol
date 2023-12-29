defmodule Noise.MixProject do
  use Mix.Project

  def project do
    [
      app: :noise,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:lib_secp256k1, "~> 0.4"},
      {:enacl, "~> 1.2"}
    ]
  end
end
