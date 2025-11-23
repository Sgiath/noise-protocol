defmodule Noise.Crypto.Hash.Blake2s do
  @moduledoc "BLAKE2s Hash implementation."
  use Noise.Crypto.Hash

  @impl Noise.Crypto.Hash
  def hashlen, do: 32

  @impl Noise.Crypto.Hash
  def hash(data) do
    :crypto.hash(:blake2s, data)
  end

  @impl Noise.Crypto.Hash
  def hmac_hash(key, data) do
    :crypto.mac(:hmac, :blake2s, key, data)
  end
end
