defmodule Noise.Crypto.Hash.Blake2b do
  use Noise.Crypto.Hash

  @impl Noise.Crypto.Hash
  def hashlen, do: 64

  @impl Noise.Crypto.Hash
  def hash(data) do
    :crypto.hash(:blake2b, data)
  end

  @impl Noise.Crypto.Hash
  def hmac_hash(key, data) do
    :crypto.mac(:hmac, :blake2b, key, data)
  end
end
