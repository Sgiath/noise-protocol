defmodule Noise.Crypto.Hash.Sha256 do
  use Noise.Crypto.Hash

  @impl Noise.Crypto.Hash
  def hashlen, do: 32

  @impl Noise.Crypto.Hash
  def hash(data) do
    :crypto.hash(:sha256, data)
  end

  @impl Noise.Crypto.Hash
  def hmac_hash(key, data) do
    :crypto.mac(:hmac, :sha256, key, data)
  end
end
