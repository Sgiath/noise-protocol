defmodule Noise.Crypto.Hash.Sha512 do
  use Noise.Crypto.Hash

  @impl Noise.Crypto.Hash
  def hashlen, do: 64

  @impl Noise.Crypto.Hash
  def hash(data) do
    :crypto.hash(:sha512, data)
  end

  @impl Noise.Crypto.Hash
  def hmac_hash(key, data) do
    :crypto.mac(:hmac, :sha512, key, data)
  end
end
