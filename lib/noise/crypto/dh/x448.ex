defmodule Noise.Crypto.DH.X448 do
  use Noise.Crypto.DH

  @impl Noise.Crypto.DH
  def generate_keypair do
    {pubkey, seckey} = :crypto.generate_key(:ecdh, :x448)
    {seckey, pubkey}
  end

  @impl Noise.Crypto.DH
  def dh({seckey, _pubkey}, pubkey) do
    :crypto.compute_key(:ecdh, pubkey, seckey, :x448)
  end
end
