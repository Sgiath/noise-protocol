defmodule Noise.Crypto.DH.Secp256k1 do
  use Noise.Crypto.DH

  @impl Noise.Crypto.DH
  def generate_keypair do
    {pubkey, seckey} = :crypto.generate_key(:ecdh, :secp256k1)
    {seckey, pubkey}
  end

  @impl Noise.Crypto.DH
  def dh({seckey, _pubkey}, pubkey) do
    :crypto.compute_key(:ecdh, pubkey, seckey, :secp256k1)
  end
end
