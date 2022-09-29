defmodule Noise.Crypto.DH.X25519 do
  use Noise.Crypto.DH

  @impl Noise.Crypto.DH
  def dhlen, do: 32

  @impl Noise.Crypto.DH
  def generate_keypair do
    {pubkey, seckey} = :crypto.generate_key(:ecdh, :x25519)
    {seckey, pubkey}
  end

  @impl Noise.Crypto.DH
  def dh({seckey, _pubkey}, pubkey) do
    :crypto.compute_key(:ecdh, pubkey, seckey, :x25519)
  end
end
