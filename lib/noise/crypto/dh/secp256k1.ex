defmodule Noise.Crypto.DH.Secp256k1 do
  @moduledoc "Secp256k1 Diffie-Hellman implementation."
  use Noise.Crypto.DH

  @dialyzer {:no_return, generate_keypair: 0, dh: 2}

  @impl Noise.Crypto.DH
  def dhlen, do: 33

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
