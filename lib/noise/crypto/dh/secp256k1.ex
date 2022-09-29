defmodule Noise.Crypto.DH.Secp256k1 do
  use Noise.Crypto.DH

  @dialyzer {:no_return, generate_keypair: 0, dh: 2}

  @impl Noise.Crypto.DH
  def dhlen, do: 33

  @impl Noise.Crypto.DH
  def generate_keypair do
    Secp256k1.keypair(:compressed)
  end

  @impl Noise.Crypto.DH
  def dh({seckey, _pubkey}, pubkey) do
    Secp256k1.ecdh(seckey, pubkey)
  end
end
