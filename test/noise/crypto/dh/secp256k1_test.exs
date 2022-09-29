defmodule NoiseTest.Crypto.DH.Secp256k1 do
  use ExUnit.Case, async: true

  alias Noise.Crypto.DH

  doctest Noise.Crypto.DH.Secp256k1

  test "DH works?" do
    seckey = Base.decode16!("1212121212121212121212121212121212121212121212121212121212121212")
    pubkey = Base.decode16!("028D7500DD4C12685D1F568B4C2B5048E8534B873319F3A8DAA612B469132EC7F7")
    ecdh = Base.decode16!("1E2FB3C8FE8FB9F262F649F64D26ECF0F2C0A805A767CF02DC2D77A6EF1FDCC3")

    assert ecdh == DH.Secp256k1.dh({seckey, <<>>}, pubkey)
  end
end
