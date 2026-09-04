defmodule Noise.Crypto.DH.Secp256k1Test do
  use ExUnit.Case, async: true

  alias Noise.Crypto.DH.Secp256k1

  test "dhlen is 33 (compressed public keys)" do
    assert Secp256k1.dhlen() == 33
  end

  test "generate_keypair returns a 32-byte secret and a 33-byte compressed public key" do
    {priv, pub} = Secp256k1.generate_keypair()
    assert byte_size(priv) == 32
    assert <<prefix, _::binary-size(32)>> = pub
    assert prefix in [2, 3]
  end

  test "dh exchange agrees on both sides" do
    {_, alice_pub} = alice = Secp256k1.generate_keypair()
    {_, bob_pub} = bob = Secp256k1.generate_keypair()

    assert {:ok, shared} = Secp256k1.dh(alice, bob_pub)
    assert {:ok, ^shared} = Secp256k1.dh(bob, alice_pub)
    assert byte_size(shared) == 32
  end

  test "matches BOLT-8 (SHA256 of the compressed shared point)" do
    # Act One `ss` from the BOLT-8 initiator test vector
    seckey = Base.decode16!("1212121212121212121212121212121212121212121212121212121212121212")
    pubkey = Base.decode16!("028D7500DD4C12685D1F568B4C2B5048E8534B873319F3A8DAA612B469132EC7F7")
    shared = Base.decode16!("1E2FB3C8FE8FB9F262F649F64D26ECF0F2C0A805A767CF02DC2D77A6EF1FDCC3")

    assert {:ok, ^shared} = Secp256k1.dh({seckey, <<>>}, pubkey)
  end

  test "invalid points are rejected" do
    keypair = Secp256k1.generate_keypair()
    assert {:error, :invalid_public_key} = Secp256k1.dh(keypair, <<4, 0::256>>)
    assert {:error, :invalid_public_key} = Secp256k1.dh(keypair, <<2, 0::256>>)
  end
end
