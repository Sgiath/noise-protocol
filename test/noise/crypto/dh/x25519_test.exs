defmodule NoiseTest.Crypto.DH.X25519 do
  use ExUnit.Case, async: true

  alias Noise.Crypto.DH.X25519

  test "dhlen is 32" do
    assert X25519.dhlen() == 32
  end

  test "generate_keypair returns 32-byte keys" do
    {priv, pub} = X25519.generate_keypair()
    assert byte_size(priv) == 32
    assert byte_size(pub) == 32
  end

  test "dh exchange works" do
    alice = X25519.generate_keypair()
    bob = X25519.generate_keypair()
    {_alice_priv, alice_pub} = alice
    {_bob_priv, bob_pub} = bob

    s1 = X25519.dh(alice, bob_pub)
    s2 = X25519.dh(bob, alice_pub)

    assert s1 == s2
    assert byte_size(s1) == 32
  end
end

