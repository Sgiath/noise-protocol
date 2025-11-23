defmodule NoiseTest.Crypto.DH.X448 do
  use ExUnit.Case, async: true

  alias Noise.Crypto.DH.X448

  test "dhlen is 56" do
    assert X448.dhlen() == 56
  end

  test "generate_keypair returns 56-byte keys" do
    {priv, pub} = X448.generate_keypair()
    assert byte_size(priv) == 56
    assert byte_size(pub) == 56
  end

  test "dh exchange works" do
    alice = X448.generate_keypair()
    bob = X448.generate_keypair()
    {_alice_priv, alice_pub} = alice
    {_bob_priv, bob_pub} = bob

    s1 = X448.dh(alice, bob_pub)
    s2 = X448.dh(bob, alice_pub)

    assert s1 == s2
    assert byte_size(s1) == 56
  end
end

