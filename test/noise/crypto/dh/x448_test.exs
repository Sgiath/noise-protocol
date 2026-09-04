defmodule Noise.Crypto.DH.X448Test do
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

  test "dh exchange agrees on both sides" do
    {_, alice_pub} = alice = X448.generate_keypair()
    {_, bob_pub} = bob = X448.generate_keypair()

    assert {:ok, shared} = X448.dh(alice, bob_pub)
    assert {:ok, ^shared} = X448.dh(bob, alice_pub)
    assert byte_size(shared) == 56
  end

  test "low-order points are rejected" do
    assert {:error, :invalid_public_key} = X448.dh(X448.generate_keypair(), <<0::448>>)
  end
end
