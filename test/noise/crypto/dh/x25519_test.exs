defmodule Noise.Crypto.DH.X25519Test do
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

  test "dh exchange agrees on both sides" do
    {_, alice_pub} = alice = X25519.generate_keypair()
    {_, bob_pub} = bob = X25519.generate_keypair()

    assert {:ok, shared} = X25519.dh(alice, bob_pub)
    assert {:ok, ^shared} = X25519.dh(bob, alice_pub)
    assert byte_size(shared) == 32
  end

  test "RFC 7748 §6.1 vector" do
    alice_priv =
      Base.decode16!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        case: :lower
      )

    bob_pub =
      Base.decode16!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        case: :lower
      )

    shared =
      Base.decode16!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        case: :lower
      )

    assert {:ok, ^shared} = X25519.dh({alice_priv, <<>>}, bob_pub)
  end

  test "low-order points are rejected" do
    keypair = X25519.generate_keypair()
    assert {:error, :invalid_public_key} = X25519.dh(keypair, <<0::256>>)
    assert {:error, :invalid_public_key} = X25519.dh(keypair, <<1, 0::248>>)
  end
end
