defmodule NoiseTest.Crypto.Hash.Sha512 do
  use ExUnit.Case, async: true

  alias Noise.Crypto.Hash.Sha512

  test "hashlen is 64" do
    assert Sha512.hashlen() == 64
  end

  test "hash returns correct length" do
    h = Sha512.hash("abc")
    assert byte_size(h) == 64
  end

  test "hmac_hash returns correct length" do
    h = Sha512.hmac_hash("key", "data")
    assert byte_size(h) == 64
  end
end

