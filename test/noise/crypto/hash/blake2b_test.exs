defmodule NoiseTest.Crypto.Hash.Blake2b do
  use ExUnit.Case, async: true

  alias Noise.Crypto.Hash.Blake2b

  test "hashlen is 64" do
    assert Blake2b.hashlen() == 64
  end

  test "hash returns correct length" do
    h = Blake2b.hash("abc")
    assert byte_size(h) == 64
  end

  test "hmac_hash returns correct length" do
    h = Blake2b.hmac_hash("key", "data")
    assert byte_size(h) == 64
  end
end

