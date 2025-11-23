defmodule NoiseTest.Crypto.Hash.Blake2s do
  use ExUnit.Case, async: true

  alias Noise.Crypto.Hash.Blake2s

  test "hashlen is 32" do
    assert Blake2s.hashlen() == 32
  end

  test "hash returns correct length" do
    h = Blake2s.hash("abc")
    assert byte_size(h) == 32
  end

  test "hmac_hash returns correct length" do
    h = Blake2s.hmac_hash("key", "data")
    assert byte_size(h) == 32
  end
end
