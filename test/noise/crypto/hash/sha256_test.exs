defmodule NoiseTest.Crypto.Hash.Sha256 do
  use ExUnit.Case, async: true

  alias Noise.Crypto.Hash.Sha256

  test "hashlen is 32" do
    assert Sha256.hashlen() == 32
  end

  test "hash returns correct length" do
    h = Sha256.hash("abc")
    assert byte_size(h) == 32
  end

  test "hmac_hash returns correct length" do
    h = Sha256.hmac_hash("key", "data")
    assert byte_size(h) == 32
  end

  test "hash empty string" do
    # known value for empty string sha256
    expected = Base.decode16!("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
    assert Sha256.hash("") == expected
  end
end

