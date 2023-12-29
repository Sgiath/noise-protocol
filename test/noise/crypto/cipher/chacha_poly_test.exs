defmodule NoiseTest.Crypto.Cipher.ChachaPoly do
  use ExUnit.Case

  alias Noise.Crypto.Cipher.ChaChaPoly

  doctest ChaChaPoly

  test "encryption works" do
    k = Base.decode16!("E68F69B7F096D7917245F5E5CF8AE1595FEBE4D4644333C99F9C4A1282031C9F")
    n = 0x000000000000000000000000
    ad = Base.decode16!("9E0E7DE8BB75554F21DB034633DE04BE41A2B8A18DA7A319A03C803BF02B396C")
    plain_text = <<>>
    cipher_text = Base.decode16!("0DF6086551151F58B8AFE6C195782C6A")

    assert cipher_text == ChaChaPoly.encrypt(k, n, ad, plain_text)
  end
end
