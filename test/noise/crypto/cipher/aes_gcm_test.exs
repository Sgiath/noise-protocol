defmodule NoiseTest.Crypto.Cipher.AESGCM do
  use ExUnit.Case, async: true

  alias Noise.Crypto.Cipher.AESGCM

  test "round trip encryption/decryption" do
    k = :crypto.strong_rand_bytes(32)
    n = 0
    ad = "associated data"
    plain_text = "hello world"

    cipher_text = AESGCM.encrypt(k, n, ad, plain_text)
    assert byte_size(cipher_text) == byte_size(plain_text) + 16

    decrypted = AESGCM.decrypt(k, n, ad, cipher_text)
    assert decrypted == plain_text
  end

  test "decrypt fails with wrong key" do
    k = :crypto.strong_rand_bytes(32)
    wrong_k = :crypto.strong_rand_bytes(32)
    n = 0
    ad = ""
    plain_text = "hello"

    cipher_text = AESGCM.encrypt(k, n, ad, plain_text)
    assert AESGCM.decrypt(wrong_k, n, ad, cipher_text) == :error
  end

  test "decrypt fails with wrong ad" do
    k = :crypto.strong_rand_bytes(32)
    n = 0
    ad = "ad1"
    plain_text = "hello"

    cipher_text = AESGCM.encrypt(k, n, ad, plain_text)
    assert AESGCM.decrypt(k, n, "ad2", cipher_text) == :error
  end
end

