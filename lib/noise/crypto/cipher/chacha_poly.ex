defmodule Noise.Crypto.Cipher.ChaChaPoly do
  @moduledoc "ChaCha20-Poly1305 Cipher implementation."
  use Noise.Crypto.Cipher

  @impl Noise.Crypto.Cipher
  def encrypt(k, n, ad, plain_text) do
    {cipher_text, tag} =
      :crypto.crypto_one_time_aead(:chacha20_poly1305, k, nonce(n), plain_text, ad, true)

    cipher_text <> tag
  end

  @impl Noise.Crypto.Cipher
  def decrypt(k, n, ad, cipher_text) do
    cipher_len = byte_size(cipher_text) - 16
    <<cipher::binary-size(cipher_len), tag::binary-size(16)>> = cipher_text

    :crypto.crypto_one_time_aead(:chacha20_poly1305, k, nonce(n), cipher, ad, tag, false)
  end

  defp nonce(n), do: <<0::32, n::little-unsigned-integer-64>>
end
