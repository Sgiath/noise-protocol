defmodule Noise.Crypto.Cipher.ChaChaPoly do
  @moduledoc "ChaCha20-Poly1305 cipher (spec §12.3): 96-bit little-endian nonce, 16-byte tag appended."
  use Noise.Crypto.Cipher

  @impl Noise.Crypto.Cipher
  def encrypt(k, n, ad, plain_text) do
    {cipher_text, tag} =
      :crypto.crypto_one_time_aead(:chacha20_poly1305, k, nonce(n), plain_text, ad, true)

    <<cipher_text::binary, tag::binary>>
  end

  @impl Noise.Crypto.Cipher
  def decrypt(k, n, ad, cipher_text) when byte_size(cipher_text) >= 16 do
    cipher_len = byte_size(cipher_text) - 16
    <<cipher::binary-size(^cipher_len), tag::binary-size(16)>> = cipher_text

    :crypto.crypto_one_time_aead(:chacha20_poly1305, k, nonce(n), cipher, ad, tag, false)
  end

  def decrypt(_k, _n, _ad, _cipher_text), do: :error

  defp nonce(n), do: <<0::32, n::unsigned-little-integer-64>>
end
