defmodule Noise.Crypto.Cipher.ChaChaPoly do
  use Noise.Crypto.Cipher

  @impl Noise.Crypto.Cipher
  def encrypt(k, n, ad, plaintext) do
    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:chacha20_poly1305, k, nonce(n), plaintext, ad, true)

    ciphertext <> tag
  end

  @impl Noise.Crypto.Cipher
  def decrypt(k, n, ad, ciphertext) do
    :crypto.crypto_one_time_aead(:chacha20_poly1305, k, nonce(n), ciphertext, ad, false)
  end

  defp nonce(n), do: <<0::32, n::little-unsigned-integer-64>>
end
