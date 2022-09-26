defmodule Noise.Crypto.Cipher.AESGCM do
  use Noise.Crypto.Cipher

  @impl Noise.Crypto.Cipher
  def encrypt(k, n, ad, plaintext) do
    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, k, nonce(n), plaintext, ad, true)

    ciphertext <> tag
  end

  @impl Noise.Crypto.Cipher
  def decrypt(k, n, ad, ciphertext) do
    :crypto.crypto_one_time_aead(:aes_256_gcm, k, nonce(n), ciphertext, ad, false)
  end

  defp nonce(n), do: <<0::32, n::unsigned-integer-64>>
end
