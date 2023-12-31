defmodule Noise.Crypto.Cipher.AESGCM do
  use Noise.Crypto.Cipher

  @impl Noise.Crypto.Cipher
  def encrypt(k, n, ad, plain_text) do
    {cipher_text, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, k, nonce(n), plain_text, ad, true)

    cipher_text <> tag
  end

  @impl Noise.Crypto.Cipher
  def decrypt(k, n, ad, cipher_text) do
    :crypto.crypto_one_time_aead(:aes_256_gcm, k, nonce(n), cipher_text, ad, false)
  end

  defp nonce(n), do: <<0::32, n::unsigned-integer-64>>
end
