defmodule Noise.Crypto.Cipher.ChaChaPoly do
  use Noise.Crypto.Cipher

  @impl Noise.Crypto.Cipher
  def encrypt(k, n, ad, plain_text) do
    :enacl.aead_chacha20poly1305_ietf_encrypt(plain_text, ad, nonce(n), k)
  end

  @impl Noise.Crypto.Cipher
  def decrypt(k, n, ad, cipher_text) do
    :enacl.aead_chacha20poly1305_ietf_decrypt(cipher_text, ad, nonce(n), k)
  end

  defp nonce(n), do: <<0::32, n::little-unsigned-integer-64>>
end
