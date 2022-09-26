defmodule Noise.Crypto do
  def cipher(:aes_gcm), do: Noise.Crypto.Cipher.AESGCM
  def cipher(:chacha20_poly1305), do: Noise.Crypto.Cipher.ChaCha20Poly1305

  def dh(:x25519), do: Noise.Crypto.DH.X25519
  def dh(:x448), do: Noise.Crypto.DH.X448
  def dh(:secp256k1), do: Noise.Crypto.DH.Secp256k1

  def hash(:sha256), do: Noise.Crypto.Hash.Sha256
  def hash(:sha512), do: Noise.Crypto.Hash.Sha512
  def hash(:brake2b), do: Noise.Crypto.Hash.Blake2b
  def hash(:brake2s), do: Noise.Crypto.Hash.Blake2s
end
