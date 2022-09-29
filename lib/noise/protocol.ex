defmodule Noise.Protocol do
  @moduledoc false

  alias Noise.Pattern

  @enforce_keys [:name, :cipher, :dh, :dhlen, :hash, :hashlen, :pattern]
  defstruct [:name, :cipher, :dh, :dhlen, :hash, :hashlen, :pattern, :extensions]

  @type t() :: %__MODULE__{
          name: String.t(),
          cipher: module(),
          dh: module(),
          hash: module(),
          pattern: Pattern.t(),
          extensions: []
        }

  def from_name(protocol_name)
      when is_binary(protocol_name) and byte_size(protocol_name) <= 255 do
    protocol_name
    |> String.split("_")
    |> parse()
  end

  def from_name(protocol_name) do
    raise ArgumentError,
          "Protocol name has to be 255 or less bytes long string. Got: #{protocol_name}"
  end

  # DH functions
  def generate_keypair(%__MODULE__{dh: dh}), do: dh.generate_keypair()
  def dh(%__MODULE__{dh: dh}, keypair, pubkey), do: dh.dh(keypair, pubkey)

  # Cipher
  def encrypt(%__MODULE__{cipher: cipher}, k, n, ad, plaintext),
    do: cipher.encrypt(k, n, ad, plaintext)

  def decrypt(%__MODULE__{cipher: cipher}, k, n, ad, ciphertext),
    do: cipher.decrypt(k, n, ad, ciphertext)

  def rekey(%__MODULE__{cipher: cipher}, key), do: cipher.rekey(key)

  # Hash
  def hash(%__MODULE__{hash: hash}, data), do: hash.hash(data)
  def hkdf(%__MODULE__{hash: hash}, ck, ik, n), do: hash.hkdf(ck, ik, n)

  # internal API

  defp parse(["Noise", pattern, dh, cipher, hash]) do
    %__MODULE__{
      name: "Noise_#{pattern}_#{dh}_#{cipher}_#{hash}",
      cipher: parse_cipher(cipher),
      dh: parse_dh(dh),
      dhlen: parse_dh(dh).dhlen(),
      hash: parse_hash(hash),
      hashlen: parse_hash(hash).hashlen(),
      pattern: Pattern.from_name(pattern),
      extensions: []
    }
  end

  defp parse(name) do
    raise ArgumentError, "Invalid protocol name #{name}"
  end

  defp parse_dh("secp256k1"), do: Noise.Crypto.DH.Secp256k1
  defp parse_dh("448"), do: Noise.Crypto.DH.X448
  defp parse_dh("25519"), do: Noise.Crypto.DH.X25519
  defp parse_dh(dh), do: raise(ArgumentError, "Unsupported DH type: #{dh}")

  defp parse_cipher("AESGCM"), do: Noise.Crypto.Cipher.AESGCM
  defp parse_cipher("ChaChaPoly"), do: Noise.Crypto.Cipher.ChaChaPoly
  defp parse_cipher(cipher), do: raise("Unsupported Cipher type: #{cipher}")

  defp parse_hash("SHA256"), do: Noise.Crypto.Hash.Sha256
  defp parse_hash("SHA512"), do: Noise.Crypto.Hash.Sha512
  defp parse_hash("SHA3/256"), do: Noise.Crypto.Hash.Sha3_256
  defp parse_hash("SHA3/512"), do: Noise.Crypto.Hash.Sha3_512
  defp parse_hash("BLAKE2s"), do: Noise.Crypto.Hash.Blake2s
  defp parse_hash("BLAKE2b"), do: Noise.Crypto.Hash.Blake2b
  defp parse_hash(hash), do: raise(ArgumentError, "Unsupported Hash type: #{hash}")
end
