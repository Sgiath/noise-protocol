defmodule Noise.Crypto.DH do
  @moduledoc """
  Behaviour for Diffie-Hellman functions (spec §4.1).

  `dh/2` returns `{:error, :invalid_public_key}` for a remote public key that
  the underlying library rejects (wrong encoding, point not on the curve, or
  a low-order point producing an all-zero shared secret). Signalling this as
  an error is explicitly permitted by spec §12.1/§12.2.
  """

  @type seckey() :: binary()
  @type pubkey() :: binary()
  @type keypair() :: {seckey(), pubkey()}
  @type shared_secret() :: binary()

  @callback dhlen() :: pos_integer()
  @callback generate_keypair() :: keypair()
  @callback dh(keypair(), pubkey()) :: {:ok, shared_secret()} | {:error, :invalid_public_key}
end
