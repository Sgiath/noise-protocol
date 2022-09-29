defmodule Noise.Crypto.DH do
  @type pubkey() :: <<_::_*8>>
  @type keypair() :: {<<_::_*8>>, pubkey()}

  @callback dhlen() :: 32 | 33 | 56
  @callback generate_keypair() :: keypair()
  @callback dh(keypair(), pubkey()) :: <<_::_*8>>

  defmacro __using__(_opts) do
    quote do
      @behaviour Noise.Crypto.DH
    end
  end
end
