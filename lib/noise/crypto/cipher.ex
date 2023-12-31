defmodule Noise.Crypto.Cipher do
  alias Noise.Crypto.Cipher

  @type key() :: <<_::32, _::_*8>>
  @type nonce() :: integer()

  @callback encrypt(k :: key(), n :: nonce(), ad :: binary(), plain_text :: binary()) ::
              cipher_text :: binary()
  @callback decrypt(k :: key(), n :: nonce(), ad :: binary(), cipher_text :: binary()) ::
              (plain_text :: binary()) | :error
  @callback rekey(key :: key()) :: key()

  def max_nonce, do: Integer.pow(2, 64) - 1

  defmacro __using__(_opts) do
    quote do
      @behaviour Cipher

      def rekey(k) do
        encrypt(k, Cipher.max_nonce(), <<>>, <<0x00::256>>)
      end

      defoverridable(rekey: 1)
    end
  end
end
