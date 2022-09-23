defmodule Noise.Crypto.Hash do
  @type hash() :: <<_::32, _::_*8>> | <<_::64, _::_*8>>

  @callback hashlen() :: 32 | 64
  @callback hash(data :: binary()) :: hash()
  @callback hmac_hash(key :: <<_::32, _::_*8>>, data :: binary()) :: hash()
  @callback hkdf(
              chaining_key :: hash(),
              input_key_material :: <<>> | hash(),
              num_outputs :: 2 | 3
            ) ::
              {output1 :: hash(), output2 :: hash()}
              | {output1 :: hash(), output2 :: hash(), output3 :: hash()}

  defmacro __using__(_opts) do
    quote do
      @behaviour Noise.Crypto.Hash

      def hkdf(chaining_key, input_key_material, 2) do
        temp_key = hmac_hash(chaining_key, input_key_material)
        output1 = hmac_hash(temp_key, <<0x01::8>>)
        output2 = hmac_hash(temp_key, <<output1::binary, 0x02::8>>)
        {output1, output2}
      end

      def hkdf(chaining_key, input_key_material, 3) do
        temp_key = hmac_hash(chaining_key, input_key_material)
        output1 = hmac_hash(temp_key, <<0x01::8>>)
        output2 = hmac_hash(temp_key, <<output1::binary, 0x02::8>>)
        output3 = hmac_hash(temp_key, <<output2::binary, 0x03::8>>)
        {output1, output2, output3}
      end
    end
  end
end
