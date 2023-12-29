defmodule Noise.SymmetricState do
  @moduledoc false

  alias Noise.CipherState
  alias Noise.Protocol

  @enforce_keys [:protocol, :cipher_state]
  defstruct [:protocol, :ck, :h, :cipher_state]

  def initialize(%Protocol{name: protocol_name, hashlen: hashlen} = protocol)
      when byte_size(protocol_name) <= hashlen do
    s = 8 * (hashlen - byte_size(protocol_name))

    do_init(protocol, <<protocol_name::binary, 0x00::size(s)>>)
  end

  def initialize(%Protocol{name: protocol_name} = protocol) do
    do_init(protocol, Protocol.hash(protocol, protocol_name))
  end

  def mix_key(%__MODULE__{protocol: protocol} = state, input_key_material) do
    {ck, <<temp_k::binary-size(32), _rest::binary>>} =
      Protocol.hkdf(protocol, state.ck, input_key_material, 2)

    state
    |> Map.put(:ck, ck)
    |> Map.update!(:cipher_state, &CipherState.initialize_key(&1, temp_k))
  end

  def mix_hash(%__MODULE__{protocol: protocol, h: h} = state, data) do
    Map.put(state, :h, Protocol.hash(protocol, h <> data))
  end

  def mix_key_and_hash(%__MODULE__{protocol: protocol} = state, input_key_material) do
    {ck, temp_h, <<temp_k::binary-size(32), _rest::binary>>} =
      Protocol.hkdf(protocol, state.ck, input_key_material, 3)

    state
    |> Map.put(:ck, ck)
    |> mix_hash(temp_h)
    |> Map.update!(:cipher_state, &CipherState.initialize_key(&1, temp_k))
  end

  def get_handshake_hash(%__MODULE__{h: h}), do: h

  def encrypt_and_hash(%__MODULE__{} = state, plain_text) do
    {cipher_text, cipher_state} =
      CipherState.encrypt_with_ad(state.cipher_state, state.h, plain_text)

    state =
      state
      |> Map.put(:cipher_state, cipher_state)
      |> mix_hash(cipher_text)

    {cipher_text, state}
  end

  def decrypt_and_hash(%__MODULE__{} = state, cipher_text) do
    {plain_text, cipher_state} =
      CipherState.decrypt_with_ad(state.cipher_state, state.h, cipher_text)

    state =
      state
      |> Map.put(:cipher_state, cipher_state)
      |> mix_hash(cipher_text)

    {plain_text, state}
  end

  def split(%__MODULE__{protocol: protocol, ck: ck} = state) do
    {<<temp_k1::binary-size(32), _rest1::binary>>, <<temp_k2::binary-size(32), _rest2::binary>>} =
      Protocol.hkdf(protocol, ck, <<>>, 2)

    c1 = CipherState.initialize(protocol)
    c2 = CipherState.initialize(protocol)

    {{CipherState.initialize_key(c1, temp_k1), CipherState.initialize_key(c2, temp_k2)}, state}
  end

  # internal

  defp do_init(protocol, h) do
    %__MODULE__{
      protocol: protocol,
      cipher_state: CipherState.initialize(protocol),
      h: h,
      ck: h
    }
  end

  def has_key?(%__MODULE__{cipher_state: cs}) do
    CipherState.has_key?(cs)
  end
end

defimpl Inspect, for: Noise.SymmetricState do
  alias Noise.Utils

  def inspect(state, opts) do
    Inspect.Map.inspect(
      %{ck: Utils.hex(state.ck), h: Utils.hex(state.h), cipher_state: state.cipher_state},
      opts
    )
  end
end
