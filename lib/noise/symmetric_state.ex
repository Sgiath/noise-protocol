defmodule Noise.SymmetricState do
  alias Noise.CipherState

  @enforce_keys [:type, :hashlen, :cipher_state]
  defstruct [:type, :hashlen, :ck, :h, :cipher_state]

  def initialize_symmetric(%__MODULE__{hashlen: hashlen} = state, protocol_name)
      when byte_size(protocol_name) <= hashlen do
    s = 8 * (hashlen - byte_size(protocol_name))

    do_init(state, <<protocol_name::binary, 0x00::size(s)>>)
  end

  def initialize_symmetric(%__MODULE__{type: type} = state, protocol_name) do
    do_init(state, type.hash(protocol_name))
  end

  def mix_key(%__MODULE__{type: type} = state, input_key_material) do
    {ck, <<temp_k::binary-size(32), _rest::binary>>} = type.hkdf(state.ck, input_key_material, 2)

    state
    |> Map.put(:ck, ck)
    |> Map.update!(:cipher_state, &CipherState.initialize_key(&1, temp_k))
  end

  def mix_hash(%__MODULE__{type: type, h: h} = state, data) do
    Map.put(state, :h, type.hash(h <> data))
  end

  def mix_key_and_hash(%__MODULE__{type: type} = state, input_key_material) do
    {ck, temp_h, <<temp_k::binary-size(32), _rest::binary>>} =
      type.hkdf(state.ck, input_key_material, 3)

    state
    |> Map.put(:ck, ck)
    |> mix_hash(temp_h)
    |> Map.update!(:cipher_state, &CipherState.initialize_key(&1, temp_k))
  end

  def get_handshake_hash(%__MODULE__{h: h}), do: h

  def encrypt_and_hash(%__MODULE__{} = state, plaintext) do
    {ciphertext, cipher_state} =
      CipherState.encrypt_with_ad(state.cipher_state, state.h, plaintext)

    state =
      state
      |> Map.put(:cipher_state, cipher_state)
      |> mix_hash(ciphertext)

    {ciphertext, state}
  end

  def decrypt_and_hash(%__MODULE__{} = state, ciphertext) do
    {plaintext, cipher_state} =
      CipherState.decrypt_with_ad(state.cipher_state, state.h, ciphertext)

    state =
      state
      |> Map.put(:cipher_state, cipher_state)
      |> mix_hash(ciphertext)

    {plaintext, state}
  end

  def split(%__MODULE__{type: type, ck: ck, cipher_state: cipher_state} = state) do
    {<<temp_k1::binary-size(32), _rest1::binary>>, <<temp_k2::binary-size(32), _rest2::binary>>} =
      type.hkdf(ck, <<>>, 2)

    c1 = %CipherState{type: cipher_state.type}
    c2 = %CipherState{type: cipher_state.type}

    {{CipherState.initialize_key(c1, temp_k1), CipherState.initialize_key(c2, temp_k2)}, state}
  end

  # internal

  defp do_init(state, h) do
    state
    |> Map.put(:h, h)
    |> Map.put(:ck, h)
    |> Map.update!(:cipher_state, &CipherState.initialize_key(&1, nil))
  end
end
