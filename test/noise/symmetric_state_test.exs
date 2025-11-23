defmodule NoiseTest.SymmetricState do
  use ExUnit.Case, async: true

  alias Noise.SymmetricState
  alias Noise.Protocol
  alias Noise.CipherState

  setup do
    protocol = Protocol.from_name("Noise_NN_25519_ChaChaPoly_BLAKE2b")
    {:ok, protocol: protocol}
  end

  test "initialize sets h and ck to protocol name (padded)", %{protocol: protocol} do
    state = SymmetricState.initialize(protocol)
    
    assert byte_size(state.h) == protocol.hashlen
    assert byte_size(state.ck) == protocol.hashlen
    
    # Protocol name is < 32 chars, so it should be padded with zeros to hashlen (64 for blake2b)
    # Wait, protocol name is "Noise_NN_25519_ChaChaPoly_BLAKE2b" (length 34)
    # hashlen for BLAKE2b is 64.
    
    # Check if first bytes match protocol name
    name_len = byte_size(protocol.name)
    <<name::binary-size(name_len), _rest::binary>> = state.h
    assert name == protocol.name
  end

  test "mix_hash updates h", %{protocol: protocol} do
    state = SymmetricState.initialize(protocol)
    h_orig = state.h
    
    state = SymmetricState.mix_hash(state, "data")
    assert state.h != h_orig
    assert byte_size(state.h) == protocol.hashlen
  end

  test "mix_key updates ck and cipher_state", %{protocol: protocol} do
    state = SymmetricState.initialize(protocol)
    ck_orig = state.ck
    
    # CipherState initially has no key
    refute SymmetricState.has_key?(state)
    
    input_key = <<0::256>>
    state = SymmetricState.mix_key(state, input_key)
    
    assert state.ck != ck_orig
    assert SymmetricState.has_key?(state)
  end

  test "encrypt_and_hash updates h and returns ciphertext", %{protocol: protocol} do
    state = SymmetricState.initialize(protocol)
    input_key = <<0::256>>
    state = SymmetricState.mix_key(state, input_key)
    
    h_orig = state.h
    plaintext = "hello"
    
    {ciphertext, state_next} = SymmetricState.encrypt_and_hash(state, plaintext)
    
    assert ciphertext != plaintext
    # ChaChaPoly adds 16 byte tag
    assert byte_size(ciphertext) == byte_size(plaintext) + 16
    assert state_next.h != h_orig
  end

  test "decrypt_and_hash updates h and returns plaintext", %{protocol: protocol} do
    state = SymmetricState.initialize(protocol)
    input_key = <<0::256>>
    state = SymmetricState.mix_key(state, input_key)
    
    {ciphertext, state_send} = SymmetricState.encrypt_and_hash(state, "hello")
    
    # Reset state for receiver (needs same keys)
    state_recv = state 
    
    {plaintext, state_recv_next} = SymmetricState.decrypt_and_hash(state_recv, ciphertext)
    
    assert plaintext == "hello"
    assert state_recv_next.h == state_send.h
  end

  test "split returns two cipher states", %{protocol: protocol} do
    state = SymmetricState.initialize(protocol)
    input_key = <<0::256>>
    state = SymmetricState.mix_key(state, input_key)
    
    {{cs1, cs2}, _state} = SymmetricState.split(state)
    
    assert %CipherState{} = cs1
    assert %CipherState{} = cs2
    assert CipherState.has_key?(cs1)
    assert CipherState.has_key?(cs2)
  end
end

