defmodule NoiseTest.CipherState do
  use ExUnit.Case, async: true

  alias Noise.CipherState
  alias Noise.Protocol

  setup do
    protocol = Protocol.from_name("Noise_NN_25519_ChaChaPoly_BLAKE2b")
    {:ok, protocol: protocol}
  end

  test "initialization", %{protocol: protocol} do
    state = CipherState.initialize(protocol)
    assert state.protocol == protocol
    refute CipherState.has_key?(state)
  end

  test "initialize_key", %{protocol: protocol} do
    state = CipherState.initialize(protocol)
    key = <<0::256>>
    state = CipherState.initialize_key(state, key)

    assert CipherState.has_key?(state)
    assert state.k == key
    assert state.n == 0
  end

  test "encrypt_with_ad increments nonce", %{protocol: protocol} do
    state = CipherState.initialize(protocol)
    key = <<0::256>>
    state = CipherState.initialize_key(state, key)

    {_cipher, state_next} = CipherState.encrypt_with_ad(state, "", "plaintext")
    assert state_next.n == 1
    assert state_next.k == state.k
  end

  test "decrypt_with_ad increments nonce", %{protocol: protocol} do
    state = CipherState.initialize(protocol)
    key = <<0::256>>
    state = CipherState.initialize_key(state, key)

    # First encrypt to get valid ciphertext
    {ciphertext, state} = CipherState.encrypt_with_ad(state, "", "plaintext")

    # Reset nonce to 0 for decryption to match encryption
    state = CipherState.set_nonce(state, 0)

    {plaintext, state_next} = CipherState.decrypt_with_ad(state, "", ciphertext)
    assert plaintext == "plaintext"
    assert state_next.n == 1
  end

  test "passthrough when no key", %{protocol: protocol} do
    state = CipherState.initialize(protocol)
    # No key set

    {ciphertext, state_next} = CipherState.encrypt_with_ad(state, "ad", "plaintext")
    assert ciphertext == "plaintext"
    # State shouldn't change (nonce shouldn't increment)
    assert state_next == state

    {plaintext, state_next2} = CipherState.decrypt_with_ad(state, "ad", "ciphertext")
    assert plaintext == "ciphertext"
    assert state_next2 == state
  end

  test "rekey updates the key", %{protocol: protocol} do
    state = CipherState.initialize(protocol)
    key = <<0::256>>
    state = CipherState.initialize_key(state, key)

    state_rekeyed = CipherState.rekey(state)
    assert state_rekeyed.k != state.k
    assert byte_size(state_rekeyed.k) == 32
  end
end
