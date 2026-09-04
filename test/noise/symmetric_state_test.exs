defmodule Noise.SymmetricStateTest do
  use ExUnit.Case, async: true

  alias Noise.CipherState
  alias Noise.Protocol
  alias Noise.SymmetricState

  setup do
    protocol = Protocol.from_name("Noise_NN_25519_ChaChaPoly_BLAKE2b")
    keyed = protocol |> SymmetricState.initialize() |> SymmetricState.mix_key(<<0::256>>)
    {:ok, protocol: protocol, keyed: keyed}
  end

  test "short protocol name is zero-padded into h (spec §5.2)", %{protocol: protocol} do
    h = protocol |> SymmetricState.initialize() |> SymmetricState.handshake_hash()
    name_len = byte_size(protocol.name)
    padding = (protocol.hashlen - name_len) * 8

    assert h == <<protocol.name::binary, 0::size(padding)>>
  end

  test "protocol name longer than HASHLEN is hashed into h (spec §5.2)" do
    protocol = Protocol.from_name("Noise_XXpsk0+psk1+psk2+psk3_25519_ChaChaPoly_SHA256")
    assert byte_size(protocol.name) > 32

    h = protocol |> SymmetricState.initialize() |> SymmetricState.handshake_hash()
    assert h == :crypto.hash(:sha256, protocol.name)
  end

  test "mix_hash changes h", %{protocol: protocol} do
    state = SymmetricState.initialize(protocol)

    assert SymmetricState.handshake_hash(SymmetricState.mix_hash(state, "data")) !=
             SymmetricState.handshake_hash(state)
  end

  test "mix_key installs a cipher key", %{protocol: protocol, keyed: keyed} do
    refute SymmetricState.has_key?(SymmetricState.initialize(protocol))
    assert SymmetricState.has_key?(keyed)
  end

  test "encrypt_and_hash / decrypt_and_hash round-trip and agree on h", %{keyed: state} do
    {:ok, ciphertext, sender} = SymmetricState.encrypt_and_hash(state, "hello")
    assert byte_size(ciphertext) == 5 + 16

    {:ok, "hello", receiver} = SymmetricState.decrypt_and_hash(state, ciphertext)
    assert SymmetricState.handshake_hash(sender) == SymmetricState.handshake_hash(receiver)
  end

  test "decrypt_and_hash failure leaves the state untouched", %{keyed: state} do
    {:ok, ciphertext, _} = SymmetricState.encrypt_and_hash(state, "hello")
    tampered = <<0>> <> binary_part(ciphertext, 1, byte_size(ciphertext) - 1)

    assert {:error, :decrypt_failed} = SymmetricState.decrypt_and_hash(state, tampered)
    assert {:ok, "hello", _} = SymmetricState.decrypt_and_hash(state, ciphertext)
  end

  test "split returns two keyed cipher states", %{keyed: state} do
    {cs1, cs2} = SymmetricState.split(state)
    assert CipherState.has_key?(cs1)
    assert CipherState.has_key?(cs2)
    assert cs1 != cs2
  end
end
