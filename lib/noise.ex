defmodule Noise do
  @moduledoc """
  Noise Protocol Framework.

  This module provides the public API for interacting with the Noise protocol implementation.
  It allows you to initialize handshakes, process handshake messages, and perform encryption/decryption
  using the established sessions.

  ## Example

      # Initiator
      protocol = Noise.protocol("Noise_IK_25519_ChaChaPoly_BLAKE2s")
      kp_i = Noise.generate_keypair(protocol)
      state_i = Noise.handshake(protocol, true, <<>>, s: kp_i, rs: kp_r_pub)

      # Responder
      state_r = Noise.handshake(protocol, false, <<>>, s: kp_r)

      # Handshake step 1 (Initiator writes)
      {:ok, msg1, state_i} = Noise.handshake_step(state_i, "payload1")

      # Handshake step 1 (Responder reads)
      {:ok, "payload1", state_r} = Noise.handshake_step(state_r, msg1)

      # ... continue until split ...
  """

  alias Noise.Protocol
  alias Noise.HandshakeState
  alias Noise.Handshake
  alias Noise.CipherState

  @type protocol_name :: String.t()
  @type keypair :: {binary(), binary()}
  @type key :: binary()
  @type handshake_state :: HandshakeState.t()
  @type cipher_state :: CipherState.t()

  @doc """
  Parses a protocol name string into a `Noise.Protocol` struct.
  """
  @spec protocol(protocol_name()) :: Protocol.t()
  def protocol(name), do: Protocol.from_name(name)

  @doc """
  Generates a keypair for the given protocol.
  """
  @spec generate_keypair(Protocol.t()) :: keypair()
  def generate_keypair(%Protocol{} = protocol) do
    Protocol.generate_keypair(protocol)
  end

  @doc """
  Initializes a handshake state.

  ## Arguments
  * `protocol` - A `Noise.Protocol` struct or protocol name string.
  * `initiator` - Boolean, `true` if this party is the initiator, `false` otherwise.
  * `prologue` - (Optional) Prologue data, defaults to empty binary.
  * `opts` - Keyword list of options:
    * `:s` - Local static keypair `{priv, pub}`.
    * `:rs` - Remote static public key.
    * `:e` - Local ephemeral keypair (usually generated automatically, provided for testing/determinism).
    * `:re` - Remote ephemeral public key.
    * `:psks` - List of pre-shared keys.
  """
  @spec handshake(Protocol.t() | protocol_name(), boolean(), binary(), keyword()) :: handshake_state()
  def handshake(protocol, initiator, prologue \\ <<>>, opts \\ []) do
    s = Keyword.get(opts, :s)
    rs = Keyword.get(opts, :rs)
    e = Keyword.get(opts, :e)
    re = Keyword.get(opts, :re)
    psks = Keyword.get(opts, :psks, [])

    HandshakeState.initialize(protocol, initiator, prologue, s, rs, e, re, psks)
  end

  @doc """
  Advances the handshake state machine.

  If the current turn is to **write** a message, `data` should be the plaintext payload to send.
  If the current turn is to **read** a message, `data` should be the received ciphertext.

  Returns:
  * `{:ok, message, new_state}` - The handshake continues. `message` is the ciphertext to send (if writing) or the decrypted payload (if reading).
  * `{:complete, message, {cs1, cs2}}` - The handshake is completed with this step. `message` is the final output, and `{cs1, cs2}` are the split CipherStates.
  * `{:split, {cs1, cs2}}` - The handshake was already ready to split (called on a state with no remaining patterns).
  """
  @spec handshake_step(handshake_state(), binary()) ::
          {:ok, binary(), handshake_state()}
          | {:complete, binary(), {cipher_state(), cipher_state()}}
          | {:split, {cipher_state(), cipher_state()}}
  def handshake_step(state, data \\ <<>>) do
    case Handshake.next_step(state, data) do
      {{%CipherState{}, %CipherState{}} = split_states, _state} ->
        {:split, split_states}

      {msg, %HandshakeState{message_patterns: []} = new_state} when is_binary(msg) ->
        {{c1, c2}, _} = HandshakeState.finalize(new_state)
        {:complete, msg, {c1, c2}}

      {msg, new_state} when is_binary(msg) ->
        {:ok, msg, new_state}
    end
  end

  @doc """
  Encrypts data using the given CipherState.

  Returns `{ciphertext, new_cipher_state}`.
  Updates the nonce in the CipherState.
  """
  @spec encrypt(cipher_state(), binary(), binary()) :: {binary(), cipher_state()}
  def encrypt(cipher_state, plain_text, ad \\ <<>>) do
    CipherState.encrypt_with_ad(cipher_state, ad, plain_text)
  end

  @doc """
  Decrypts data using the given CipherState.

  Returns `{plaintext, new_cipher_state}`.
  Updates the nonce in the CipherState.
  """
  @spec decrypt(cipher_state(), binary(), binary()) :: {binary(), cipher_state()}
  def decrypt(cipher_state, cipher_text, ad \\ <<>>) do
    CipherState.decrypt_with_ad(cipher_state, ad, cipher_text)
  end

  @doc """
  Rekey the CipherState.
  """
  @spec rekey(cipher_state()) :: cipher_state()
  def rekey(cipher_state) do
    CipherState.rekey(cipher_state)
  end
end
