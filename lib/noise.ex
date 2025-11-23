defmodule Noise do
  @moduledoc """
  The entry point for the Noise Protocol Framework.

  This module serves as the primary interface for the Noise library, allowing users to:
  1.  Define protocols using standard Noise strings.
  2.  Initialize and manage handshake state machines.
  3.  Perform encryption and decryption of transport messages.

  ## What is Noise?

  Noise is a framework for crypto protocols based on Diffie-Hellman key agreement.
  It allows you to describe a protocol by a simple name string (e.g., `Noise_IK_25519_ChaChaPoly_BLAKE2s`)
  which determines the handshake pattern and cryptographic primitives used.

  ## Supported Primitives

  This implementation supports the following primitives as defined in the specification:

  *   **Cipher**: [AES-GCM](`Noise.Crypto.Cipher.AESGCM`), [ChaChaPoly](`Noise.Crypto.Cipher.ChaChaPoly`)
  *   **Diffie-Hellman**: [25519](`Noise.Crypto.DH.X25519`), [448](`Noise.Crypto.DH.X448`), [secp256k1](`Noise.Crypto.DH.Secp256k1`)
  *   **Hash**: [SHA256](`Noise.Crypto.Hash.Sha256`), [SHA512](`Noise.Crypto.Hash.Sha512`), [Blake2b](`Noise.Crypto.Hash.Blake2b`), [Blake2s](`Noise.Crypto.Hash.Blake2s`)

  ## Usage

  The typical workflow involves selecting a protocol, generating keys, and running the handshake.

  ### 1. Protocol Instantiation

  Use `Noise.protocol/1` to create a protocol struct from a name string.

  ```elixir
  protocol = Noise.protocol("Noise_IK_25519_ChaChaPoly_BLAKE2s")
  ```

  ### 2. Key Generation

  Generate a keypair appropriate for the protocol's DH function. The keypair is returned as `{private_key, public_key}`.

  ```elixir
  client_kp = Noise.generate_keypair(protocol)
  # {client_priv, client_pub} = client_kp
  ```

  ### 3. Handshake Initialization

  Start the handshake by creating a `Noise.HandshakeState`. You must specify whether you are the `initiator` or `responder`.
  Depending on the handshake pattern (e.g., `IK`, `XX`, `NN`), you may need to provide:
    * `:s` - Your local static keypair.
    * `:rs` - The remote party's static public key.
    * `:psks` - A list of pre-shared keys (for patterns with `psk` modifier).

  ```elixir
  # Initiator (knows responder's public key `server_pub`)
  initiator = Noise.handshake(protocol, true, <<>>, s: client_kp, rs: server_pub)

  # Responder (authenticates with its own keypair)
  responder = Noise.handshake(protocol, false, <<>>, s: server_kp)
  ```

  ### 4. The Handshake Loop

  Exchange messages using `Noise.handshake_step/2`. This function handles both reading and writing.
  It returns `{:ok, message, new_state}` for intermediate steps, and `{:complete, message, split_states}`
  when the handshake is finished.

  ```elixir
  # --- Step 1 ---
  # Initiator writes the first message
  {:ok, msg1, initiator} = Noise.handshake_step(initiator, "Client Hello")

  # Responder reads the message
  {:ok, "Client Hello", responder} = Noise.handshake_step(responder, msg1)

  # ... Continue for subsequent steps ...
  ```

  ### 5. Transport Phase

  When the handshake completes, it returns a pair of `Noise.CipherState` objects:
  one for sending (encrypting) and one for receiving (decrypting).

  ```elixir
  # Upon completion:
  {:complete, final_msg, {send_cipher, recv_cipher}} = Noise.handshake_step(initiator, inbound_msg)
  ```

  You can now securely exchange data:

  ```elixir
  # Encrypt
  {ciphertext, new_send_cipher} = Noise.encrypt(send_cipher, "My Secret Data")

  # Decrypt
  {plaintext, new_recv_cipher} = Noise.decrypt(recv_cipher, ciphertext)
  ```
  """

  alias Noise.Protocol
  alias Noise.HandshakeState
  alias Noise.Handshake
  alias Noise.CipherState

  @typedoc "The Noise protocol name string, e.g. 'Noise_IK_25519_ChaChaPoly_BLAKE2s'"
  @type protocol_name :: String.t()

  @typedoc "A keypair represented as {private_key, public_key} binaries"
  @type keypair :: {binary(), binary()}

  @typedoc "A symmetric key as a binary"
  @type key :: binary()

  @typedoc "Noise handshake state (see `Noise.HandshakeState`)"
  @type handshake_state :: HandshakeState.t()

  @typedoc "Noise cipher state (see `Noise.CipherState`)"
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
  @spec handshake(Protocol.t() | protocol_name(), boolean(), binary(), keyword()) ::
          handshake_state()
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
