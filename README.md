# Noise Protocol

[![Hex.pm](https://img.shields.io/hexpm/v/noise_protocol.svg?style=flat&color=blue)](https://hex.pm/packages/noise_protocol)
[![Docs](https://img.shields.io/badge/api-docs-green.svg?style=flat)](https://hexdocs.pm/noise_protocol)

Elixir implementation of [Noise Protocol Framework](https://noiseprotocol.org/noise.html).

## Project Goals

The main goal of this project is to provide a complete and correct implementation of the Noise Protocol Framework in Elixir. It aims to:

- Follow the [Noise Protocol Specification](https://noiseprotocol.org/noise.html) precisely.
- Offer a flexible and easy-to-use API for building secure network protocols.
- Support a wide range of cryptographic primitives as defined in the spec.

## Project Status

The project currently implements the core Noise protocol framework with support for the following primitives:

- **Cipher Functions**: AESGCM, ChaChaPoly
- **Diffie-Hellman Functions**: X25519, X448, Secp256k1
- **Hash Functions**: SHA256, SHA512, BLAKE2s, BLAKE2b

It supports the standard handshake patterns and can be used to establish secure channels.

## Quick Installation

Add `noise_protocol` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:noise_protocol, "~> 0.2.0"}
  ]
end
```

## Usage Guide

Here is a basic example of how to perform a handshake using the `Noise_IK_25519_ChaChaPoly_BLAKE2s` protocol.

### Initiator

```elixir
# 1. Select the protocol
protocol = Noise.protocol("Noise_IK_25519_ChaChaPoly_BLAKE2s")

# 2. Generate keys (or load them)
kp_i = Noise.generate_keypair(protocol)
# Assuming we know the responder's static public key `kp_r_pub`

# 3. Initialize handshake state
# :s  -> Local static keypair
# :rs -> Remote static public key
state_i = Noise.handshake(protocol, true, <<>>, s: kp_i, rs: kp_r_pub)

# 4. Perform handshake step (Initiator starts in IK pattern)
# Write the first message
{:ok, msg1, state_i} = Noise.handshake_step(state_i, "payload1")

# Send `msg1` to the responder...
```

### Responder

```elixir
# 1. Select the protocol
protocol = Noise.protocol("Noise_IK_25519_ChaChaPoly_BLAKE2s")

# 2. Load keys
# `kp_r` is the responder's static keypair

# 3. Initialize handshake state
# responder is `false` for initiator param
state_r = Noise.handshake(protocol, false, <<>>, s: kp_r)

# 4. Receive message and process it
# `msg1` received from network
{:ok, "payload1", state_r} = Noise.handshake_step(state_r, msg1)
```

Once the handshake is complete (which depends on the specific pattern), `Noise.handshake_step/2` will return `{:complete, message, {cipher_state_1, cipher_state_2}}`. You can then use these cipher states to encrypt and decrypt transport messages.

```elixir
# Encrypting data
{ciphertext, new_cs1} = Noise.encrypt(cipher_state_1, "Hello World")

# Decrypting data
{plaintext, new_cs2} = Noise.decrypt(cipher_state_2, ciphertext)
```

For detailed documentation, refer to the [API Docs](https://hexdocs.pm/noise_protocol).
