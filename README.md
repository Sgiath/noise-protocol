# Noise Protocol

[![Hex.pm](https://img.shields.io/hexpm/v/noise_protocol.svg?style=flat&color=blue)](https://hex.pm/packages/noise_protocol)
[![Docs](https://img.shields.io/badge/api-docs-green.svg?style=flat)](https://hexdocs.pm/noise_protocol)

Elixir implementation of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
(revision 34). Pure Elixir on top of OTP `:crypto`; no runtime dependencies.

## What is implemented

- **Patterns**: all one-way (`N`, `K`, `X`), fundamental (`NN` … `IX`) and
  deferred (`NK1`, `X1X1`, …) patterns, with `pskN` modifiers.
- **DH**: `25519`, `448`; `secp256k1` following the Lightning BOLT-8 convention
  (compressed 33-byte keys, `SHA256(shared point)`) when the optional
  [`lib_secp256k1`](https://hex.pm/packages/lib_secp256k1) dependency is present.
- **Cipher**: `AESGCM`, `ChaChaPoly`.
- **Hash**: `SHA256`, `SHA512`, `BLAKE2s`, `BLAKE2b`.
- Rekey, handshake hash for channel binding, explicit nonces for out-of-order
  transports.

Not implemented: `fallback` (Noise Pipes), `hfs`, SHA3.

Conformance is verified against the Snow and Cacophony test-vector suites
(1,352 vectors covering every pattern × cipher × hash) and BOLT-8.

## Installation

```elixir
def deps do
  [
    {:noise_protocol, "~> 0.3.0"},
    # only if you use Noise_*_secp256k1_* protocols:
    {:lib_secp256k1, "~> 0.8"}
  ]
end
```

Requires Elixir 1.18+ and an OTP whose `:crypto` was built with the
primitives you select (`:crypto.supports/1` lists them).

## Usage

`Noise_XX_25519_ChaChaPoly_BLAKE2s`: three messages, both parties learn each
other's static key during the handshake.

```elixir
protocol = Noise.protocol("Noise_XX_25519_ChaChaPoly_BLAKE2s")
client_kp = Noise.generate_keypair(protocol)
server_kp = Noise.generate_keypair(protocol)

client = Noise.handshake(protocol, true, "prologue", s: client_kp)
server = Noise.handshake(protocol, false, "prologue", s: server_kp)

# -> e
{:ok, msg1, client} = Noise.handshake_step(client, "hello")
{:ok, "hello", server} = Noise.handshake_step(server, msg1)

# <- e, ee, s, es
{:ok, msg2, server} = Noise.handshake_step(server, "")
{:ok, "", client} = Noise.handshake_step(client, msg2)

# -> s, se  — the last message; both sides return :complete
{:complete, msg3, client} = Noise.handshake_step(client, "")
{:complete, "", server} = Noise.handshake_step(server, msg3)

# Peer identity and channel binding
server_pub = Noise.remote_static(client)
true = Noise.handshake_hash(client) == Noise.handshake_hash(server)

# Transport: split/1 returns {send, receive} for *this* role
{client_tx, client_rx} = Noise.split(client)
{server_tx, server_rx} = Noise.split(server)

{:ok, ciphertext, client_tx} = Noise.encrypt(client_tx, "secret")
{:ok, "secret", server_rx} = Noise.decrypt(server_rx, ciphertext)
```

`handshake_step/2` writes when it is your turn and reads otherwise. Use
`Noise.write_message/2` / `Noise.read_message/2` when you want that explicit;
they return `{:error, :wrong_turn}` if misused.

Patterns that need pre-shared keys take them as options:

```elixir
# IK: the initiator already knows the responder's static key
initiator = Noise.handshake("Noise_IK_25519_AESGCM_SHA256", true, "", s: kp_i, rs: server_pub)
responder = Noise.handshake("Noise_IK_25519_AESGCM_SHA256", false, "", s: kp_r)

# NNpsk0: one 32-byte pre-shared key per psk token
Noise.handshake("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s", true, "", psks: [psk])
```

Missing or superfluous keys raise `ArgumentError` at `Noise.handshake/4`.

## Errors

Anything coming from the network is handled without raising:

| Reason                | Meaning                                                              |
| --------------------- | -------------------------------------------------------------------- |
| `:decrypt_failed`     | AEAD tag mismatch. State unchanged; drop the message and carry on.   |
| `:malformed_message`  | Handshake message shorter than its tokens require.                   |
| `:message_too_long`   | Over the 65535-byte Noise limit (65519 bytes of transport plaintext).|
| `:invalid_public_key` | The peer's DH key was rejected (bad encoding or low-order point).    |
| `:nonce_exhausted`    | 2^64-1 messages sent or received on one cipher state; rekey earlier. |
| `:wrong_turn`         | `write_message/2` on the peer's turn or vice versa.                  |
| `:handshake_complete` | Handshake function called after the last message; call `split/1`.   |

Private keys, PSKs and chaining keys are redacted from `inspect/1`.

## Development

```sh
mix check   # format, compile --warnings-as-errors, credo, dialyzer, docs, tests
```

The spec this implementation follows is checked in as `protocol.md`.
