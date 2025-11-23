defmodule Noise.HandshakeStateTest do
  use ExUnit.Case, async: true

  alias Noise.HandshakeState

  @protocol_name "Noise_NN_25519_ChaChaPoly_BLAKE2b"

  describe "initialize/8" do
    test "initializes state correctly for initiator" do
      state =
        HandshakeState.initialize(
          @protocol_name,
          true,
          "prologue",
          nil,
          nil,
          nil,
          nil,
          []
        )

      assert state.initiator == true
      assert state.protocol.name == @protocol_name
      assert state.message_patterns == state.protocol.pattern.tokens
    end

    test "initializes state correctly for responder" do
      state =
        HandshakeState.initialize(
          @protocol_name,
          false,
          "prologue",
          nil,
          nil,
          nil,
          nil,
          []
        )

      assert state.initiator == false
      assert state.protocol.name == @protocol_name
    end

    test "raises ArgumentError for unknown protocol" do
      assert_raise ArgumentError, fn ->
        HandshakeState.initialize(
          "Noise_Unknown_25519_ChaChaPoly_BLAKE2b",
          true,
          "",
          nil,
          nil,
          nil,
          nil,
          []
        )
      end
    end

    test "accepts PSK for PSK handshake" do
      psk_protocol = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2b"
      psk = <<0::256>>

      state =
        HandshakeState.initialize(
          psk_protocol,
          true,
          "",
          nil,
          nil,
          nil,
          nil,
          [psk]
        )

      assert state.psks == [psk]
    end
  end
end
