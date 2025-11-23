defmodule Noise.Handshake do
  @moduledoc """
  Logic for processing handshake steps.

  This module determines the next action (read or write) based on the current `HandshakeState`
  and delegates to the appropriate functions in `Noise.HandshakeState`.
  """

  alias Noise.HandshakeState

  def next_step(state, message \\ <<>>)

  def next_step(
        %HandshakeState{initiator: true, message_patterns: [{:ini, _tokens} | _]} = state,
        message
      ) do
    HandshakeState.write_message(state, message)
  end

  def next_step(
        %HandshakeState{initiator: false, message_patterns: [{:ini, _tokens} | _]} = state,
        message
      ) do
    HandshakeState.read_message(state, message)
  end

  def next_step(
        %HandshakeState{initiator: true, message_patterns: [{:resp, _tokens} | _]} = state,
        message
      ) do
    HandshakeState.read_message(state, message)
  end

  def next_step(
        %HandshakeState{initiator: false, message_patterns: [{:resp, _tokens} | _]} = state,
        message
      ) do
    HandshakeState.write_message(state, message)
  end

  def next_step(%HandshakeState{message_patterns: []} = state, _message) do
    HandshakeState.finalize(state)
  end
end
