defmodule Noise.Handshake do
  @moduledoc false

  alias Noise.HandshakeState

  def next_step(state, message \\ <<>>)

  def next_step(
        %HandshakeState{initiator: true, message_patterns: [{:ini, _tokens}]} = state,
        message
      ) do
    HandshakeState.write_message(state, message)
  end

  def next_step(
        %HandshakeState{initiator: false, message_patterns: [{:ini, _tokens}]} = state,
        message
      ) do
    HandshakeState.read_message(state, message)
  end

  def next_step(
        %HandshakeState{initiator: true, message_patterns: [{:resp, _tokens}]} = state,
        message
      ) do
    HandshakeState.read_message(state, message)
  end

  def next_step(
        %HandshakeState{initiator: false, message_patterns: [{:resp, _tokens}]} = state,
        message
      ) do
    HandshakeState.write_message(state, message)
  end

  def next_step(%HandshakeState{message_patterns: []} = state, _message) do
    HandshakeState.finalize(state)
  end
end
