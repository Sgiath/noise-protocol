defmodule Noise.HandshakeState do
  @moduledoc false

  alias Noise.Protocol
  alias Noise.SymmetricState

  @enforce_keys [:protocol]
  defstruct [:protocol, :initiator, :symetric_state, :message_patterns, :s, :e, :rs, :re]

  def initialize(
        %Protocol{} = protocol,
        initiator,
        prologue \\ <<>>,
        s \\ nil,
        e \\ nil,
        rs \\ nil,
        re \\ nil
      ) do
    symmetric_state =
      protocol
      |> SymmetricState.initialize()
      |> SymmetricState.mix_hash(prologue)

    symmetric_state =
      Enum.reduce(protocol.pattern.pre_message, symmetric_state, fn
        [], state ->
          state

        [:e], state ->
          SymmetricState.mix_hash(state, elem(e, 1))

        [:s], state ->
          SymmetricState.mix_hash(state, elem(s, 1))

        [:e, :s], state ->
          state
          |> SymmetricState.mix_hash(elem(e, 1))
          |> SymmetricState.mix_hash(elem(s, 1))
      end)

    %__MODULE__{
      protocol: protocol,
      initiator: initiator,
      symetric_state: symmetric_state,
      message_patterns: protocol.pattern.tokens,
      s: s,
      e: e,
      rs: rs,
      re: re
    }
  end

  def write_message(%__MODULE__{} = state, payload) do
    {act, state} =
      Map.get_and_update!(state, :message_patterns, fn [act | rest] -> {act, rest} end)

    {message, state} = construct_message(state, act, <<>>)
    {ciphertext, state} = encrypt_and_hash(state, payload)
    {message <> ciphertext, state}
  end

  # internal API

  defp construct_message(%__MODULE__{e: nil} = state, [:e | rest], msg) do
    {_sec, pubkey} = e = Protocol.generate_keypair(state.protocol)

    state
    |> Map.put(:e, e)
    |> mix_hash(pubkey)
    |> construct_message(rest, <<msg::binary, pubkey::binary>>)
  end

  defp construct_message(%__MODULE__{s: {_sec, pubkey}} = state, [:s | rest], msg) do
    {ciphertext, state} = encrypt_and_hash(state, pubkey)
    construct_message(state, rest, <<msg::binary, ciphertext::binary>>)
  end

  defp construct_message(%__MODULE__{e: e, re: re} = state, [:ee | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, e, re))
    |> construct_message(rest, msg)
  end

  defp construct_message(%__MODULE__{initiator: true, e: e, rs: rs} = state, [:es | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, e, rs))
    |> construct_message(rest, msg)
  end

  defp construct_message(%__MODULE__{initiator: false, s: s, re: re} = state, [:es | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, s, re))
    |> construct_message(rest, msg)
  end

  defp construct_message(%__MODULE__{initiator: false, e: e, rs: rs} = state, [:se | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, e, rs))
    |> construct_message(rest, msg)
  end

  defp construct_message(%__MODULE__{initiator: true, s: s, re: re} = state, [:se | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, s, re))
    |> construct_message(rest, msg)
  end

  defp construct_message(%__MODULE__{s: s, rs: rs} = state, [:ss | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, s, rs))
    |> construct_message(rest, msg)
  end

  defp construct_message(%__MODULE__{} = state, [], msg), do: {msg, state}

  # sub-state functions

  defp mix_key(%__MODULE__{symetric_state: ss} = state, ikm) do
    %__MODULE__{state | symetric_state: SymmetricState.mix_key(ss, ikm)}
  end

  defp mix_hash(%__MODULE__{symetric_state: ss} = state, data) do
    %__MODULE__{state | symetric_state: SymmetricState.mix_hash(ss, data)}
  end

  defp encrypt_and_hash(%__MODULE__{symetric_state: ss} = state, plaintext) do
    {ciphertext, ss} = SymmetricState.encrypt_and_hash(ss, plaintext)
    {ciphertext, %__MODULE__{state | symetric_state: ss}}
  end
end
