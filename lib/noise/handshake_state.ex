defmodule Noise.HandshakeState do
  @moduledoc false

  alias Noise.Protocol
  alias Noise.SymmetricState

  @enforce_keys [:protocol]
  defstruct [:protocol, :initiator, :symmetric_state, :message_patterns, :s, :e, :rs, :re, :psks]

  def initialize(
        protocol,
        initiator,
        prologue \\ <<>>,
        s \\ nil,
        rs \\ nil,
        e \\ nil,
        re \\ nil,
        psks \\ []
      )

  def initialize(protocol_name, initiator, prologue, s, rs, e, re, psks)
      when is_binary(protocol_name) do
    protocol_name
    |> Protocol.from_name()
    |> initialize(initiator, prologue, s, rs, e, re, psks)
  end

  def initialize(%Protocol{} = protocol, initiator, prologue, s, rs, e, re, nil) do
    initialize(protocol, initiator, prologue, s, rs, e, re, [])
  end

  def initialize(%Protocol{} = protocol, initiator, prologue, s, rs, e, re, psk)
      when is_binary(psk) do
    initialize(protocol, initiator, prologue, s, rs, e, re, [psk])
  end

  def initialize(%Protocol{} = protocol, initiator, prologue, s, rs, e, re, psks) do
    is_psk = is_psk_handshake?(protocol)

    if is_psk and Enum.empty?(psks) do
      raise ArgumentError, "At least one PSK is required for PSK handshake"
    end

    symmetric_state =
      protocol
      |> SymmetricState.initialize()
      |> SymmetricState.mix_hash(prologue)

    [init_pre, resp_pre] = protocol.pattern.pre_message

    symmetric_state =
      case init_pre do
        [] ->
          symmetric_state

        [:e] ->
          key = if initiator, do: elem(e, 1), else: re
          ss = SymmetricState.mix_hash(symmetric_state, key)
          if is_psk, do: SymmetricState.mix_key(ss, key), else: ss

        [:s] ->
          key = if initiator, do: elem(s, 1), else: rs
          SymmetricState.mix_hash(symmetric_state, key)

        [:e, :s] ->
          [key_e, key_s] = if initiator, do: [elem(e, 1), elem(s, 1)], else: [re, rs]

          ss = SymmetricState.mix_hash(symmetric_state, key_e)
          ss = if is_psk, do: SymmetricState.mix_key(ss, key_e), else: ss
          SymmetricState.mix_hash(ss, key_s)
      end

    symmetric_state =
      case resp_pre do
        [] ->
          symmetric_state

        [:e] ->
          key = if initiator, do: re, else: elem(e, 1)
          ss = SymmetricState.mix_hash(symmetric_state, key)
          if is_psk, do: SymmetricState.mix_key(ss, key), else: ss

        [:s] ->
          key = if initiator, do: rs, else: elem(s, 1)
          SymmetricState.mix_hash(symmetric_state, key)

        [:e, :s] ->
          [key_e, key_s] = if initiator, do: [re, rs], else: [elem(e, 1), elem(s, 1)]

          ss = SymmetricState.mix_hash(symmetric_state, key_e)
          ss = if is_psk, do: SymmetricState.mix_key(ss, key_e), else: ss
          SymmetricState.mix_hash(ss, key_s)
      end

    %__MODULE__{
      protocol: protocol,
      initiator: initiator,
      symmetric_state: symmetric_state,
      message_patterns: protocol.pattern.tokens,
      s: s,
      e: e,
      rs: rs,
      re: re,
      psks: psks
    }
  end

  def write_message(%__MODULE__{message_patterns: []} = state, _payload) do
    finalize(state)
  end

  def write_message(%__MODULE__{} = state, payload) do
    {act, state} =
      Map.get_and_update!(state, :message_patterns, fn [{_type, act} | rest] -> {act, rest} end)

    {message, state} = do_write_message(state, act, <<>>)
    {cipher_text, state} = encrypt_and_hash(state, payload)
    {message <> cipher_text, state}
  end

  def read_message(%__MODULE__{message_patterns: []} = state, _message) do
    finalize(state)
  end

  def read_message(%__MODULE__{} = state, message) do
    {act, state} =
      Map.get_and_update!(state, :message_patterns, fn [{_type, act} | rest] -> {act, rest} end)

    {message, state} = do_read_message(state, act, message)
    decrypt_and_hash(state, message)
  end

  def finalize(%__MODULE__{message_patterns: []} = state) do
    split(state)
  end

  # internal API

  defp do_write_message(%__MODULE__{e: nil} = state, [:e | rest], msg) do
    {_sec, pubkey} = e = Protocol.generate_keypair(state.protocol)

    state =
      state
      |> Map.put(:e, e)
      |> mix_hash(pubkey)

    state = if is_psk_handshake?(state.protocol), do: mix_key(state, pubkey), else: state

    do_write_message(state, rest, <<msg::binary, pubkey::binary>>)
  end

  defp do_write_message(%__MODULE__{e: {_sec, pubkey}} = state, [:e | rest], msg) do
    state =
      state
      |> mix_hash(pubkey)

    state = if is_psk_handshake?(state.protocol), do: mix_key(state, pubkey), else: state

    do_write_message(state, rest, <<msg::binary, pubkey::binary>>)
  end

  defp do_write_message(%__MODULE__{s: {_sec, pubkey}} = state, [:s | rest], msg) do
    {cipher_text, state} = encrypt_and_hash(state, pubkey)
    do_write_message(state, rest, <<msg::binary, cipher_text::binary>>)
  end

  defp do_write_message(%__MODULE__{e: e, re: re} = state, [:ee | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, e, re))
    |> do_write_message(rest, msg)
  end

  defp do_write_message(%__MODULE__{initiator: true, e: e, rs: rs} = state, [:es | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, e, rs))
    |> do_write_message(rest, msg)
  end

  defp do_write_message(%__MODULE__{initiator: false, s: s, re: re} = state, [:es | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, s, re))
    |> do_write_message(rest, msg)
  end

  defp do_write_message(%__MODULE__{initiator: false, e: e, rs: rs} = state, [:se | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, e, rs))
    |> do_write_message(rest, msg)
  end

  defp do_write_message(%__MODULE__{initiator: true, s: s, re: re} = state, [:se | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, s, re))
    |> do_write_message(rest, msg)
  end

  defp do_write_message(%__MODULE__{s: s, rs: rs} = state, [:ss | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, s, rs))
    |> do_write_message(rest, msg)
  end

  defp do_write_message(%__MODULE__{psks: [psk | psks]} = state, [:psk | rest], msg) do
    state
    |> Map.put(:psks, psks)
    |> mix_key_and_hash(psk)
    |> do_write_message(rest, msg)
  end

  defp do_write_message(%__MODULE__{} = state, [], msg), do: {msg, state}

  defp do_read_message(%__MODULE__{re: nil} = state, [:e | rest], msg) do
    <<re::binary-size(state.protocol.dhlen), msg::binary>> = msg

    state =
      state
      |> Map.put(:re, re)
      |> mix_hash(re)

    state = if is_psk_handshake?(state.protocol), do: mix_key(state, re), else: state

    do_read_message(state, rest, msg)
  end

  defp do_read_message(%__MODULE__{rs: nil} = state, [:s | rest], msg) do
    len = if has_key?(state), do: state.protocol.dhlen + 16, else: state.protocol.dhlen
    <<temp::binary-size(len), msg::binary>> = msg

    {rs, state} = decrypt_and_hash(state, temp)

    state
    |> Map.put(:rs, rs)
    |> do_read_message(rest, msg)
  end

  defp do_read_message(%__MODULE__{e: e, re: re} = state, [:ee | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, e, re))
    |> do_read_message(rest, msg)
  end

  defp do_read_message(%__MODULE__{initiator: true, e: e, rs: rs} = state, [:es | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, e, rs))
    |> do_read_message(rest, msg)
  end

  defp do_read_message(%__MODULE__{initiator: false, s: s, re: re} = state, [:es | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, s, re))
    |> do_read_message(rest, msg)
  end

  defp do_read_message(%__MODULE__{initiator: false, e: e, rs: rs} = state, [:se | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, e, rs))
    |> do_read_message(rest, msg)
  end

  defp do_read_message(%__MODULE__{initiator: true, s: s, re: re} = state, [:se | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, s, re))
    |> do_read_message(rest, msg)
  end

  defp do_read_message(%__MODULE__{s: s, rs: rs} = state, [:ss | rest], msg) do
    state
    |> mix_key(Protocol.dh(state.protocol, s, rs))
    |> do_read_message(rest, msg)
  end

  defp do_read_message(%__MODULE__{psks: [psk | psks]} = state, [:psk | rest], msg) do
    state
    |> Map.put(:psks, psks)
    |> mix_key_and_hash(psk)
    |> do_read_message(rest, msg)
  end

  defp do_read_message(%__MODULE__{} = state, [], msg), do: {msg, state}

  # sub-state functions

  defp has_key?(%__MODULE__{symmetric_state: ss}) do
    SymmetricState.has_key?(ss)
  end

  defp mix_key(%__MODULE__{symmetric_state: ss} = state, ikm) do
    %__MODULE__{state | symmetric_state: SymmetricState.mix_key(ss, ikm)}
  end

  defp mix_hash(%__MODULE__{symmetric_state: ss} = state, data) do
    %__MODULE__{state | symmetric_state: SymmetricState.mix_hash(ss, data)}
  end

  defp mix_key_and_hash(%__MODULE__{symmetric_state: ss} = state, ikm) do
    %__MODULE__{state | symmetric_state: SymmetricState.mix_key_and_hash(ss, ikm)}
  end

  defp encrypt_and_hash(%__MODULE__{symmetric_state: ss} = state, plain_text) do
    {cipher_text, ss} = SymmetricState.encrypt_and_hash(ss, plain_text)
    {cipher_text, %__MODULE__{state | symmetric_state: ss}}
  end

  defp decrypt_and_hash(%__MODULE__{symmetric_state: ss} = state, cipher_text) do
    {plain_text, ss} = SymmetricState.decrypt_and_hash(ss, cipher_text)
    {plain_text, %__MODULE__{state | symmetric_state: ss}}
  end

  defp split(%__MODULE__{symmetric_state: ss} = state) do
    {c, ss} = SymmetricState.split(ss)
    {c, %__MODULE__{state | symmetric_state: ss}}
  end

  defp is_psk_handshake?(protocol) do
    protocol.pattern.tokens
    |> Enum.flat_map(fn {_role, tokens} -> tokens end)
    |> Enum.member?(:psk)
  end
end

defimpl Inspect, for: Noise.HandshakeState do
  alias Noise.Utils

  def inspect(state, opts) do
    Inspect.Map.inspect(
      %{
        symmetric_state: state.symmetric_state,
        s: %{sec: Utils.hex(elem(state.s, 0)), pub: Utils.hex(elem(state.s, 1))},
        e: %{sec: Utils.hex(elem(state.e, 0)), pub: Utils.hex(elem(state.e, 1))},
        rs: Utils.hex(state.rs),
        re: Utils.hex(state.re),
        psks: state.psks
      },
      opts
    )
  end
end
