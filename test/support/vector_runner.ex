defmodule Noise.VectorRunner do
  import ExUnit.Assertions

  alias Noise.CipherState
  alias Noise.HandshakeState

  def load_vectors_from_file(path) do
    path
    |> File.read!()
    |> JSON.decode!()
    |> Map.get("vectors")
  end

  def run_vector(vector) do
    case skip_reason(vector) do
      nil -> do_run_vector(vector)
      _reason -> :ok
    end
  end

  def skip_reason(vector) do
    cond do
      Map.get(vector, "fail", false) ->
        IO.inspect("Marked to fail")
        nil

      String.contains?(vector["protocol_name"], "+") ->
        "Hybrid keys not yet supported"

      Map.get(vector, "fallback", false) ->
        "Fallback not supported"

      :otherwise ->
        nil
    end
  end

  defp do_run_vector(vector) do
    protocol_name = vector["protocol_name"]
    prologue = decode_hex(vector["init_prologue"] || "")

    # Keys
    init_static = decode_keypair(vector["init_static"], protocol_name)
    init_ephemeral = decode_keypair(vector["init_ephemeral"], protocol_name)
    init_remote_static = decode_key(vector["init_remote_static"])

    resp_static = decode_keypair(vector["resp_static"], protocol_name)
    resp_ephemeral = decode_keypair(vector["resp_ephemeral"], protocol_name)
    resp_remote_static = decode_key(vector["resp_remote_static"])

    # PSKs
    init_psks = vector |> Map.get("init_psks", []) |> Enum.map(&decode_hex/1)
    resp_psks = vector |> Map.get("resp_psks", []) |> Enum.map(&decode_hex/1)

    # Verify key derivation
    if resp_static && init_remote_static do
      assert elem(resp_static, 1) == init_remote_static,
             "Responder Static Key Derivation Mismatch"
    end

    # Initialize States
    hs_init =
      HandshakeState.initialize(
        protocol_name,
        true,
        prologue,
        init_static,
        init_remote_static,
        init_ephemeral,
        nil,
        init_psks
      )

    hs_resp =
      HandshakeState.initialize(
        protocol_name,
        false,
        prologue,
        resp_static,
        resp_remote_static,
        resp_ephemeral,
        nil,
        resp_psks
      )

    # Determine if One-Way
    is_one_way = Enum.all?(hs_init.protocol.pattern.tokens, fn {role, _} -> role == :ini end)

    # Run messages
    run_messages(vector, {:handshake, hs_init}, {:handshake, hs_resp}, :initiator, is_one_way)
  end

  defp run_messages(%{"messages" => []}, sender, receiver, _turn, _is_one_way),
    do: {sender, receiver}

  defp run_messages(%{"messages" => [msg | rest]} = vector, sender, receiver, turn, is_one_way) do
    payload = decode_hex(msg["payload"])
    expected_ciphertext = decode_hex(msg["ciphertext"])

    # Write
    {ciphertext, new_sender} = process_write(sender, payload, vector)

    assert ciphertext == expected_ciphertext,
           "Ciphertext mismatch in #{turn} write. Expected #{inspect(msg["ciphertext"])}"

    # Read
    {decrypted_payload, new_receiver} = process_read(receiver, ciphertext, vector)

    assert decrypted_payload == payload,
           "Payload mismatch in #{turn} read"

    # Flip turn
    if is_one_way do
      # Sender is ALWAYS Initiator. Receiver is ALWAYS Responder.
      # Arguments: (sender, receiver).
      # sender was passed as first arg.
      # So we pass them SAME order.
      # But `new_sender` is the updated state of sender.
      run_messages(%{vector | "messages" => rest}, new_sender, new_receiver, turn, is_one_way)
    else
      next_turn = if turn == :initiator, do: :responder, else: :initiator
      # Swap sender/receiver for next iteration
      run_messages(
        %{vector | "messages" => rest},
        new_receiver,
        new_sender,
        next_turn,
        is_one_way
      )
    end
  end

  # --- State Processing ---

  # Handshake Mode
  defp process_write({:handshake, state}, payload, vector) do
    {ciphertext, new_state} = HandshakeState.write_message(state, payload)

    if new_state.message_patterns == [] do
      # Handshake complete, Split
      {{cs1, cs2}, final_hs} = HandshakeState.finalize(new_state)

      if not is_nil(vector["handshake_hash"]) do
        assert vector["handshake_hash"] == Noise.Utils.hex(final_hs.symmetric_state.h)
      end

      is_initiator = state.initiator

      transport_state =
        if is_initiator do
          {:transport, cs1, cs2}
          # Send using c1, Recv using c2
        else
          {:transport, cs2, cs1}
          # Send using c2, Recv using c1
        end

      {ciphertext, transport_state}
    else
      {ciphertext, {:handshake, new_state}}
    end
  end

  # Transport Mode
  defp process_write({:transport, send_cs, recv_cs}, payload, _vector) do
    {ciphertext, new_send_cs} = CipherState.encrypt_with_ad(send_cs, <<>>, payload)
    {ciphertext, {:transport, new_send_cs, recv_cs}}
  end

  # Read - Handshake
  defp process_read({:handshake, state}, ciphertext, vector) do
    {payload, new_state} = HandshakeState.read_message(state, ciphertext)

    if new_state.message_patterns == [] do
      # Split
      {{cs1, cs2}, final_hs} = HandshakeState.finalize(new_state)

      if not is_nil(vector["handshake_hash"]) do
        assert vector["handshake_hash"] == Noise.Utils.hex(final_hs.symmetric_state.h)
      end

      is_initiator = state.initiator

      transport_state =
        if is_initiator do
          {:transport, cs1, cs2}
        else
          {:transport, cs2, cs1}
        end

      {payload, transport_state}
    else
      {payload, {:handshake, new_state}}
    end
  end

  # Read - Transport
  defp process_read({:transport, send_cs, recv_cs}, ciphertext, _vector) do
    {payload, new_recv_cs} = CipherState.decrypt_with_ad(recv_cs, <<>>, ciphertext)
    {payload, {:transport, send_cs, new_recv_cs}}
  end

  # --- Helpers ---

  defp decode_hex(nil), do: nil
  defp decode_hex(hex), do: Base.decode16!(hex, case: :mixed)

  defp decode_key(nil), do: nil
  defp decode_key(hex), do: decode_hex(hex)

  defp decode_keypair(nil, _), do: nil

  defp decode_keypair(hex, protocol_name) do
    priv = decode_hex(hex)
    pub = derive_public_key(priv, protocol_name)
    {priv, pub}
  end

  defp derive_public_key(priv, protocol_name) do
    cond do
      String.contains?(protocol_name, "25519") ->
        # X25519: Base point is 9
        :crypto.compute_key(:ecdh, <<9, 0::248>>, priv, :x25519)

      String.contains?(protocol_name, "448") ->
        # X448: Base point is 5
        :crypto.compute_key(:ecdh, <<5, 0::440>>, priv, :x448)

      String.contains?(protocol_name, "secp256k1") ->
        # Secp256k1
        Secp256k1.pubkey(priv, :compressed)

      true ->
        raise "Unknown DH for key derivation in protocol: #{protocol_name}"
    end
  end
end
