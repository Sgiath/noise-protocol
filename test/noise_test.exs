defmodule NoiseTest do
  use ExUnit.Case

  doctest Noise

  test "Noise public API handshake NN" do
    protocol = Noise.protocol("Noise_NN_25519_ChaChaPoly_BLAKE2s")

    # Initialize
    state_i = Noise.handshake(protocol, true)
    state_r = Noise.handshake(protocol, false)

    # -> e
    # Initiator starts.
    {:ok, msg1, state_i} = Noise.handshake_step(state_i, "payload1")

    # Responder reads msg1.
    {:ok, payload1, state_r} = Noise.handshake_step(state_r, msg1)
    assert payload1 == "payload1"

    # <- e, dhee
    # Responder writes msg2. This should be the last step for NN.
    {:complete, msg2, {c1_r, c2_r}} = Noise.handshake_step(state_r, "payload2")

    # Initiator reads msg2. This should be the last step for Init.
    {:complete, payload2, {c1_i, c2_i}} = Noise.handshake_step(state_i, msg2)
    assert payload2 == "payload2"

    # Verify transport phase
    # c1 is for initiator->responder
    # c2 is for responder->initiator

    # Init -> Resp
    {cipher, _c1_i_next} = Noise.encrypt(c1_i, "transport_msg_1")
    {plain, _c1_r_next} = Noise.decrypt(c1_r, cipher)
    assert plain == "transport_msg_1"

    # Resp -> Init
    {cipher2, _c2_r_next} = Noise.encrypt(c2_r, "transport_msg_2")
    {plain2, _c2_i_next} = Noise.decrypt(c2_i, cipher2)
    assert plain2 == "transport_msg_2"
  end
end
