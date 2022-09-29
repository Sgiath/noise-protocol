defmodule NoiseTest.HandshakeState do
  use ExUnit.Case

  doctest Noise.HandshakeState

  setup_all do
    # initiator
    iss = "1111111111111111111111111111111111111111111111111111111111111111"
    isp = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
    ies = "1212121212121212121212121212121212121212121212121212121212121212"
    iep = "036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7"

    # responder
    rss = "2121212121212121212121212121212121212121212121212121212121212121"
    rsp = "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7"
    res = "2222222222222222222222222222222222222222222222222222222222222222"
    rep = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"

    {:ok,
     %{
       protocol_name: "Noise_XK_secp256k1_ChaChaPoly_SHA256",
       prologue: "lightning",
       initiator: actor_keys(iss, isp, ies, iep),
       responder: actor_keys(rss, rsp, res, rep)
     }}
  end

  defp actor_keys(ss, sp, es, ep) do
    %{
      s: {Base.decode16!(ss, case: :lower), Base.decode16!(sp, case: :lower)},
      e: {Base.decode16!(es, case: :lower), Base.decode16!(ep, case: :lower)}
    }
  end

  defp init(
         %{
           protocol_name: protocol_name,
           prologue: prologue,
           initiator: %{s: s, e: e},
           responder: %{s: {_s, rs}}
         },
         true
       ) do
    Noise.HandshakeState.initialize(protocol_name, true, prologue, s, rs, e, nil)
  end

  defp init(
         %{
           protocol_name: protocol_name,
           prologue: prologue,
           responder: %{s: s, e: e}
         },
         false
       ) do
    Noise.HandshakeState.initialize(protocol_name, false, prologue, s, nil, e, nil)
  end

  test "Lightning test vector initiator", config do
    hsi = init(config, true)
    hsr = init(config, false)

    {output, hsi} = Noise.HandshakeState.write_message(hsi, <<>>)

    assert Base.encode16(output, case: :lower) ==
             "036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a"

    {_message, hsr} = Noise.HandshakeState.read_message(hsr, output)
    {output, hsr} = Noise.HandshakeState.write_message(hsr, <<>>)

    assert Base.encode16(output, case: :lower) ==
             "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae"

    {_message, hsi} = Noise.HandshakeState.read_message(hsi, output)
    {output, hsi} = Noise.HandshakeState.write_message(hsi, <<>>)

    assert Base.encode16(output, case: :lower) ==
             "b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"

    {_message, hsr} = Noise.HandshakeState.read_message(hsr, output)

    # result
    {{isk, irk}, _hsi} = Noise.HandshakeState.write_message(hsi, <<>>)
    {{rrk, rsk}, _hsr} = Noise.HandshakeState.write_message(hsr, <<>>)

    assert Base.encode16(isk.k, case: :lower) ==
             "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"

    assert Base.encode16(irk.k, case: :lower) ==
             "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"

    assert Base.encode16(rrk.k, case: :lower) ==
             "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"

    assert Base.encode16(rsk.k, case: :lower) ==
             "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"
  end
end
