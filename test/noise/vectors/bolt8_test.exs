defmodule Noise.Vectors.Bolt8Test do
  @moduledoc """
  Lightning BOLT-8 test vectors for `Noise_XK_secp256k1_ChaChaPoly_SHA256`.

  BOLT-8 frames every act with a leading version byte (`0x00`) that is not
  part of the Noise message, so it is stripped from the vectors here.
  """
  use ExUnit.Case, async: true

  @protocol "Noise_XK_secp256k1_ChaChaPoly_SHA256"
  @prologue "lightning"

  defp hex(h), do: Base.decode16!(h, case: :lower)
  # act bytes without the BOLT-8 version prefix
  defp act(h), do: binary_part(hex(h), 1, byte_size(hex(h)) - 1)

  @init_static Base.decode16!("1111111111111111111111111111111111111111111111111111111111111111",
                 case: :lower
               )
  @init_ephemeral Base.decode16!(
                    "1212121212121212121212121212121212121212121212121212121212121212",
                    case: :lower
                  )
  @resp_static Base.decode16!("2121212121212121212121212121212121212121212121212121212121212121",
                 case: :lower
               )
  @resp_ephemeral Base.decode16!(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                    case: :lower
                  )
  @resp_pub Base.decode16!("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7",
              case: :lower
            )
  @init_pub Base.decode16!("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
              case: :lower
            )

  @act1 "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a"
  @act2 "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae"
  @act3 "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"

  defp keypair(priv), do: {priv, Secp256k1.pubkey(priv, :compressed)}

  defp initiator do
    Noise.handshake(@protocol, true, @prologue,
      s: keypair(@init_static),
      e: keypair(@init_ephemeral),
      rs: @resp_pub
    )
  end

  defp responder do
    Noise.handshake(@protocol, false, @prologue,
      s: keypair(@resp_static),
      e: keypair(@resp_ephemeral)
    )
  end

  test "successful handshake and first transport message" do
    init = initiator()
    resp = responder()
    assert elem(keypair(@init_static), 1) == @init_pub

    {:ok, act1, init} = Noise.handshake_step(init, "")
    assert act1 == act(@act1)
    {:ok, "", resp} = Noise.handshake_step(resp, act1)

    {:ok, act2, resp} = Noise.handshake_step(resp, "")
    assert act2 == act(@act2)
    {:ok, "", init} = Noise.handshake_step(init, act2)

    {:complete, act3, init} = Noise.handshake_step(init, "")
    assert act3 == act(@act3)
    {:complete, "", resp} = Noise.handshake_step(resp, act3)

    assert Noise.remote_static(resp) == @init_pub
    assert Noise.handshake_hash(init) == Noise.handshake_hash(resp)

    # transport-message test: length prefix then "hello" under sk at nonces 0 and 1
    {init_tx, init_rx} = Noise.split(init)
    {resp_tx, resp_rx} = Noise.split(resp)

    {:ok, c0, init_tx} = Noise.encrypt(init_tx, <<0, 5>>)
    assert c0 == hex("cf2b30ddf0cf3f80e7c35a6e6730b59fe802")
    {:ok, c1, _} = Noise.encrypt(init_tx, "hello")
    assert c1 == hex("473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95")

    {:ok, <<0, 5>>, resp_rx} = Noise.decrypt(resp_rx, c0)
    {:ok, "hello", _} = Noise.decrypt(resp_rx, c1)

    {:ok, back, _} = Noise.encrypt(resp_tx, "pong")
    {:ok, "pong", _} = Noise.decrypt(init_rx, back)
  end

  describe "initiator rejects" do
    setup do
      {:ok, _act1, init} = Noise.handshake_step(initiator(), "")
      {:ok, init: init}
    end

    test "act2 short read", %{init: init} do
      assert {:error, :malformed_message} =
               Noise.handshake_step(init, binary_part(act(@act2), 0, 48))
    end

    test "act2 bad key serialization", %{init: init} do
      <<_, rest::binary>> = act(@act2)
      assert {:error, :invalid_public_key} = Noise.handshake_step(init, <<4, rest::binary>>)
    end

    test "act2 bad MAC", %{init: init} do
      tampered = binary_part(act(@act2), 0, 48) <> <<0xAF>>
      assert {:error, :decrypt_failed} = Noise.handshake_step(init, tampered)
    end
  end

  describe "responder rejects" do
    test "act1 short read" do
      assert {:error, :malformed_message} =
               Noise.handshake_step(responder(), binary_part(act(@act1), 0, 48))
    end

    test "act1 bad key serialization" do
      <<_, rest::binary>> = act(@act1)

      assert {:error, :invalid_public_key} =
               Noise.handshake_step(responder(), <<4, rest::binary>>)
    end

    test "act1 bad MAC" do
      tampered = binary_part(act(@act1), 0, 48) <> <<0x6B>>
      assert {:error, :decrypt_failed} = Noise.handshake_step(responder(), tampered)
    end

    setup context do
      if context[:after_act2] do
        {:ok, "", resp} = Noise.handshake_step(responder(), act(@act1))
        {:ok, _act2, resp} = Noise.handshake_step(resp, "")
        {:ok, resp: resp}
      else
        :ok
      end
    end

    @tag :after_act2
    test "act3 short read", %{resp: resp} do
      assert {:error, :malformed_message} =
               Noise.handshake_step(resp, binary_part(act(@act3), 0, 64))
    end

    @tag :after_act2
    test "act3 bad MAC for ciphertext", %{resp: resp} do
      <<_, rest::binary>> = act(@act3)
      assert {:error, :decrypt_failed} = Noise.handshake_step(resp, <<0xC9, rest::binary>>)
    end

    @tag :after_act2
    test "act3 bad rs (decrypts to an uncompressed-prefix key)", %{resp: resp} do
      bad_rs =
        act(
          "00bfe3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa2235536ad09a8ee351870c2bb7f78b754a26c6cef79a98d25139c856d7efd252c2ae73c"
        )

      assert {:error, :invalid_public_key} = Noise.handshake_step(resp, bad_rs)
    end

    @tag :after_act2
    test "act3 bad MAC", %{resp: resp} do
      tampered = binary_part(act(@act3), 0, 64) <> <<0xBB>>
      assert {:error, :decrypt_failed} = Noise.handshake_step(resp, tampered)
    end
  end
end
