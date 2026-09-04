defmodule Noise.Crypto.Cipher.ChaChaPolyTest do
  use ExUnit.Case, async: true

  alias Noise.Crypto.Cipher.ChaChaPoly

  @k Base.decode16!("E68F69B7F096D7917245F5E5CF8AE1595FEBE4D4644333C99F9C4A1282031C9F")
  @ad Base.decode16!("9E0E7DE8BB75554F21DB034633DE04BE41A2B8A18DA7A319A03C803BF02B396C")
  @mac Base.decode16!("0DF6086551151F58B8AFE6C195782C6A")

  test "BOLT-8 Act One tag: little-endian nonce, empty plaintext" do
    assert ChaChaPoly.encrypt(@k, 0, @ad, <<>>) == @mac
    assert ChaChaPoly.decrypt(@k, 0, @ad, @mac) == <<>>
  end

  test "nonce is encoded little-endian in the low 8 bytes (spec §12.3)" do
    {expected, tag} =
      :crypto.crypto_one_time_aead(:chacha20_poly1305, @k, <<0::32, 1::little-64>>, "x", "", true)

    assert ChaChaPoly.encrypt(@k, 1, "", "x") == expected <> tag
  end

  test "authentication failures and short input return :error" do
    assert ChaChaPoly.decrypt(@k, 1, @ad, @mac) == :error
    assert ChaChaPoly.decrypt(@k, 0, "", @mac) == :error
    assert ChaChaPoly.decrypt(@k, 0, @ad, binary_part(@mac, 0, 15)) == :error
    assert ChaChaPoly.decrypt(@k, 0, @ad, <<>>) == :error
  end

  test "rekey derives a different 32-byte key deterministically" do
    assert byte_size(ChaChaPoly.rekey(@k)) == 32
    assert ChaChaPoly.rekey(@k) != @k
    assert ChaChaPoly.rekey(@k) == ChaChaPoly.rekey(@k)
  end
end
