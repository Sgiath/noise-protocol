defmodule Noise.PatternTest do
  use ExUnit.Case, async: true

  alias Noise.Pattern

  describe "from_name/1" do
    test "parses simple one-way pattern" do
      pattern = Pattern.from_name("N")
      assert pattern.name == "N"
      assert pattern.pre_message == [[], [:s]]
      assert pattern.tokens == [{:ini, [:e, :es]}]
    end

    test "parses interactive pattern NN" do
      pattern = Pattern.from_name("NN")
      assert pattern.name == "NN"
      assert pattern.pre_message == [[], []]
      assert pattern.tokens == [{:ini, [:e]}, {:resp, [:e, :ee]}]
    end

    test "parses pattern with modifiers (psk0)" do
      pattern = Pattern.from_name("NNpsk0")
      assert pattern.name == "NNpsk0"
      # psk0 adds psk to the first message (index 0)
      assert pattern.tokens == [{:ini, [:psk, :e]}, {:resp, [:e, :ee]}]
    end

    test "parses pattern with modifiers (psk2)" do
      # XX has 3 messages: ini, resp, ini.
      # psk2 means adds psk to the end of 2nd message (index 1)
      pattern = Pattern.from_name("XXpsk2")
      assert pattern.name == "XXpsk2"
      # Original XX:
      # -> e
      # <- e, ee, s, es
      # -> s, se

      # Modified XXpsk2:
      # -> e
      # <- e, ee, s, es, psk
      # -> s, se

      expected_tokens = [
        {:ini, [:e]},
        {:resp, [:e, :ee, :s, :es, :psk]},
        {:ini, [:s, :se]}
      ]

      assert pattern.tokens == expected_tokens
    end

    test "parses multiple modifiers" do
      # "NNpsk0+psk2" -> psk at msg 0 (start) and msg 1 (end)
      # psk0 -> prepend to msg 0
      # psk2 -> append to msg 1 (index 1)

      pattern = Pattern.from_name("NNpsk0+psk2")
      assert pattern.name == "NNpsk0+psk2"
      assert pattern.tokens == [{:ini, [:psk, :e]}, {:resp, [:e, :ee, :psk]}]
    end

    test "raises ArgumentError for unsupported base pattern" do
      assert_raise ArgumentError, "Pattern ZZ is not supported", fn ->
        Pattern.from_name("ZZ")
      end
    end

    test "raises ArgumentError (or matches regex but fails later) for weird format" do
      # The regex is ^([A-Z0-9]+)(.*)$, so "noise" matches base="noise", mods=""
      # get_base_pattern("noise") will raise
      assert_raise ArgumentError, "Pattern noise is not supported", fn ->
        Pattern.from_name("noise")
      end
    end
  end
end
