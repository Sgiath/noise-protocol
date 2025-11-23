defmodule Noise.Pattern do
  @moduledoc false

  @enforce_keys [:name]
  defstruct name: nil, pre_message: [[], []], tokens: []

  @type token() :: :e | :s | :ee | :se | :es | :ss | :psk
  @type t() :: %__MODULE__{
          name: String.t(),
          pre_message: [[token()]],
          tokens: [{:ini | :resp, [token()]}]
        }

  def from_name(name) do
    case Regex.run(~r/^([A-Z]+)(.*)$/, name) do
      [_, base_name, modifiers_str] ->
        base_name
        |> get_base_pattern()
        |> apply_modifiers(name, modifiers_str)

      _ ->
        raise ArgumentError, "Pattern #{name} is not supported"
    end
  end

  defp apply_modifiers(pattern, full_name, "") do
    %{pattern | name: full_name}
  end

  defp apply_modifiers(pattern, full_name, modifiers_str) do
    modifiers = String.split(modifiers_str, "+")

    tokens =
      Enum.reduce(modifiers, pattern.tokens, fn modifier, tokens ->
        apply_modifier(modifier, tokens)
      end)

    %{pattern | name: full_name, tokens: tokens}
  end

  defp apply_modifier("psk0", tokens) do
    List.update_at(tokens, 0, fn {role, message_tokens} ->
      {role, [:psk | message_tokens]}
    end)
  end

  defp apply_modifier("psk" <> n, tokens) do
    index = String.to_integer(n) - 1

    List.update_at(tokens, index, fn {role, message_tokens} ->
      {role, message_tokens ++ [:psk]}
    end)
  end

  # One way
  defp get_base_pattern("N") do
    %__MODULE__{name: "N", pre_message: [[], [:s]], tokens: [{:ini, [:e, :es]}]}
  end

  defp get_base_pattern("K") do
    %__MODULE__{name: "K", pre_message: [[:s], [:s]], tokens: [{:ini, [:e, :es, :ss]}]}
  end

  defp get_base_pattern("X") do
    %__MODULE__{name: "X", pre_message: [[], [:s]], tokens: [{:ini, [:e, :es, :s, :ss]}]}
  end

  # Interactive
  defp get_base_pattern("NN") do
    %__MODULE__{name: "NN", tokens: [{:ini, [:e]}, {:resp, [:e, :ee]}]}
  end

  defp get_base_pattern("KN") do
    %__MODULE__{
      name: "KN",
      pre_message: [[:s], []],
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :se]}]
    }
  end

  defp get_base_pattern("NK") do
    %__MODULE__{
      name: "NK",
      pre_message: [[], [:s]],
      tokens: [{:ini, [:e, :es]}, {:resp, [:e, :ee]}]
    }
  end

  defp get_base_pattern("KK") do
    %__MODULE__{
      name: "KK",
      pre_message: [[:s], [:s]],
      tokens: [{:ini, [:e, :es, :ss]}, {:resp, [:e, :ee, :se]}]
    }
  end

  defp get_base_pattern("NX") do
    %__MODULE__{name: "NX", tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :s, :es]}]}
  end

  defp get_base_pattern("KX") do
    %__MODULE__{
      name: "KX",
      pre_message: [[:s], []],
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :se, :s, :es]}]
    }
  end

  defp get_base_pattern("XN") do
    %__MODULE__{name: "XN", tokens: [{:ini, [:e]}, {:resp, [:e, :ee]}, {:ini, [:s, :se]}]}
  end

  defp get_base_pattern("IN") do
    %__MODULE__{name: "IN", tokens: [{:ini, [:e, :s]}, {:resp, [:e, :ee, :se]}]}
  end

  defp get_base_pattern("XK") do
    %__MODULE__{
      name: "XK",
      pre_message: [[], [:s]],
      tokens: [{:ini, [:e, :es]}, {:resp, [:e, :ee]}, {:ini, [:s, :se]}]
    }
  end

  defp get_base_pattern("IK") do
    %__MODULE__{
      name: "IK",
      pre_message: [[], [:s]],
      tokens: [{:ini, [:e, :es, :s, :ss]}, {:resp, [:e, :ee, :se]}]
    }
  end

  defp get_base_pattern("XX") do
    %__MODULE__{
      name: "XX",
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :s, :es]}, {:ini, [:s, :se]}]
    }
  end

  defp get_base_pattern("IX") do
    %__MODULE__{name: "IX", tokens: [{:ini, [:e, :s]}, {:resp, [:e, :ee, :se, :s, :es]}]}
  end

  defp get_base_pattern(pattern) do
    raise ArgumentError, "Pattern #{pattern} is not supported"
  end
end

defimpl Inspect, for: Noise.Pattern do
  def inspect(state, _opts) do
    state.name <> pre_msg(state) <> handshake(state)
  end

  defp pre_msg(%Noise.Pattern{pre_message: [[], []]}), do: "\n"

  defp pre_msg(%Noise.Pattern{pre_message: [[], recv]}) do
    """
    \n  <- #{Enum.join(recv, ", ")}
      ...
    """
  end

  defp pre_msg(%Noise.Pattern{pre_message: [init, []]}) do
    """
    \n  -> #{Enum.join(init, ", ")}
      ...
    """
  end

  defp pre_msg(%Noise.Pattern{pre_message: [init, recv]}) do
    """
    \n  -> #{Enum.join(init, ", ")}
      <- #{Enum.join(recv, ", ")}
      ...
    """
  end

  defp handshake(%Noise.Pattern{tokens: tokens}) do
    Enum.map_join(
      tokens,
      fn
        {:ini, t} -> "  -> #{Enum.join(t, ", ")}"
        {:resp, t} -> "  <- #{Enum.join(t, ", ")}"
      end,
      "\n"
    )
  end
end
