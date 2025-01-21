defmodule Noise.Pattern do
  @moduledoc false

  @enforce_keys [:name]
  defstruct name: nil, pre_message: [[], []], tokens: []

  @type token() :: :e | :s | :ee | :se | :es | :ss
  @type t() :: %__MODULE__{
          name: String.t(),
          pre_message: [[token()]],
          tokens: [{:ini | :resp, [token()]}]
        }

  # One way
  def from_name("N") do
    %__MODULE__{name: "N", pre_message: [[], [:s]], tokens: [{:ini, [:e, :es]}]}
  end

  def from_name("K") do
    %__MODULE__{name: "K", pre_message: [[:s], [:s]], tokens: [{:ini, [:e, :es, :ss]}]}
  end

  def from_name("X") do
    %__MODULE__{name: "X", pre_message: [[], [:s]], tokens: [{:ini, [:e, :es, :s, :ss]}]}
  end

  # Interactive
  def from_name("NN") do
    %__MODULE__{name: "NN", tokens: [{:ini, [:e]}, {:resp, [:e, :ee]}]}
  end

  def from_name("KN") do
    %__MODULE__{
      name: "KN",
      pre_message: [[:s], []],
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :se]}]
    }
  end

  def from_name("NK") do
    %__MODULE__{
      name: "NK",
      pre_message: [[], [:s]],
      tokens: [{:ini, [:e, :es]}, {:resp, [:e, :ee]}]
    }
  end

  def from_name("KK") do
    %__MODULE__{
      name: "KK",
      pre_message: [[:s], [:s]],
      tokens: [{:ini, [:e, :es, :ss]}, {:resp, [:e, :ee, :se]}]
    }
  end

  def from_name("NX") do
    %__MODULE__{name: "NX", tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :s, :es]}]}
  end

  def from_name("KX") do
    %__MODULE__{
      name: "KX",
      pre_message: [[:s], []],
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :se, :s, :es]}]
    }
  end

  def from_name("XN") do
    %__MODULE__{name: "XN", tokens: [{:ini, [:e]}, {:resp, [:e, :ee]}, {:ini, [:s, :se]}]}
  end

  def from_name("IN") do
    %__MODULE__{name: "IN", tokens: [{:ini, [:e, :s]}, {:resp, [:e, :ee, :se]}]}
  end

  def from_name("XK") do
    %__MODULE__{
      name: "XK",
      pre_message: [[], [:s]],
      tokens: [{:ini, [:e, :es]}, {:resp, [:e, :ee]}, {:ini, [:s, :se]}]
    }
  end

  def from_name("IK") do
    %__MODULE__{
      name: "IK",
      pre_message: [[], [:s]],
      tokens: [{:ini, [:e, :es, :s, :ss]}, {:resp, [:e, :ee, :se]}]
    }
  end

  def from_name("XX") do
    %__MODULE__{
      name: "XX",
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :s, :es]}, {:ini, [:s, :se]}]
    }
  end

  def from_name("IX") do
    %__MODULE__{name: "IX", tokens: [{:ini, [:e, :s]}, {:resp, [:e, :ee, :se, :s, :es]}]}
  end

  def from_name(pattern) do
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
