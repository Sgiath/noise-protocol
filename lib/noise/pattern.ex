defmodule Noise.Pattern do
  @moduledoc false

  @enforce_keys [:name]
  defstruct name: nil, pre_message: [[], []], tokens: []

  @type token() :: :e | :s | :ee | :se | :es | :ss
  @type t() :: %__MODULE__{
          name: String.t(),
          pre_message: [[token()]],
          tokens: [[token()]]
        }

  # One way
  def from_name("N") do
    %__MODULE__{name: "N", pre_message: [[], [:s]], tokens: [[:e, :es]]}
  end

  def from_name("K") do
    %__MODULE__{name: "K", pre_message: [[:s], [:s]], tokens: [[:e, :es, :ss]]}
  end

  def from_name("X") do
    %__MODULE__{name: "X", pre_message: [[], [:s]], tokens: [[:e, :es, :s, :ss]]}
  end

  # Interactive
  def from_name("NN") do
    %__MODULE__{name: "NN", tokens: [[:e], [:e, :ee]]}
  end

  def from_name("KN") do
    %__MODULE__{name: "KN", pre_message: [[:s], []], tokens: [[:e], [:e, :ee, :se]]}
  end

  def from_name("NK") do
    %__MODULE__{name: "NK", pre_message: [[], [:s]], tokens: [[:e, :es], [:e, :ee]]}
  end

  def from_name("KK") do
    %__MODULE__{name: "KK", pre_message: [[:s], [:s]], tokens: [[:e, :es, :ss], [:e, :ee, :se]]}
  end

  def from_name("NX") do
    %__MODULE__{name: "NX", tokens: [[:e], [:e, :ee, :s, :es]]}
  end

  def from_name("KX") do
    %__MODULE__{name: "KX", pre_message: [[:s], []], tokens: [[:e], [:e, :ee, :se, :s, :es]]}
  end

  def from_name("XN") do
    %__MODULE__{name: "XN", tokens: [[:e], [:e, :ee], [:s, :se]]}
  end

  def from_name("IN") do
    %__MODULE__{name: "IN", tokens: [[:e, :s], [:e, :ee, :se]]}
  end

  def from_name("XK") do
    %__MODULE__{name: "XK", pre_message: [[], [:s]], tokens: [[:e, :es], [:e, :ee], [:s, :se]]}
  end

  def from_name("IK") do
    %__MODULE__{name: "IK", pre_message: [[], [:s]], tokens: [[:e, :es, :s, :ss], [:e, :ee, :se]]}
  end

  def from_name("XX") do
    %__MODULE__{name: "XX", tokens: [[:e], [:e, :ee, :s, :es], [:s, :se]]}
  end

  def from_name("IX") do
    %__MODULE__{name: "IX", tokens: [[:e, :s], [:e, :ee, :se, :s, :es]]}
  end

  def from_name(pattern) do
    raise ArgumentError, "Pattern #{pattern} is not supported"
  end
end
