defmodule Noise.CipherState do
  @moduledoc false

  alias Noise.Protocol

  @enforce_keys [:protocol]
  defstruct protocol: nil, k: nil, n: 0

  @type t() :: %__MODULE__{
          protocol: Protocol.t(),
          k: <<_::32, _::_*8>> | nil,
          n: integer()
        }

  defguard is_key(k) when is_binary(k) and byte_size(k) == 32

  def initialize(%Protocol{} = protocol) do
    %__MODULE__{protocol: protocol}
  end

  def initialize_key(%__MODULE__{} = state, key) do
    state
    |> Map.put(:k, key)
    |> Map.put(:n, 0)
  end

  def has_key?(%__MODULE__{k: key}) when is_key(key), do: true
  def has_key?(%__MODULE__{}), do: false

  def set_nonce(%__MODULE__{} = state, nonce) do
    Map.put(state, :n, nonce)
  end

  def encrypt_with_ad(%__MODULE__{protocol: protocol, k: k, n: n} = state, ad, plain_text)
      when is_key(k) do
    {Protocol.encrypt(protocol, k, n, ad, plain_text), Map.update!(state, :n, &(&1 + 1))}
  end

  def encrypt_with_ad(%__MODULE__{} = state, _ad, plain_text) do
    {plain_text, state}
  end

  def decrypt_with_ad(%__MODULE__{protocol: protocol, k: k, n: n} = state, ad, cipher_text)
      when is_key(k) do
    {Protocol.decrypt(protocol, k, n, ad, cipher_text), Map.update!(state, :n, &(&1 + 1))}
  end

  def decrypt_with_ad(%__MODULE__{} = state, _ad, cipher_text) do
    {cipher_text, state}
  end

  def rekey(%__MODULE__{protocol: protocol, k: k} = state) do
    Map.put(state, :k, Protocol.rekey(protocol, k))
  end
end

defimpl Inspect, for: Noise.CipherState do
  alias Noise.Utils

  def inspect(state, opts) do
    Inspect.Map.inspect(%{k: Utils.hex(state.k), n: state.n}, opts)
  end
end
