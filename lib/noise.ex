defmodule NoiseProtocol do
  @moduledoc false

  alias Noise.Socket

  @spec close(Socket.t()) :: :ok | {:error, term()}
  def close(%Socket{}) do
    :ok
  end

  @spec connection_information(Socket.t()) :: {:ok, Keyword.t()} | {:error, term()}
  def connection_information(%Socket{}) do
    {:ok, []}
  end

  @spec handshake(Socket.t()) :: {:ok, Socket.t()} | {:error, term()}
  def handshake(%Socket{} = socket) do
    {:ok, socket}
  end

  def listen(port, opts) do
    :gen_tcp.listen(port, opts)
  end
end
