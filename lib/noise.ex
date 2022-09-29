defmodule Noise do
  @moduledoc false

  alias Noise.Socket

  def listen(port) do
    :gen_tcp.listen(port, active: false, mode: :binary)
  end

  def accept(listen_socket) do
    {:ok, socket} = :gen_tcp.accept(listen_socket)
    {:ok, %Socket{tcp_socket: socket, initiator: false}}
  end

  def connect(host, port) do
    {:ok, socket} = :gen_tcp.connect(host, port, active: false, mode: :binary)
    {:ok, %Socket{tcp_socket: socket, initiator: true}}
  end

  @spec handshake(Socket.t(), Keyword.t()) :: {:ok, Socket.t()} | {:error, term()}
  def handshake(%Socket{} = socket, opts) do
    socket
    |> hs_init(opts)
    |> hs_loop()

    {:ok, socket}
  end

  defp hs_init(socket, opts) do
    protocol_name = Keyword.fetch!(opts, :protocol_name)
    prologue = Keyword.get(opts, :prologue, <<>>)
    s = Keyword.get(opts, :s)
    e = Keyword.get(opts, :e)
    rs = Keyword.get(opts, :rs)
    re = Keyword.get(opts, :re)

    %Socket{
      socket
      | handshake_state:
          Noise.HandshakeState.initialize(protocol_name, socket.initiator, prologue, s, rs, e, re)
    }
  end

  defp hs_loop(%Socket{}) do
  end

  @spec close(Socket.t()) :: :ok | {:error, term()}
  def close(%Socket{}) do
    :ok
  end

  @spec connection_information(Socket.t()) :: {:ok, Keyword.t()} | {:error, term()}
  def connection_information(%Socket{}) do
    {:ok, []}
  end
end
