defmodule Noise.Socket do
  defstruct [:tcp_socket, :initiator, :handshake_state]

  @type t() :: %__MODULE__{}
end
