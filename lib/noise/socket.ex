defmodule Noise.Socket do
  defstruct [:tcp_socket]

  @type t() :: %__MODULE__{}
end
