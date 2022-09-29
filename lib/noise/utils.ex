defmodule Noise.Utils do
  @moduledoc false

  def hex(nil), do: nil

  def hex(data) do
    Base.encode16(data, case: :lower)
  end
end
