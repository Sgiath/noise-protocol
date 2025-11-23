defmodule Noise.VectorsTest do
  use ExUnit.Case

  alias Noise.VectorRunner

  @cacophony_vectors "test/vectors/cacophony.json"
  @snow_vectors "test/vectors/snow.json"
  @snow_extended_vectors "test/vectors/snow-extended.json"

  @external_resource @cacophony_vectors
  @external_resource @snow_vectors
  @external_resource @snow_extended_vectors

  for {file, prefix} <- [
        {@cacophony_vectors, "cacophony"},
        {@snow_vectors, "snow"},
        # {@snow_extended_vectors, "snow-extended"},
      ] do
    if File.exists?(file) do
      vectors = VectorRunner.load_vectors_from_file(file)

      for vector <- vectors do
        name = vector["name"] || vector["protocol_name"] || "unknown"
        test_name = "#{prefix}: #{name}"

        reason = VectorRunner.skip_reason(vector)

        @tag :vectors
        if reason do
          @tag skip: reason
        end
        test test_name do
          VectorRunner.run_vector(unquote(Macro.escape(vector)))
        end
      end
    end
  end
end
