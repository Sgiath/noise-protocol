defmodule Noise.VectorsTest do
  use ExUnit.Case

  alias Noise.VectorRunner

  @cacophony_vectors "test/vectors/cacophony.json"
  @noise_c_basic_vectors "test/vectors/noise-c-basic.json"
  @noise_c_fallback_vectors "test/vectors/noise-c-fallback.json"
  @noise_c_hybrid_vectors "test/vectors/noise-c-hybrid.json"
  @snow_vectors "test/vectors/snow.json"
  @snow_extended_vectors "test/vectors/snow-extended.json"

  @external_resource @cacophony_vectors
  @external_resource @noise_c_basic_vectors
  @external_resource @noise_c_fallback_vectors
  @external_resource @noise_c_hybrid_vectors
  @external_resource @snow_vectors
  @external_resource @snow_extended_vectors

  for {file, prefix} <- [
        {@cacophony_vectors, "cacophony"},
        {@noise_c_basic_vectors, "noise-c-basic"},
        {@noise_c_fallback_vectors, "noise-c-fallback"},
        {@noise_c_hybrid_vectors, "noise-c-hybrid"},
        {@snow_vectors, "snow"},
        {@snow_extended_vectors, "snow-extended"},
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
