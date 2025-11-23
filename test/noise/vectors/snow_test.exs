defmodule Noise.Vectors.SnowTest do
  use ExUnit.Case, async: true
  alias Noise.VectorRunner

  @vectors_file "test/vectors/snow.json"
  @external_resource @vectors_file

  if File.exists?(@vectors_file) do
    vectors = VectorRunner.load_vectors_from_file(@vectors_file)

    for vector <- vectors do
      name = vector["name"] || vector["protocol_name"] || "unknown"

      @tag :vectors
      test "snow: #{name}" do
        VectorRunner.run_vector(unquote(Macro.escape(vector)))
      end
    end
  end
end


