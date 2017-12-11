defmodule HttpRequest do
  @moduledoc """
  Holds the HttpRequest functions
  """

  def get_info(url, endpoint) do
    json = HTTPoison.get!(url <> endpoint)
  end
end
