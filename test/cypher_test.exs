defmodule CypherTest do
  use ExUnit.Case
  doctest Aewallet

  alias Aewallet.Cypher, as: Cypher

  test "encrypt and decrypt data" do
    text_to_encrypt = "wallet oringe smell wall open door chair broom"
    password = "fall65me32to77be"
    encrypted_data = Cypher.encrypt(text_to_encrypt, password)

    assert Cypher.decrypt(encrypted_data, password) == text_to_encrypt
  end
end
