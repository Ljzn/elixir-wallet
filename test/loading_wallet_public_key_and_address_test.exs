defmodule LoadPublicKeyAndAddressTest do
  use ExUnit.Case
  doctest ElixirWallet

  test "validate master public key and address 1" do
    mnemonic = Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-35-48", "password")
    assert {:ok, "bulk\r property\r loop\r pen\r fuel\r wild\r gorilla\r say\r pond\r rigid\r torch\r budget"}
    = mnemonic

    {:ok, public_key} =
      Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-35-48", "password")

    assert public_key == Base.decode16!("04C232B177F8EDB01290C3FEDBE5231BDF67AEF24F4C7947B06A298C5CDA573E16ADB2A621525C44222D29E113B315508B32364584EDF99F8DE7E0D7C2D2A871AB")

    {:ok, address} = Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-35-48", "password")
    assert address == "1JWrJcwMRbxXk68nmA2gQ9Ly4BT7GhuAyt"
  end

  test "validate master public key and address 2" do
    mnemonic = Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-35-57", "password")
    assert {:ok, "able\r actress\r bring\r rebuild\r clean\r timber\r flash\r grace\r tribe\r trial\r income\r brother"}
    = mnemonic

    {:ok, public_key} =
      Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-35-57", "password")

    assert public_key == Base.decode16!("04BCD5FBFE8563FD97AFAEBAEB3B81CF22D10AD89FC905ECF5BFCE85849E417458100A66C442A942DC512181A4563AFFF3604F1F7D553FBF1A50B788F9102D1DA8")

    {:ok, address} = Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-35-57", "password")
    assert address == "1PruVefxahxDZcWiVYU7nYZxrMHKS97qvW"
  end

   test "validate master public key and address 3" do
    mnemonic = Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-35-58", "password")
    assert {:ok, "tenant\r thrive\r marble\r magnet\r chief\r taxi\r enhance\r verb\r session\r saddle\r venue\r during"}
    = mnemonic

    {:ok, public_key} =
      Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-35-58", "password")

    assert public_key == Base.decode16!("044A4435503E7E324C9AE6B966C9F43CEECCDEAE192969AD2C6E9E5963AC65E62C9C21D1CC395E8C8639B30975471B588191A67C084F0AAD08D63E6F33CA47D348")

    {:ok, address} = Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-35-58", "password")
    assert address == "12C72EW63jLCaDXfmqk6DcjUoUykdD6Xhn"
  end

  test "validate master public key and address 4" do
    mnemonic = Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-35-59", "password")
    assert {:ok, "drum\r pledge\r man\r fame\r sort\r favorite\r doll\r color\r device\r remove\r angry\r jelly"}
    = mnemonic

    {:ok, public_key} =
      Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-35-59", "password")

    assert public_key == Base.decode16!("04B9A2BF7834AF55B1BC4356F74A11D8A8D1AA4CFC9635699FCE71C2F9186B5EC07EE55CC8452A9C3535589EA12D792FEA4E907C2FE0E1E0AEAF91D86E033607C1")

    {:ok, address} = Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-35-59", "password")
    assert address == "13F4jMJmUFV9rmoWgGND1jBfwgQbTKpPuv"
  end

  test "validate master public key and address 5" do
    mnemonic = Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-36-0", "password")
    assert {:ok, "year\r wage\r suggest\r cream\r good\r length\r umbrella\r ridge\r winter\r giant\r blast\r improve"}
    = mnemonic

    {:ok, public_key} =
      Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-36-0", "password")

    assert public_key == Base.decode16!("048BF1724D1C9695D74D3948E59C89EDC1156FF9159A073507C76E99BC45F2008CC05E7BBC7F50E00311EFF62D46C8F66C4DB39D77274F0F2D0F7DE5606E8A16E8")

    {:ok, address} = Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-36-0", "password")
    assert address == "1LfdSWu1eEijd6GzTh8SASMsTU8wDgbtfB"
  end
end
