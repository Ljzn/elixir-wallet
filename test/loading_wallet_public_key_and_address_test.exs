defmodule LoadPublicKeyAndAddressTest do
  use ExUnit.Case
  doctest Aewallet

  alias Aewallet.Wallet, as: Wallet
  alias Aewallet.Cypher, as: Cypher

  test "validate master public key and address 1" do
    wallet_data = Wallet.load_wallet_file("test/test_wallets/wallet--2018-1-17-11-59-25", "password")
    assert wallet_data =
    {:ok, "day slot wink brother tip program motion kite trash excuse assume debris", :ae}

    {:ok, public_key} =
      Wallet.get_public_key("test/test_wallets/wallet--2018-1-17-11-59-25", "password")

    assert public_key ==
      Base.decode16!("0443C79213D6301FB19C50CEFCBBC2EE80CD53ACEFE9D4FB1FEE4E1DD3863F643095C24FD54EF4959A554B3461726B789D4D8E0C97526C3A18A39E16B326FF6D5A")

    {:ok, address} =
      Wallet.get_address("test/test_wallets/wallet--2018-1-17-11-59-25", "password")

    assert address == "Aw1EeJtR3xNmi5fy6Mu9xL8xqzKPzrY36w"
  end

  test "validate master public key and address 2" do
    wallet_data = Wallet.load_wallet_file("test/test_wallets/wallet--2018-1-17-12-9-55", "password")
    assert wallet_data =
    {:ok, "bacon olympic warfare link crystal liberty mechanic husband age scan glance job", :btc}

    {:ok, public_key} =
      Wallet.get_public_key("test/test_wallets/wallet--2018-1-17-12-9-55", "password")

    assert public_key ==
      Base.decode16!("04C64160211603FB738BFD69AFEC4BC675D7AEDB7BDD06D5CC661D33EA3021AAD4FDA318B310487FBFF91DEC887F13E57394EEBB3FD34876F1793F7D427BD17718")

    {:ok, address} =
      Wallet.get_address("test/test_wallets/wallet--2018-1-17-12-9-55", "password")

    assert address == "1LZsufgWrF6WbS5e39J4jiMJNwWpHEGA75"
  end

   test "validate master public key and address 3" do
    wallet_data = Wallet.load_wallet_file("test/test_wallets/wallet--2018-1-17-12-12-16", "password")
    assert wallet_data =
    {:ok, "dial prevent prize already actual hammer alarm warfare crunch recipe tide bind", :ae, "1234"}

    {:ok, public_key} =
      Wallet.get_public_key("test/test_wallets/wallet--2018-1-17-12-12-16", "password")

    assert public_key ==
      Base.decode16!("04169FE30E399CC4B6BF5CFCB8CD7091D462D5B50E8082C7D9C0A54080E77BE056777BB1596050E34462131AA07C24196E108CBD890AC9A7EA19665BB5F6E6A142")

    {:ok, address} =
      Wallet.get_address("test/test_wallets/wallet--2018-1-17-12-12-16", "password")

    assert address == "Ar4VeTDWQFE97LDFQ2De2Gg4fHf2FHeRqP"
  end
end
