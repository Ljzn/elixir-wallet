defmodule PublicKeyAndAddressTest do
  use ExUnit.Case
  doctest ElixirWallet

  alias ElixirWallet.KeyPair, as: KeyPair

  test "validate master public key and address 1" do
    seed =
      "32a3872fee61310785f3aaf291076c32263b50fed3c4f7936b9ec46f9fccd6aa9ecb63d04edaf7053c36a84dc86c5f915b2ea4ee1c1194beb5cca98c0cdb8a67"
      |> Base.decode16!(case: :mixed)
    master_key = KeyPair.generate_master_key(seed, :btc)
    public_key = master_key |> KeyPair.derive("M/0'/0")

    public_key_hex  = public_key.key |> Base.encode16()

    assert "04C5064CAD681B04D4CBD50198FEE0097FA3068854D7CDEE9BAFAA64A8C35671510B5306DEC898029411F13BAC5C0EED959AE0A63933AC50058E2ADE278FED9341"
    = public_key_hex

    address = KeyPair.generate_wallet_address(public_key.key, :btc)
    assert "1A8Yu17z49C8dihg9yeRCcAS8eG4wshi6C" = address
  end

  test "validate master public key and address 2" do
    seed =
      "5d791beef4d18793be196e5979eef6fdd691b2eefedb9fd6318091da0bc10078e25b7c608379804645139ff6107a99c63eff3b301eef936b948c4fcc68703e8e"
      |> Base.decode16!(case: :mixed)
    master_key = KeyPair.generate_master_key(seed, :btc)
    public_key = master_key |> KeyPair.derive("M/43'/1234/123/10")

    public_key_hex = public_key.key |> Base.encode16()

    assert "04C405A99D6131A57A87EEA17405E6F3A64F58460B02B2AACCD2B9D019EB0E364A91A1037E1E2AAD068711AD39672AABD23E76D1F8C40EBA9167907F5FF194A281"
    = public_key_hex

    address = KeyPair.generate_wallet_address(public_key.key, :btc)
    assert "1LZe26kABKYsdSD2FTJCsr2Zx1w2JGQ6hd" = address
  end

  test "validate master public key and address 3" do
    seed =
      "805d65b4e11c1cd47b5049f1f150f34a0dfea3e30c351be3a502da8f29bae7f2d90563670de9086e86c25c98e7bb1b729cacfecf7d4c50a95120476d0419eaae"
      |> Base.decode16!(case: :mixed)
    master_key = KeyPair.generate_master_key(seed, :btc)
    public_key = master_key |> KeyPair.derive("M/4342'/12323232/7")

    public_key_hex = public_key.key |> Base.encode16()

    assert "0493C4C922B503F7F58FBEFCF866E1BDA93D5891B9CF52DC292FF3958294A0F1147D72FA8671EDC3CD131D61366D39A74FBD59CFA1643E7878F1A05CE51921A20A"
    = public_key_hex

    address = KeyPair.generate_wallet_address(public_key.key, :btc)
    assert "1Q5PyZ8df2L8LnpZxheQmesiCxYrEJRdo2" = address
  end

end
