defmodule PublicKeyAndAddressTest do
  use ExUnit.Case
  doctest ElixirWallet

  test "validate master public key and address 1" do
    seed =
      "32a3872fee61310785f3aaf291076c32263b50fed3c4f7936b9ec46f9fccd6aa9ecb63d04edaf7053c36a84dc86c5f915b2ea4ee1c1194beb5cca98c0cdb8a67"
      |> Base.decode16!(case: :mixed)
    master_key = KeyPair.generate_master_key(seed, :seed)
    public_key = master_key |> KeyPair.derive("M/0'/0")

    public_key_hex =
      public_key.key
      |> KeyPair.compress()
      |> Base.encode16(case: :lower)

    assert "03c5064cad681b04d4cbd50198fee0097fa3068854d7cdee9bafaa64a8c3567151"
    = public_key_hex

    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "15V1MArcmSz2HJPPBYpiGMjE3qf3NWvqVr"
  end

  test "validate master public key and address 2" do
    seed =
      "5d791beef4d18793be196e5979eef6fdd691b2eefedb9fd6318091da0bc10078e25b7c608379804645139ff6107a99c63eff3b301eef936b948c4fcc68703e8e"
      |> Base.decode16!(case: :mixed)
    master_key = KeyPair.generate_master_key(seed, :seed)
    public_key = master_key |> KeyPair.derive("M/43'/1234/123/10")

    public_key_hex =
      public_key.key
      |> KeyPair.compress()
      |> Base.encode16(case: :lower)

    assert "03c405a99d6131a57a87eea17405e6f3a64f58460b02b2aaccd2b9d019eb0e364a"
    = public_key_hex

    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "1AxB5DQqFVXpEAvfjzFPSRUHSqKY9w6YNQ"
  end

  test "validate master public key and address 3" do
    seed =
      "805d65b4e11c1cd47b5049f1f150f34a0dfea3e30c351be3a502da8f29bae7f2d90563670de9086e86c25c98e7bb1b729cacfecf7d4c50a95120476d0419eaae"
      |> Base.decode16!(case: :mixed)
    master_key = KeyPair.generate_master_key(seed, :seed)
    public_key = master_key |> KeyPair.derive("M/4342'/12323232/7")

    public_key_hex =
      public_key.key
      |> KeyPair.compress()
      |> Base.encode16(case: :lower)

    assert "0293c4c922b503f7f58fbefcf866e1bda93d5891b9cf52dc292ff3958294a0f114"
    = public_key_hex

    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "1GWgbn38wFCq5VT8PAMJ4DkzUj2RUnpGrX"
  end

end
