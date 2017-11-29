defmodule KeyPair do
  @moduledoc """
  Module for generating master public and private key
  """


  alias Structs.Bip32PubKey
  alias Structs.Bip32PrivKey


  # Constant for generating the private_key / chain_code
  @bitcoin_const "Bitcoin seed"

  # Integers modulo the order of the curve (referred to as n)
  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  # Mersenne number / TODO: type what it is used for
  @mersenne_prime 2147483647

  @doc """
  Generating a root seed from given mnemonic phrase
  to further ensure uniqueness of master keys.
  ## Example
      iex> KeyPair.generate_root_seed("mnemonic", "pass")

      %{"6C055755B1F6E97DFFC1C40C1BD4919C48938B211139C12C3F04A7F011D8DD20",
      "03C6D13F979E118C97029A3F210AA207CA6695908BA814271472ED1775E4FFBC75",
      <<18, 216, 49, 31, 0, 27, 92, 61, 81, 76, 17, 212, 106, 24, 176, 124, 144, 111,
      182, 17, 157, 236, 54, 168, 91, 92, 99, 234, 76, 232, 20, 169>>
      }
  """
  @spec generate_root_seed(String.t(), String.t(), List.t()) :: Map.t()
  def generate_root_seed(mnemonic, password \\ "", opts \\ []) do
    ## FIX
  end

  def generate_seed(mnemonic, pass_phrase \\ "", opts \\ []) do
    SeedGenerator.generate(mnemonic, pass_phrase, opts)
  end

  def generate_master_key(seed, :seed) do
    generate_master_key(:crypto.hmac(:sha512, @bitcoin_const, seed), :private)
  end

  def generate_master_key(<<priv_key::binary-32, chain_code::binary>>, :private) do
    key = Bip32PrivKey.create(:mainnet)
    key = %{key | key: priv_key, chain_code: chain_code}

    #KeyPair.derive(key, "m/0'/1/2'") |> KeyPair.generate_master_key(:public)
    #KeyPair.format_key(KeyPair.derive(key, "m/0'/1/2'"))
  end
  def generate_master_key(%Bip32PrivKey{} = priv_key, :public) do
    pub_key = KeyPair.generate_pub_key(priv_key)
    key = Bip32PubKey.create(:mainnet)
    #IO.inspect "Private key chain"
    #IO.inspect priv_key.chain_code
    key = %{key |
            depth: priv_key.depth,
            f_print: priv_key.f_print,
            child_num: priv_key.child_num,
            chain_code: priv_key.chain_code,
            key: pub_key}
    #KeyPair.format_key(key)
  end

  def generate_pub_key(%Bip32PrivKey{key: priv_key} = key) do
    {pub_key, _rest} = :crypto.generate_key(:ecdh, :secp256k1, priv_key)
    pub_key
  end
  def generate_pub_key(%Bip32PrivKey{key: priv_key} = key, :compressed) do
    key |> KeyPair.generate_pub_key() |> KeyPair.compress()
  end

  def fingerprint(%Bip32PrivKey{key: priv_key} = key) do
    KeyPair.fingerprint(KeyPair.generate_pub_key(key, :compressed))
  end
  def fingerprint(%Bip32PubKey{key: pub_key} = key) do
    KeyPair.fingerprint(KeyPair.compress(pub_key))
  end
  def fingerprint(pub_key) do
    <<f_print::binary-4, _rest::binary>> =
      :crypto.hash(:ripemd160, :crypto.hash(:sha256, pub_key))
    f_print
  end

  defp serialize(%Bip32PubKey{key: pub_key} = key) do
    compressed_pub_key = KeyPair.compress(pub_key)
    {<<key.version::size(32)>>, <<key.depth::size(8), key.f_print::binary-4,
     key.child_num::size(32), key.chain_code::binary, compressed_pub_key::binary>>}
  end
  defp serialize(%Bip32PrivKey{} = key) do
    {<<key.version::size(32)>>, <<key.depth::size(8), key.f_print::binary-4,
     key.child_num::size(32), key.chain_code::binary, <<0::size(8)>>, key.key::binary>>}
  end

  def format_key(key) when is_map(key) do
    {prefix, data} = serialize(key)
    Base58Check.encode58check(prefix, data)
  end

  def derive(key, <<"m/", path::binary>>) do
    KeyPair.derive_pathlist(
      key,
      :lists.map(fn(elem) ->
        case String.reverse(elem) do
          <<"'", hardened::binary>> ->
            {num, _rest} =
              hardened
              |> String.reverse()
              |> Integer.parse()
            num + @mersenne_prime + 1
          _ ->
            {num, _rest} = Integer.parse(elem)
            num
        end
      end, :binary.split(path, <<"/">>, [:global])))
  end

  def derive_pathlist(key, []), do: key
  def derive_pathlist(key, pathlist) do
    [index | rest] = pathlist
    KeyPair.derive_pathlist(derive_key(key, index), rest)
  end

  def derive_key(%Bip32PrivKey{depth: d} = key, index) when index <= @mersenne_prime do
    # Normal derivation
    compressed_pub_key =
        KeyPair.generate_pub_key(key, :compressed)

    <<derived_key::size(256), child_chain::binary>> =
      :crypto.hmac(:sha512, key.chain_code,
        <<compressed_pub_key::binary, index::size(32)>>)

    <<parent_key_int::size(256)>> = key.key
    child_key = rem(derived_key + parent_key_int, @n)

    KeyPair.derive_key(key, :binary.encode_unsigned(child_key), child_chain, index)
  end

  def derive_key(%Bip32PrivKey{depth: d} = key, index) when index > @mersenne_prime do
    # Hardned derivation
    <<derived_key::size(256), child_chain::binary>> =
      :crypto.hmac(:sha512, key.chain_code,
        <<0::size(8), key.key::binary, index::size(32)>>)

    <<key_int::size(256)>> = key.key
    child_key = rem(derived_key + key_int, @n)
    KeyPair.derive_key(key, :binary.encode_unsigned(child_key), child_chain, index)
  end

  def derive_key(%Bip32PubKey{depth: d} = key, index) when index <= @mersenne_prime do
    # Normal derivation
    serialized_pub_key = KeyPair.compress(key.key)

    <<derived_key::binary-32, child_chain::binary>> =
      :crypto.hmac(:sha512, key.chain_code,
        <<serialized_pub_key::binary, index::size(32)>>)

   # {parent_key_int, _} =
   #   key.key
   #   |> Base.encode16()
   #   |> Integer.parse(16)

    {point, _} = :crypto.generate_key(:ecdh, :secp256k1, derived_key)

    IO.inspect "#################  Parent key compressed  ##################"
    IO.inspect(key.key, limit: :infinity)
    IO.inspect "#################  Compressed Point  ###################"
    IO.inspect(point, limit: :infinity)
    IO.inspect "#################  Derived Key   ###################"
    IO.inspect(derived_key, limit: :infinity)


    {point_int, _} =
      point
      |> Base.encode16()
      |> Integer.parse(16)

    {parent_key_int, _} =
      key.key
      |> Base.encode16()
      |> Integer.parse(16)

    child_key =  point_int + parent_key_int

    l = :binary.encode_unsigned(child_key) |> KeyPair.compress()


    IO.inspect "################## L ##################"
    IO.inspect point_int
    IO.inspect parent_key_int
    KeyPair.derive_key(key, :binary.encode_unsigned(child_key), child_chain, index)
  end

  def derive_key(%Bip32PubKey{depth: d} = key, index) when index > @mersenne_prime do
    # Hardned derivation
    throw("Cannot derive Public Hardened child")
  end

  def derive_key(key, child_key, child_chain, index) when is_map(key) do
    key = %{key |
            key: child_key,
            chain_code: child_chain,
            depth: key.depth+1,
            f_print: KeyPair.fingerprint(key),
            child_num: index}
  end

  @doc """
  Generates wallet address from a given public key
  ## Example
      iex> KeyPair.generate_wallet_address("03AE1B3F8386C6F8B08745E290DA4F7B1B6EBD2287C2505567A2A311BA09EE53F3")
      '1C7RcPXiqwnaJgfvLmoicS3AaBGYyKbiW8'
  """
  @spec generate_wallet_address(String.t()) :: String.t()
  def generate_wallet_address(public_key) do
    public_sha256 = :crypto.hash(:sha256, Base.decode16!(public_key))

    public_ripemd160 = :crypto.hash(:ripemd160, public_sha256)

    # Network ID bytes:
    # Main Network = "0x00"
    # Test Network = "0x6F"
    # Namecoin Net = "0x34"
    public_add_netbytes = <<0x00::size(8), public_ripemd160::binary>>

    checksum = :crypto.hash(:sha256,
      :crypto.hash(:sha256, public_add_netbytes))

    checksum_32bits = <<checksum::binary-4>>
    public_add_netbytes <> checksum_32bits |> Base58Check.encode58()
  end

  def compress(point) do
    first_half =
      point
      |> Base.encode16()
      |> String.slice(2, 128)
      |> String.slice(0, 64)

    second_half =
      point
      |> Base.encode16()
      |> String.slice(2, 128)
      |> String.slice(64, 64)

    {last_digit_int, _} =
      second_half
      |> String.slice(63, 63)
      |> Integer.parse(16)

    case rem(last_digit_int, 2) do
      0 ->
        "02" <> first_half
      _ ->
        "03" <> first_half
    end |> Base.decode16!()
  end
end
