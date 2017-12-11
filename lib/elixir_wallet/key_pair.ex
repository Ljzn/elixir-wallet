defmodule KeyPair do
  @moduledoc """
  Module for generating master public and private key
  """

  alias Structs.Bip32PubKey, as: PubKey
  alias Structs.Bip32PrivKey, as: PrivKey

  # Constant for generating the private_key / chain_code
  @bitcoin_key "Bitcoin seed"

  # Integers modulo the order of the curve (referred to as n)
  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  # Mersenne number / TODO: type what it is used for
  @mersenne_prime 2_147_483_647

  def generate_seed(mnemonic, pass_phrase \\ "", opts \\ []) do
    SeedGenerator.generate(mnemonic, pass_phrase, opts)
  end

  def generate_master_key(seed_bin, :seed) do
    generate_master_key(:crypto.hmac(:sha512, @bitcoin_key, seed_bin), :private)
  end

  def generate_master_key(<<priv_key::binary-32, c_code::binary>>, :private) do
    key = PrivKey.create(:mainnet)
    key = %{key | key: priv_key, chain_code: c_code}
  end
  def to_public_key(%PrivKey{} = priv_key) do
    pub_key = KeyPair.generate_pub_key(priv_key)
    key = PubKey.create(:mainnet)
    key = %{key |
            depth: priv_key.depth,
            f_print: priv_key.f_print,
            child_num: priv_key.child_num,
            chain_code: priv_key.chain_code,
            key: pub_key}
  end

  def generate_pub_key(%PrivKey{key: priv_key} = key) do
    {pub_key, _rest} = :crypto.generate_key(:ecdh, :secp256k1, priv_key)
    pub_key
  end
  def generate_pub_key(%PrivKey{key: priv_key} = key, :compressed) do
    key
    |> KeyPair.generate_pub_key()
    |> KeyPair.compress()
  end

  def fingerprint(%PrivKey{key: priv_key} = key) do
    key
    |> KeyPair.generate_pub_key(:compressed)
    |> KeyPair.fingerprint()
  end
  def fingerprint(%PubKey{key: pub_key} = key) do
    pub_key
    |> KeyPair.compress()
    |> KeyPair.fingerprint()
  end
  def fingerprint(pub_key) do
    <<f_print::binary-4, _rest::binary>> =
      :crypto.hash(:ripemd160, :crypto.hash(:sha256, pub_key))
    f_print
  end

  defp serialize(%PubKey{key: pub_key} = key) do
    compressed_pub_key = KeyPair.compress(pub_key)
    {<<key.version::size(32)>>,
     <<key.depth::size(8),
     key.f_print::binary-4,
     key.child_num::size(32),
     key.chain_code::binary,
     compressed_pub_key::binary>>}
  end
  defp serialize(%PrivKey{} = key) do
    {<<key.version::size(32)>>,
     <<key.depth::size(8),
     key.f_print::binary-4,
     key.child_num::size(32),
     key.chain_code::binary,
     <<0::size(8)>>, key.key::binary>>}
  end

  def format_key(key) when is_map(key) do
    {prefix, data} = serialize(key)
    Base58Check.encode58check(prefix, data)
  end

  def derive(key, <<"m/", path::binary>>) do ## Deriving private keys
    KeyPair.derive(key, path, :private)
  end
  def derive(key, <<"M/", path::binary>>) do ## Deriving public keys
    derive(key, path, :public)
  end
  def derive(key, path, type) do
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
      end, :binary.split(path, <<"/">>, [:global])),
      type)
  end

  def derive_pathlist(key, [], :private), do: key
  def derive_pathlist(key, [], :public), do: KeyPair.to_public_key(key)
  def derive_pathlist(key, pathlist, type) do
    [index | rest] = pathlist
    key
    |> derive_key(index)
    |> KeyPair.derive_pathlist(rest, type)
  end

  def derive_key(%PrivKey{} = key, index) when index > -1 and index <= @mersenne_prime do
    # Normal derivation
    compressed_pub_key =
        KeyPair.generate_pub_key(key, :compressed)

    <<derived_key::size(256), child_chain::binary>> =
      :crypto.hmac(:sha512, key.chain_code,
        <<compressed_pub_key::binary, index::size(32)>>)

    <<parent_key_int::size(256)>> = key.key
    child_key = :binary.encode_unsigned(rem(derived_key + parent_key_int, @n))

    KeyPair.derive_key(key, child_key, child_chain, index)
  end

  def derive_key(%PrivKey{} = key, index) when index > @mersenne_prime do
    # Hardned derivation
    <<derived_key::size(256), child_chain::binary>> =
      :crypto.hmac(:sha512, key.chain_code,
        <<0::size(8), key.key::binary, index::size(32)>>)

    <<key_int::size(256)>> = key.key
    child_key = :binary.encode_unsigned(rem(derived_key + key_int, @n))

    KeyPair.derive_key(key, child_key, child_chain, index)
  end

  def derive_key(%PubKey{} = key, index) when index > -1 and index <= @mersenne_prime do
    # Normal derivation
    serialized_pub_key = KeyPair.compress(key.key)

    <<derived_key::size(256), child_chain::binary>> =
      :crypto.hmac(:sha512, key.chain_code,
        <<serialized_pub_key::binary, index::size(32)>>)

    {point, _} = :crypto.generate_key(:ecdh, :secp256k1, derived_key)

    <<point_int::size(520)>> = point
    <<parent_key_int::size(264)>> = serialized_pub_key

    child_key = :binary.encode_unsigned(point_int + parent_key_int)
    KeyPair.derive_key(key, child_key, child_chain, index)
  end

  def derive_key(%PubKey{}, index) when index > @mersenne_prime do
    # Hardned derivation
    raise(RuntimeError, "Cannot derive Public Hardened child")
  end

  def derive_key(key, child_key, child_chain, index) when is_map(key) do
    key = %{key |
            key: child_key,
            chain_code: child_chain,
            depth: key.depth + 1,
            f_print: KeyPair.fingerprint(key),
            child_num: index}
  end

  @doc """
  Generates wallet address from a given public key
  ## Example
      iex> KeyPair.generate_wallet_address(pub_key_binary)
      '1C7RcPXiqwnaJgfvLmoicS3AaBGYyKbiW8'
  """
  @spec generate_wallet_address(Binary.t()) :: String.t()
  def generate_wallet_address(public_key) do
    public_sha256 = :crypto.hash(:sha256, public_key)

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

    compressed_key =
      case rem(last_digit_int, 2) do
        0 ->
          "02" <> first_half
        _ ->
          "03" <> first_half
      end
    Base.decode16!(compressed_key)
  end
end
