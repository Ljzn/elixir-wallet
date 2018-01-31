defmodule Aewallet.Wallet do
  @moduledoc """
  This module is used for creation of the Wallet file. To inspect it use
  WalletCrypto.decrypt_wallet("wallet_file_name", "password", "mnemonic_phrase")
  """

  alias Aewallet.KeyPair, as: KeyPair
  alias Aewallet.Cypher, as: Cypher
  alias Aewallet.Mnemonic, as: Mnemonic
  alias Aewallet.Indexes, as: Indexes

  @typedoc "Wallet option key"
  @type wallet_key :: :type

  @typedoc "Wallet option value"
  @type wallet_value :: :ae | :btc

  @typedoc "Wallet options list"
  @type wallet_opts :: [{wallet_key, wallet_value}]

  @typedoc "Network option key"
  @type network_key :: :network

  @typedoc "Network option value"
  @type network_value :: :mainnet | :testnet

  @typedoc "Network options list"
  @type network_opts :: [{network_key, network_value}]

  @doc """
  Creates a wallet file. You can use the short function to create an Aeternity wallet
  without using pass_phrase, or use the full function and fill the parameters.

  ## Options

  The accepted options are:

    * `:type` - specifies the type of wallet

  The values for `:type` are:

    * `:ae` - creates an Aeternity wallet
    * `:btc` - creates a Bitcoin wallet

  ## Examples
      iex> Wallet.create_wallet(password, path)
      Use the following phrase as additional authentication
      when accessing you wallet:

      whisper edit clump violin blame few ancient casual
      sand trip update spring
  """
  @spec create_wallet(String.t(), String.t()) :: String.t()
  def create_wallet(password, path) do
    create_wallet(password, path, "", [])
  end
  @spec create_wallet(String.t(), String.t(), String.t(), wallet_opts()) :: String.t()
  def create_wallet(password, path, pass_phrase \\ "", opts \\ []) do
    mnemonic_phrase = Mnemonic.generate_phrase(Indexes.generate_indexes)
    type = Keyword.get(opts, :type, :ae)

    {:ok, wallet_data} = build_wallet(mnemonic_phrase, pass_phrase, type)
    {:ok, file_path} = save_wallet_file(wallet_data, password, path)
    {:ok, mnemonic_phrase, file_path, type}
  end

  @doc """
  Creates a wallet file from an existing mnemonic_phrase and password
  If the wallet was not password protected, just pass the mnemonic_phrase
  """
  @spec import_wallet(String.t(), String.t(), String.t()) :: String.t()
  def import_wallet(mnemonic_phrase, password, path) do
    import_wallet(mnemonic_phrase, password, path, "", [])
  end
  @spec import_wallet(String.t(), String.t(), String.t(), String.t(), wallet_opts()) :: String.t()
  def import_wallet(mnemonic_phrase, password, path, pass_phrase \\ "", opts \\ []) do
    type = Keyword.get(opts, :type, :ae)

    {:ok, wallet_data} = build_wallet(mnemonic_phrase, pass_phrase, type)
    {:ok, file_path} = save_wallet_file(wallet_data, password, path)
    {:ok, mnemonic_phrase, file_path, type}
  end

  @doc """
  Loads the wallet data
    * Mnemonic phrase
    * Wallet type
    * Pass_phrase (if given when wallet was created)

  ## Example
      iex> Aewallet.Wallet.load_wallet_file(file_path, password)
      {:ok,
      "amazing feed doctor wing town furnace need hat public that derive athlete",
      :ae}
  """
  @spec load_wallet_file(String.t(), String.t()) :: tuple()
  def load_wallet_file(file_path, password) do
    load_wallet(File.read(file_path), password)
  end

  @doc """
  Gets the public key. Will only return a public key
  if the password is correct. Set a desired network with the options
  The default network is `:mainnet`.

  ## Options
  The accepted options are:
    * `:network` - specifies the network

  The values for `:network` can be:
    * `:mainnet` - (default)
    * `:testnet`

  ## Examples
      iex> Wallet.get_public_key(wallet_path, password)
      {:ok, <<4, 210, 200, 166, 81, 219, 54, 116, 39, 64, 199, 57, 55, 152, 204, 119, 237,
      168, 175, 243, 132, 39, 71, 208, 94, 138, 190, 242, 78, 74, 141, 43, 58, 241,
      15, 19, 179, 45, 42, 79, 118, 24, 160, 20, 64, 178, 109, 124, 172, 127, ...>>, wallet_type}

      iex> Wallet.get_private_key(file_path, password, network: :mainnet)
      {:ok, private_key_for_mainnet}

      iex> Wallet.get_private_key(file_path, password, network: :testnet)
      {:ok, private_key_for_testnet}
  """
  @spec get_public_key(String.t(), String.t(), network_opts()) :: tuple()
  def get_public_key(path, password, opts \\ []) do
    network = Keyword.get(opts, :network, :mainnet)
    case load_wallet_file(path, password) do
      {:ok, mnemonic, wallet_type} ->
        master_key =
          mnemonic
          |> KeyPair.generate_seed()
          |> KeyPair.generate_master_key(network, [type: wallet_type])

        public_key = KeyPair.to_public_key(master_key)
        {:ok, public_key.key, wallet_type}

      {:ok, mnemonic, wallet_type, pass_phrase} ->
        master_key =
          mnemonic
          |> KeyPair.generate_seed(pass_phrase)
          |> KeyPair.generate_master_key(network, type: wallet_type)

        public_key = KeyPair.to_public_key(master_key)
        {:ok, public_key.key, wallet_type}

      {:error, message} ->
        {:error, message}
    end
  end

  @doc """
  Gets the wallet address. Will only return an address if
  the password is correct. Set a desired network with the options
  The default network is `:mainnet`.
  ## Options
  The accepted options are:
    * `:network` - specifies the network

  The values for `:network` can be:
    * `:mainnet` - (default)
    * `:testnet`

  ## Examples
      iex> Wallet.get_address(file_path, password)
      {:ok, "A1M51tw1MixFCe64g6ExhCEXnowEGrQ2DE"}

      iex> Wallet.get_address(file_path, password, network: :mainnet)
      {:ok, "A1M51tw1MixFCe64g6ExhCEXnowEGrQ2DE"}

      iex> Wallet.get_address(file_path, password, network: :tesnet)
      {:ok, "T6d3d2a14FiXGe17g8ExhCBAnfe4GrD2h5"}
"""
  @spec get_address(String.t(), String.t(), network_opts()) :: tuple()
  def get_address(file_path, password, opts \\ []) do
    network = Keyword.get(opts, :network, :mainnet)
    case get_public_key(file_path, password) do
      {:ok, pub_key, wallet_type} ->
        address = KeyPair.generate_wallet_address(pub_key, network, wallet_type)
        {:ok, address}

      {:error, message} ->
        {:error, message}
    end
  end

  @doc """
  Gets the private key. Will only return a private key if
  the password is correct. Set a desired network with the options
  The default network is `:mainnet`.

  ## Options
  The accepted options are:
    * `:network` - specifies the network

  The values for `:network` can be:
    * `:mainnet` - (default)
    * `:testnet`

  ## Examples
      iex> Wallet.get_private_key(file_path, password)
      {:ok, <<100, 208, 92, 132, 43, 104, 6, 55, 125, 18, 18, 215, 98, 8, 245, 12, 78, 92,
      89, 115, 59, 231, 28, 142, 137, 119, 62, 19, 102, 238, 171, 185>>}

      iex> Wallet.get_private_key(file_path, password, network: :mainnet)
      {:ok, private_key_for_mainnet}

      iex> Wallet.get_private_key(file_path, password, network: :testnet)
      {:ok, private_key_for_testnet}
  """
  @spec get_private_key(String.t(), String.t(), network_opts()) :: tuple()
  def get_private_key(file_path, password, opts \\ []) do
    network = Keyword.get(opts, :network, :mainnet)
    case load_wallet_file(file_path, password) do
      {:ok, mnemonic, wallet_type} ->
        private_key =
          mnemonic
          |> KeyPair.generate_seed()
          |> KeyPair.generate_master_key(network, type: wallet_type)
        {:ok, private_key.key}

      {:ok, mnemonic, wallet_type, pass_phrase} ->
        private_key =
          mnemonic
          |> KeyPair.generate_seed(pass_phrase)
          |> KeyPair.generate_master_key(network, type: wallet_type)
        {:ok, private_key.key}

      {:error, message} ->
        {:error, message}
    end
  end

  ## Private functions

  for {type, wallet_type} <- [ae: :ae, btc: :btc] do
    defp build_wallet(mnemonic, pass_phrase, unquote(type)) do
      {:ok, mnemonic
            |> Kernel.<>(" ")
            |> Kernel.<>(Atom.to_string(unquote(wallet_type)))
            |> Kernel.<>(" ")
            |> Kernel.<>(pass_phrase)}
    end
  end

  @spec save_wallet_file(String.t(), String.t(), String.t()) :: tuple()
  defp save_wallet_file(wallet_data, password, path) do
    {{year, month, day}, {hours, minutes, seconds}} = :calendar.local_time()
    file_name = "wallet--#{year}-#{month}-#{day}-#{hours}-#{minutes}-#{seconds}"
    file_dir =
      case path do
        "" ->
          default_dir = File.cwd! <> "/wallet"
          File.mkdir(default_dir)
          default_dir
        _ ->
          path
      end

    file_path = Path.join(file_dir, file_name)
    case File.open(file_path, [:write]) do
      {:ok, file} ->
        encrypted = Cypher.encrypt(wallet_data, password)
        IO.binwrite(file, encrypted)
        File.close(file)
        {:ok, file_path}

      {:error, message} ->
        throw("The path you have given has thrown an #{message} error!")
    end
  end

  @spec load_wallet(tuple(), String.t()) :: tuple()
  defp load_wallet({:ok, encrypted_data}, password) do
    wallet_data = Cypher.decrypt(encrypted_data, password)
    if String.valid? wallet_data do
      data_list = String.split(wallet_data)
      mnemonic =
        data_list
        |> Enum.slice(0..11)
        |> Enum.join(" ")
      wallet_type =
        data_list
        |> Enum.at(12)
        |> String.to_atom()
      case Enum.at(data_list, 13) do
        :nil ->
          {:ok, mnemonic, wallet_type}
        pass_phrase ->
          {:ok, mnemonic, wallet_type, pass_phrase}
        _ ->
          {:ok, mnemonic, wallet_type}
      end
    else
      {:error, "Invalid password"}
    end
  end
  defp load_wallet({:error, reason}, _password) do
    case reason do
      :enoent ->
        {:error, "The file does not exist."}
      :eaccess ->
        {:error, "Missing permision for reading the file,
        or for searching one of the parent directories."}
      :eisdir ->
        {:error, "The named file is a directory."}
      :enotdir ->
        {:error, "A component of the file name is not a directory."}
      :enomem ->
        {:error, "There is not enough memory for the contents of the file."}
    end
  end
end
