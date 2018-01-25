defmodule Aewallet.Contract do
  @moduledoc """
  This module is responsible for Encryption and Decryption of a file
  using a public and it's corresponding private key
  """

  alias Aewallet.Cypher, as: Cypher

  @typedoc ""
  @type option :: :encrypt | :decrypt

  @doc """
  Responsible for encrypting a contract file and saving the
  encrypted file to a specified location.
  """
  @spec encrypt(String.t(), binary()) :: tuple()
  def encrypt(file_path, pub_key) do
    {:ok, contract_data} = read_file(File.read(file_path), pub_key, file_path)
    {:ok, encrypted_data} = do_encrypt(contract_data, pub_key, file_path)
    save_file(encrypted_data, file_path, :encrypt)
  end

  @doc """
  Responsible for decrypting a contract file with the
  corresponding private keyand and saving the decrypted version
  in a specified location with a specified extension.
  """
  @spec decrypt(String.t(), binary()) :: tuple()
  def decrypt(file_path, priv_key) do
    {:ok, contract_data} = read_file(File.read(file_path), priv_key, file_path)
    {:ok, decrypted_data} = do_decrypt(contract_data, priv_key, file_path)
    save_file(decrypted_data, file_path, :decrypt)
  end

  ## Private functions.

  @spec read_file(tuple(), binary(), String.t()) :: tuple()
  defp read_file({:ok, contract_data}, pub_key, file_path) do
    {:ok, contract_data}
  end

  @spec read_file(tuple(), binary(), String.t()) :: tuple()
  defp read_file({:error, reason}, _key, file_path) do
    case reason do
      :enoent ->
        {:error, "The file at #{file_path} does not exist."}
      :eaccess ->
        {:error, "Missing permision for reading the #{file_path} file,
        or for searching one of the parent directories."}
      :eisdir ->
        {:error, "The named file - #{file_path} is a directory."}
      :enotdir ->
        {:error, "A component of the file - #{file_path} name is not a directory."}
      :enomem ->
        {:error, "There is not enough memory for the contents of the file."}
    end
  end

  @spec save_file(binary(), String.t(), option()) :: tuple()
  defp save_file(data, file_path, option) do
    file_name =
      case option do
        :encrypt ->
          4
          |> :crypto.strong_rand_bytes()
          |> Base.encode16()

        ## TODO: Make the name of the file more specific
        :decrypt ->
          "Contract"
      end

    new_path =
      file_path
      |> String.split("/")
      |> Enum.drop(-1)
      |> Enum.join("/")
      |> Kernel.<>("/")
      |> Kernel.<>(file_name)
      |> Kernel.<>(".pdf")

    {File.write!(new_path, data), new_path}
  end

  @spec do_encrypt(String.t(), binary(), String.t()) :: tuple()
  defp do_encrypt(contract_data, pub_key, file_path) do
    rand = :crypto.strong_rand_bytes(32)

    {:ok, encryptor} = :libsecp256k1.ec_pubkey_tweak_mul(pub_key, rand)
    {helper_key, _} = :crypto.generate_key(:ecdh, :secp256k1, rand)

    encrypted_contract = Cypher.encrypt(contract_data, encryptor)

    {:ok, helper_key <> encrypted_contract}
  end

  @spec do_decrypt(binary(), binary(), String.t()) :: tuple()
  defp do_decrypt(encrypted_data, priv_key, file_path) do
    <<helper_key::binary-65, contract_data::binary>> = encrypted_data

    {:ok, decryptor} = :libsecp256k1.ec_pubkey_tweak_mul(helper_key, priv_key)
    decrypted_contract = Cypher.decrypt(contract_data, decryptor)

    {:ok, decrypted_contract}
  end

end
