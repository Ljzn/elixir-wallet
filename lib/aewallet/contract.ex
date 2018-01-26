defmodule Aewallet.Contract do
  @moduledoc """
  This module is responsible for Encryption and Decryption of a file
  using a public and it's corresponding private key
  """

  alias Aewallet.Cypher, as: Cypher
  alias Aewallet.Signing, as: Signing

  @typedoc "Checks if the file is encrypted or not"
  @type option :: :encrypted | :decrypted

  @typedoc "Structure of a contract struct"
  @type t :: %__MODULE__{
          helper_key: binary(),
          hash: binary(),
          signature: binary(),
          contract_data: binary()
        }

  defstruct [:helper_key, :hash, :signature, :contract_data]

  @doc """
  Responsible for encrypting a contract file,
  signing the it with the senders private keym
  and saving the encrypted file to a specified location.
  """
  @spec encrypt_and_sign(String.t(), binary(), binary()) :: tuple()
  def encrypt_and_sign(contract_path, pub_key, priv_key) do

    {:ok, contract_data} = read_file(File.read(contract_path), contract_path)

    hash = :crypto.hash(:sha256, contract_data)
    signature = Signing.sign(contract_data, priv_key)

    {:ok, helper_key, encrypted_contract} = do_encrypt(contract_data, pub_key)

    contract_struct = build_contract_struct(helper_key, hash, signature, encrypted_contract)
    struct_binary = :erlang.term_to_binary(contract_struct)

    save_file(struct_binary, contract_path, :encrypted)
  end

  @doc """
  Responsible for decrypting a contract file with the
  corresponding private key, verifying the signature with
  the senders public keyand saving the decrypted contract
  in a specified location with a specified extension.
  """
  @spec decrypt_and_verify(String.t(), binary(), binary()) :: tuple()
  def decrypt_and_verify(contract_path, pub_key, priv_key) do

    {:ok, contract_data} = read_file(File.read(contract_path), contract_path)

    %Aewallet.Contract{
      helper_key: helper_key,
      signature: signature,
      contract_data: encrypted_contract
    } = :erlang.binary_to_term(contract_data)

    {:ok, decrypted_contract} = do_decrypt(encrypted_contract, helper_key, priv_key)

    case Signing.verify(decrypted_contract, signature, pub_key) do
      :false ->
        {:error, "Signature does not match!"}

      :true ->
        {:ok, contract_path} = save_file(decrypted_contract, contract_path, :decrypted)
        {:ok, "Signature matches!", contract_path}
    end
  end

  ## Private functions.

  @spec read_file(tuple(), String.t()) :: tuple()
  defp read_file({:ok, contract_data}, _file_path) do
    {:ok, contract_data}
  end
  defp read_file({:error, reason}, file_path) do
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
        :encrypted ->
          4
          |> :crypto.strong_rand_bytes()
          |> Base.encode16()

        ## TODO: Make the name of the file more specific
        :decrypted ->
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

  @spec do_encrypt(String.t(), binary()) :: tuple()
  defp do_encrypt(contract_data, pub_key) do
    rand = :crypto.strong_rand_bytes(32)

    {:ok, encryptor} = :libsecp256k1.ec_pubkey_tweak_mul(pub_key, rand)
    {helper_key, _} = :crypto.generate_key(:ecdh, :secp256k1, rand)

    encrypted_contract = Cypher.encrypt(contract_data, encryptor)

    {:ok, helper_key, encrypted_contract}
  end

  @spec do_decrypt(binary(), binary(), binary()) :: tuple()
  defp do_decrypt(encrypted_contract, helper_key, priv_key) do

    {:ok, decryptor} = :libsecp256k1.ec_pubkey_tweak_mul(helper_key, priv_key)
    decrypted_contract = Cypher.decrypt(encrypted_contract, decryptor)

    {:ok, decrypted_contract}
  end

  @spec build_contract_struct(binary(), binary(), binary(), binary()) :: t()
  defp build_contract_struct(helper_key, hash, signature, encrypted_contract) do
    %Aewallet.Contract{
      helper_key: helper_key,
      hash: hash,
      signature: signature,
      contract_data: encrypted_contract
    }
  end

end
