defmodule Aewallet.Structs.Bip32PrivKey do
  @moduledoc """
  Module for holding the struct for a BIP32 Private key
  """

  @typedoc "Wallet types"
  @type currency :: :ae | :btc

  @typedoc "Network types"
  @type network :: :mainnet | :testnet

  @typedoc "Structure of a key"
  @type t :: %__MODULE__{
          currency: atom(),
          network: atom(),
          version: integer(),
          depth: integer(),
          f_print: binary(),
          child_num: integer(),
          chain_code: binary(),
          key: binary()
        }

  ## Network versions

  # Bitcoin
  @mainnet_btc_prefix 0x0488ADE4
  @testnet_btc_prefix 0x04358394

  #Aeternity
  @mainnet_ae_prefix 0x9E850AC9
  @testnet_ae_prefix 0x9E850AC9

  defstruct [
    :currency,
    :network,
    :version,
    :depth,
    :f_print,
    :child_num,
    :chain_code,
    :key
  ]

  @spec create(network(), currency()) :: t()
  def create(:mainnet, :btc) do
    default(@mainnet_btc_prefix, :mainnet, :btc)
  end
  def create(:testnet, :btc) do
    default(@testnet_btc_prefix, :testnet, :btc)
  end
  def create(:mainnet, :ae) do
    default(@mainnet_ae_prefix, :mainnet, :ae)
  end
  def create(:testnet, :ae) do
    default(@testnet_ae_prefix, :testnet, :ae)
  end
  def create(network, _currency) do
    throw("The given network #{network} is not supported! Please use either :mainnet or :testnet")
  end

  @spec default(integer(), network(), currency()) :: t()
  defp default(version, network, currency) do
    %Aewallet.Structs.Bip32PrivKey{
      currency: currency,
      network: network,
      version: version,
      depth: 0,
      f_print: <<0::32>>,
      child_num: 0,
      chain_code: <<0>>,
      key: <<0>>}
  end
end
