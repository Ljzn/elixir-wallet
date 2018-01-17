defmodule Aewallet.Structs.Bip32PubKey do
  @moduledoc """
  Module for holding the struct for a BIP32 Public key
  """

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
  @mainnet_btc_prefix 0x0488B21E
  @testnet_btc_prefix 0x043587CF

  #Aeternity
  @mainnet_ae_prefix 0x9E86B78E
  @testnet_ae_prefix 0xF350DAF8

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

  @spec create(atom(), atom()) :: t()
  def create(:mainnet, :btc) do
    default(@mainnet_btc_prefix, :btc, :mainnet)
  end

  @spec create(atom(), atom()) :: t()
  def create(:testnet, :btc) do
    default(@testnet_btc_prefix, :btc, :testnet)
  end

  @spec create(atom(), atom()) :: t()
  def create(:mainnet, :ae) do
    default(@mainnet_ae_prefix, :ae, :mainnet)
  end

  @spec create(atom(), atom()) :: t()
  def create(:testnet, :ae) do
    default(@testnet_ae_prefix, :ae, :testnet)
  end

  @spec create(atom(), atom()) :: String.t()
  def create(network, _currency) do
    throw("The given network #{network} is not supported! Please use either :miannet or :testnet")
  end

  @spec default(integer(), atom(), atom()) :: t()
  defp default(version, currency, network) do
    %Aewallet.Structs.Bip32PubKey{
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
