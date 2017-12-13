defmodule Structs.Bip32PubKey do
  @moduledoc """
  Module for holding the struct for a BIP32 Public key
  """

  ## Network versions

  # Bitcoin
  @mainnet_btc_prefix 0x0488B21E
  @testnet_btc_prefix 0x043587CF

  #Aeternity
  @mainnet_ae_prefix 0x9E850AC9
  @testnet_ae_prefix 0x043587CF

  defstruct [:currency, :version, :depth, :f_print, :child_num, :chain_code, :key]

  def create(:mainnet, :btc) do
    default(@mainnet_btc_prefix, :btc)
  end
  def create(:testnet, :btc) do
    default(@testnet_btc_prefix, :btc)
  end
  def create(:mainnet, :ae) do
    default(@mainnet_ae_prefix, :ae)
  end
  def create(:testnet, :ae) do
    default(@testnet_ae_prefix, :ae)
  end

  defp default(version, currency) do
    %Structs.Bip32PubKey{
      currency: currency,
      version: version,
      depth: 0,
      f_print: <<0::32>>,
      child_num: 0,
      chain_code: <<0>>,
      key: <<0>>}
  end
end
