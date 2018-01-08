defmodule Aewallet.Structs.Bip32PrivKey do
  @moduledoc """
  Module for holding the struct for a BIP32 Private key
  """

  ## Network versions

  # Bitcoin
  @mainnet_btc_prefix 0x0488ADE4
  @testnet_btc_prefix 0x04358394

  #Aeternity
  @mainnet_ae_prefix 0x9E850AC9
  @testnet_ae_prefix 0x9E850AC9

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
    %Aewallet.Structs.Bip32PrivKey{
      currency: currency,
      version: version,
      depth: 0,
      f_print: <<0::32>>,
      child_num: 0,
      chain_code: <<0>>,
      key: <<0>>}
  end
end
