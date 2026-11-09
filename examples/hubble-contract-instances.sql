-- Latest instance entry for every Soroban contract, from Stellar's Hubble
-- dataset on BigQuery. Export the result as CSV or JSON Lines and pass it to
-- `advisory-watch report --inventory`.
--
-- Column names come from the Hubble data dictionary (bronze `contract_data`)
-- and stellar-etl's transform code: `contract_data_xdr` is a base64
-- ContractDataEntry, and instance rows have
-- contract_key_type = 'ScValTypeScvLedgerKeyContractInstance'.
--
-- Status: not yet run against BigQuery by the maintainers. Check the table
-- path and cost before running. The table is partitioned by `closed_at`, so
-- this query scans every partition. See the open issue
-- "Verify and document the Hubble inventory query".
SELECT
  contract_id,
  contract_data_xdr
FROM (
  SELECT
    contract_id,
    contract_data_xdr,
    deleted,
    ROW_NUMBER() OVER (
      PARTITION BY contract_id
      ORDER BY ledger_sequence DESC
    ) AS rn
  FROM `crypto-stellar.crypto_stellar.contract_data`
  WHERE contract_key_type = 'ScValTypeScvLedgerKeyContractInstance'
)
WHERE rn = 1
  AND deleted = FALSE;
