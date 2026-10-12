# Analysis Code

The `code` directory preserves the scripts used in the research workflow.

## Scripts

- `phase1/run_address_label_agreement.py`: extracts address-label records and builds the first address-overlap analysis.
- `phase3/run_analysis.py`: adds the three newer address datasets and applies label-reliability preprocessing.
- `phase4/audit_account_types.py`: distinguishes EOA, delegated EOA, and conventional contract addresses using on-chain bytecode checks.
- `phase4/restandardize_label_analysis.py`: generates the final label-attribute mapping, intersection table, pair comparison, conflict-cause table, summary, and individual-review table.
- `verify_manifest.py`: verifies packaged data files against their recorded SHA-256 checksums.

## Environment

The analysis scripts primarily use the Python standard library. Phase 1 also invokes `pdftotext` for an auxiliary PDF extractor, and the account-type audit requires Ethereum JSON-RPC access.

The preserved scripts contain paths from the original Windows analysis environment. Update the base path constants or expose equivalent directory paths before rerunning them on another machine.

## Recommended execution order

```text
phase1/run_address_label_agreement.py
phase3/run_analysis.py
phase4/audit_account_types.py
phase4/restandardize_label_analysis.py
```

The final repository results correspond to the most recent strict taxonomy and dataset-level root-source-set methodology. Earlier scripts are retained for provenance, not as competing final definitions.

