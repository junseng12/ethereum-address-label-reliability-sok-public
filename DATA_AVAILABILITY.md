# Data Availability and Redistribution Review

## Recommended repository mode

Use a private GitHub repository for the complete collaboration package. The package contains exact research inputs, final results, code, documentation, checksums, and upstream version identifiers.

Do not make the complete package public until every third-party dataset has been reviewed for redistribution permission.

## Public release policy

For a public repository, retain the following even when a raw file must be removed:

- dataset name;
- upstream repository or download URL;
- pinned commit or snapshot date;
- exact upstream-relative file path;
- file size;
- SHA-256 checksum;
- extraction and preprocessing code;
- derived aggregate results that are permitted to be shared.

## License findings in the local snapshot

| Dataset | Local license finding | Recommended handling |
|---|---|---|
| EtherScamDB | MIT | Redistributable with license and attribution |
| Forta Labelled Datasets | MIT | Redistributable with license and attribution |
| scamsonethereum | GPL-3.0 | Retain GPL notice and source obligations |
| EX-Graph | CC BY-NC-SA 4.0 | Non-commercial sharing with attribution and share-alike conditions |
| OFAC | Official U.S. government distribution | Preserve snapshot date and official source |
| Remaining datasets | No explicit license file found in the local snapshot | Private only pending license review |

This table records a local artifact review, not legal advice. Upstream terms may change and should be checked before publication.

## GitHub capacity

The selected analysis inputs are approximately 2.86 GiB. Final analysis outputs are approximately 1.31 GiB. Large objects are configured for Git LFS. The full 15-dataset source directories are not included because they contain unrelated model artifacts and multi-gigabyte graph files that were not used in the address-label analysis.

