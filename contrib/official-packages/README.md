# Official datadir packages

Bitcoin Purity can bootstrap a new node from pre-built datadir archives published at
`https://downloads.bitcoinpurity.org/`. Each archive contains a pruned or full
`blocks/` and `chainstate/` tree built at a fixed snapshot height.

Package definitions (snapshot height, prune size, download URI, hashes, etc.) are
**not hardcoded in source**. The GUI fetches the current package list from:

- Mainnet: `https://downloads.bitcoinpurity.org/official-packages-mainnet.json`
- Testnet: `https://downloads.bitcoinpurity.org/official-packages-testnet.json`

This list is refreshed each time the first-run wizard loads the sync options, so
new packages can be published without shipping a new client build.

## Local overrides

For testing or air-gapped setups, use one of:

1. `-officialpackages=<path>` on the command line
2. `<datadir>/official-packages-<chain>.json` (optional per-node override)

Filenames tried in the datadir include `official-packages-main.json`,
`official-packages-mainnet.json` (mainnet alias), and `official-packages.json`.

Example local testing:

```bash
bitcoin-qt -officialpackages=/path/to/official-packages-mainnet.json
```

### JSON format

```json
{
  "packages": [
    {
      "id": "mainnet-910000-prune-2gb",
      "snapshot_height": 910000,
      "base_blockhash": "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
      "prune_mib": 1907,
      "download_uri": "https://downloads.bitcoinpurity.org/mainnet/mainnet-910000-prune-2gb.zip",
      "archive_sha256": "...",
      "archive_size_bytes": 8589934592,
      "extracted_size_bytes": 4294967296
    }
  ]
}
```

| Field | Description |
|---|---|
| `id` | Unique package identifier stored in settings |
| `snapshot_height` | Block height of the chainstate inside the archive |
| `base_blockhash` | Block hash at `snapshot_height` (validated after extraction) |
| `prune_mib` | `0` = full node; `>= 550` = automatic prune target in MiB |
| `download_uri` | Official download URL for the `.zip` archive |
| `archive_sha256` | SHA256 of the compressed archive (required, non-zero) |
| `archive_size_bytes` | Estimated download size (for UI disk-space hints) |
| `extracted_size_bytes` | Estimated size after extraction (for UI disk-space hints) |

## Package contents

Each `.zip` archive must contain:

```
blocks/
chainstate/
bitcoinpurity-package.json
```

The manifest file documents the package identity and is validated on extraction:

```json
{
  "id": "mainnet-910000-prune-2gb",
  "snapshot_height": 910000,
  "base_blockhash": "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
  "prune_mib": 1907
}
```

Do **not** include user-specific files such as `bitcoin.conf`, `settings.json`,
`wallets/`, or log files.

## Building a package

1. Sync a node to the desired snapshot height with the target prune setting.
2. Stop the node cleanly.
3. From the network data directory, archive only the required paths:

```bash
DATADIR=~/.bitcoin
HEIGHT=910000
PACKAGE_ID=mainnet-910000-prune-2gb
PRUNE_MIB=1907
WORKDIR=$(mktemp -d)

cat > "${WORKDIR}/bitcoinpurity-package.json" <<EOF
{
  "id": "${PACKAGE_ID}",
  "snapshot_height": ${HEIGHT},
  "base_blockhash": "<block hash at height>",
  "prune_mib": ${PRUNE_MIB}
}
EOF

(cd "${DATADIR}" && zip -r "${WORKDIR}/${PACKAGE_ID}.zip" blocks chainstate)
(cd "${WORKDIR}" && zip -u "${PACKAGE_ID}.zip" bitcoinpurity-package.json)
```

4. Compute the archive SHA256:

```bash
sha256sum "${WORKDIR}/${PACKAGE_ID}.zip"
```

5. Upload the archive to the URI referenced in the JSON config.

6. Add or update the package entry in the remote `official-packages-<chain>.json`
   hosted at `https://downloads.bitcoinpurity.org/`. No client recompile is required.

## Download behaviour

The GUI downloader uses resumable HTTP downloads when the server supports
`Accept-Ranges: bytes`. Partial data is stored under `<datadir>/.package-download/`
and can be resumed after cancellation or restart; metadata is saved in a sidecar
`*.download.json` file next to the archive.

## Supported combinations

The GUI intro wizard only exposes packages listed in the fetched JSON configuration.
Each entry is a fixed combination of snapshot height and storage mode.

When adding a new package:

1. Build and verify the archive on a clean machine.
2. Update the remote `official-packages-<chain>.json` on downloads.bitcoinpurity.org.
3. Publish the archive to the matching download URI.
