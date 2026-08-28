# Official datadir packages

Bitcoin Purity can bootstrap a new node from pre-built datadir archives published at
`https://bitcoinpurity.org/downloads/`. Each archive contains a pruned or full
`blocks/` and `chainstate/` tree built at a fixed snapshot height.

Package definitions (snapshot height, prune size, download URI, hashes, etc.) are
**not hardcoded in source**. They are loaded from a JSON configuration file that
operators can edit without recompiling.

## Example configuration

The files under `contrib/official-packages/` are **templates only**. The `download_uri`
and `archive_sha256` values are placeholders until real packages are built, uploaded,
and the JSON is updated with the final URL and hash. If you try to download before
publication, the client will report an HTTP 404 error.

For local testing, point `download_uri` at a `file://` URL for a real archive you
built yourself, and set `archive_sha256` to the computed hash.

Default search order:

1. `-officialpackages=<path>` if passed on the command line
2. `<datadir>/official-packages-<chain>.json` (optional per-node override)
3. Shipped defaults in `contrib/official-packages/` (baked into the build via `OFFICIAL_PACKAGES_DIR`)

Filenames tried for each location include `official-packages-main.json`,
`official-packages-mainnet.json` (mainnet alias), and `official-packages.json`.

The example file ships with the source tree at
`contrib/official-packages/official-packages-mainnet.json`. No copy into the
datadir is required on first launch.

Or point to a custom file explicitly while testing:

```bash
bitcoin-qt -officialpackages=contrib/official-packages/official-packages-mainnet.json
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
      "download_uri": "https://bitcoinpurity.org/downloads/mainnet/mainnet-910000-prune-2gb.zip",
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

6. Add or update the package entry in `official-packages-<chain>.json` with the
   final URI, SHA256, snapshot height, and prune size. No client recompile is
   required.

## Download behaviour

The GUI downloader uses parallel HTTP range requests (up to 4 connections) when
the server supports `Accept-Ranges: bytes`. Partial data is stored under
`<datadir>/.package-download/` and can be resumed after cancellation or restart;
metadata is saved in a sidecar `*.download.json` file next to the archive.

## Supported combinations

The GUI intro wizard only exposes packages listed in the JSON configuration file.
Each entry is a fixed combination of snapshot height and storage mode.

When adding a new package:

1. Build and verify the archive on a clean machine.
2. Update `contrib/official-packages/official-packages-<chain>.json` (or a datadir override).
3. Publish the archive to the matching download URI.
