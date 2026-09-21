### Verify Binaries

#### Preparation

As of Bitcoin Knots v21.x, releases are signed by a number of public keys on the basis
of the [guix.sigs repository](https://github.com/bitcoinknots/guix.sigs/). When
verifying binary downloads, you (the end user) decide which of these public keys you
trust and then use that trust model to evaluate the signature on a file that contains
hashes of the release binaries. The downloaded binaries are then hashed and compared to
the signed checksum file.

First, you have to figure out which public keys to recognize. Browse the [list of frequent
builder-keys](https://github.com/bitcoinknots/guix.sigs/tree/knots/builder-keys) and
decide which of these keys you would like to trust. For each key you want to trust, you
must obtain that key for your local GPG installation.

You can obtain these keys by
  - through a browser using a key server (e.g. keyserver.ubuntu.com),
  - manually using the `gpg --keyserver <url> --recv-keys <key>` command, or
  - you can run the packaged `verify.py --import-keys ...` script to
    have it automatically retrieve unrecognized keys.

#### Usage

This script attempts to download the checksum file (`SHA256SUMS`) and corresponding
signature file `SHA256SUMS.asc` from https://bitcoinknots.org and
https://github.com/bitcoinknots/bitcoin/releases.

It first checks if the checksum file is valid based upon a plurality of signatures, and
then downloads the release files specified in the checksum file, and checks if the
hashes of the release files are as expected.

If we encounter pubkeys in the signature file that we do not recognize, the script
can prompt the user as to whether they'd like to download the pubkeys. To enable
this behavior, use the `--import-keys` flag.

The script returns 0 if everything passes the checks. It returns 1 if either the
signature check or the hash check doesn't pass. An exit code of >2 indicates an error.

See the `Config` object for various options.

#### Examples

Validate releases with default settings:
```sh
./contrib/verify-binaries/verify.py pub 29.1.knots20250903
./contrib/verify-binaries/verify.py pub 27.1.knots20240801
```

Get JSON output and don't prompt for user input (no auto key import):

```sh
./contrib/verify-binaries/verify.py --json pub 29.1.knots20250903-x86
./contrib/verify-binaries/verify.py --json pub 27.1.knots20240801-win64
```

Require all hosts (bitcoinknots.org / github.com) to provide identical
checksums and signature files:

```sh
./contrib/verify-binaries/verify.py --json pub --require-all-hosts 29.1.knots20250903-x86
./contrib/verify-binaries/verify.py --json pub --require-all-hosts 27.1.knots20240801-win64
```

Rely only on local GPG state and manually specified keys, while requiring a
threshold of at least 10 trusted signatures:
```sh
./contrib/verify-binaries/verify.py \
    --trusted-keys 1A3E761F19D2CC7785C5502EA291A2C45D0C504A,F4FC70F07310028424EFC20A8E4256593F177720 \
    --min-good-sigs 10 pub 29.1.knots20250903-linux
```

If you only want to download the binaries for a certain architecture and/or platform, add the corresponding suffix, e.g.:

```sh
./contrib/verify-binaries/verify.py pub 25.1.knots20231115-x86_64-linux
./contrib/verify-binaries/verify.py pub 23.0.knots20220529-darwin
./contrib/verify-binaries/verify.py pub 27.1.knots20240801-win64-setup.exe
```

If you do not want to keep the downloaded binaries, specify the cleanup option.

```sh
./contrib/verify-binaries/verify.py pub --cleanup 29.1.knots20250903
```

Use the bin subcommand to verify all files listed in a local checksum file

```sh
./contrib/verify-binaries/verify.py bin SHA256SUMS
```

Verify only a subset of the files listed in a local checksum file

```sh
./contrib/verify-binaries/verify.py bin ~/Downloads/SHA256SUMS \
    ~/Downloads/bitcoin-23.0.knots20220529-x86_64-linux-gnu.tar.gz \
    ~/Downloads/bitcoin-23.0.knots20220529-arm-linux-gnueabihf.tar.gz
```
