# syntax=docker/dockerfile:1
FROM alpine:3.22 AS builder

ARG RDTS_CONSENT="UNSET"

RUN <<EORUN
  cat <<\EOSCRIPT >/tmp/rdts_check
    case "$(echo "$RDTS_CONSENT" | tr '[:lower:]' '[:upper:]')" in
        1|ON|YES|TRUE|Y) RDTS_CONSENT="IMPLICIT" ;;
    esac
    case "$RDTS_CONSENT" in
        RUNTIME_CHECK|IMPLICIT)
            ;;
        *)
            red=$(printf '\033[31m')
            term_reset=$(printf '\033[0m')
            cat <<EOF >&2

${red}ERROR: RDTS_CONSENT is not set.

This version of Bitcoin Knots applies the BIP110 (RDTS) network upgrade, which fixes critical vulnerabilities in long-standing network design. To avoid applying this upgrade by accident, please choose whether to accept it now, or defer explicit confirmation until runtime.

Important: Because this upgrade already has broad community support, reverting to an older software version does not reject it. Running outdated software after any network upgrade only leaves your node vulnerable to displaying fake or fraudulent transactions. To effectively reject this upgrade, you need to run alternative software designed to split away from the upgraded network.

To accept this upgrade now, add to your Docker build arguments:

  --build-arg RDTS_CONSENT=IMPLICIT

Or to defer explicit confirmation until runtime (via consensusrules=rdts config setting):

  --build-arg RDTS_CONSENT=RUNTIME_CHECK

For more information, see: https://bitcoinknots.org/learn/2026-rdts ${term_reset}
EOF
            exit 1
            ;;
    esac
EOSCRIPT
EORUN

RUN . /tmp/rdts_check

RUN apk add --no-cache \
    build-base \
    cmake \
    boost-dev \
    libevent-dev \
    sqlite-dev \
    zeromq-dev \
    coreutils \
    binutils

WORKDIR /opt/bitcoin

COPY . .

WORKDIR /opt/bitcoin/build

RUN cmake .. \
    -D RDTS_CONSENT="${RDTS_CONSENT}" \
    -DCMAKE_INSTALL_PREFIX="/usr/local/" \
    -DBUILD_DAEMON="ON" \
    -DBUILD_CLI="ON" \
    -DENABLE_WALLET="ON" \
    -DWITH_ZMQ="ON" \
    -DBUILD_TESTS="ON" \
    -DBUILD_GUI="OFF" \
    -DBUILD_TX="OFF" \
    -DBUILD_UTIL="OFF" \
    -DBUILD_WALLET_TOOL="OFF" \
    -DBUILD_BENCH="OFF" \
    -DBUILD_FUZZ_BINARY="OFF" \
    -DBUILD_UTIL_CHAINSTATE="OFF" \
    -DWITH_BDB="OFF" \
    -DWITH_USDT="OFF" \
    -DINSTALL_MAN="OFF" \
    -DWITH_CCACHE="OFF"

RUN cmake --build . --parallel $(nproc)
RUN ctest --output-on-failure
RUN cmake --install .

RUN strip --strip-unneeded /usr/local/bin/*

FROM alpine:3.22 AS final

ARG RDTS_CONSENT
LABEL org.bitcoinknots.rdts_consent="${RDTS_CONSENT}"

ARG USER_ID=1000
ARG GROUP_ID=1000

RUN apk add --no-cache \
    libevent \
    sqlite-libs \
    zeromq \
    boost-system \
    boost-filesystem \
    boost-program_options

COPY --from=builder /usr/local/bin/bitcoind     /usr/local/bin/bitcoind
COPY --from=builder /usr/local/bin/bitcoin-cli  /usr/local/bin/bitcoin-cli

RUN addgroup -S -g ${GROUP_ID} bitcoin && \
    adduser -S -u ${USER_ID} -G bitcoin -H -s /bin/false bitcoin

WORKDIR /var/lib/bitcoind
EXPOSE 8333 8332
USER bitcoin
VOLUME ["/var/lib/bitcoind", "/etc/bitcoin/bitcoin.conf"]

ENTRYPOINT ["bitcoind", "-conf=/etc/bitcoin/bitcoin.conf", "-datadir=/var/lib/bitcoind"]

HEALTHCHECK --interval=5m --timeout=15s --start-period=2m --start-interval=10s \
    CMD ["bitcoin-cli", "-conf=/etc/bitcoin/bitcoin.conf", "-datadir=/var/lib/bitcoind", "getblockchaininfo"]
