# Builder stage: build Bitcoin Knots from source
FROM debian:bookworm-slim AS builder

ARG BITCOIN_KNOTS_TAG=v28.1.knots20250305
ARG CPU_CORES=4

ENV USERNAME=bitcoin
ENV HOME_DIR=/home/$USERNAME
ENV BITCOIN_SRC_DIR=$HOME_DIR/bitcoin

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libtool \
    autotools-dev \
    automake \
    pkg-config \
    bsdmainutils \
    curl \
    git \
    gnupg \
    libevent-dev \
    libboost-system-dev \
    libboost-filesystem-dev \
    libboost-test-dev \
    libboost-thread-dev \
    libminiupnpc-dev \
    libnatpmp-dev \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a user
RUN useradd -m -s /bin/bash $USERNAME

USER $USERNAME
WORKDIR $HOME_DIR

# Clone and build Bitcoin Knots
RUN git clone https://github.com/bitcoinknots/bitcoin.git && \
    git -C bitcoin fetch --tags && \
    git -C bitcoin checkout $BITCOIN_KNOTS_TAG && \
    cd bitcoin && \
    ./autogen.sh && \
    ./configure --disable-wallet --disable-zmq --prefix=$BITCOIN_SRC_DIR && \
    make -j$CPU_CORES && \
    make install

# Runtime stage: smaller image with only runtime deps + binaries
FROM debian:bookworm-slim

ENV USERNAME=bitcoin
ENV HOME_DIR=/home/$USERNAME

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libevent-dev \
    libboost-system-dev \
    libboost-filesystem-dev \
    libboost-test-dev \
    libboost-thread-dev \
    libminiupnpc-dev \
    libnatpmp-dev \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -m -s /bin/bash $USERNAME

# Copy binaries from builder
COPY --from=builder /home/bitcoin/bitcoin/bin /home/bitcoin/bitcoin/bin

# Add binary path to PATH
ENV PATH="/home/bitcoin/bitcoin/bin:${PATH}"

# Expose standard Bitcoin ports
EXPOSE 8333 8332


# Volume for blockchain data
VOLUME ["/bitcoin/.bitcoin"]

RUN mkdir -p /bitcoin/.bitcoin && \
    chown -R bitcoin:bitcoin /bitcoin

USER bitcoin

ENTRYPOINT ["bitcoind", "-datadir=/bitcoin/.bitcoin", "-printtoconsole"]

