FROM ubuntu:22.04

LABEL maintainer="you@example.com"
LABEL description="Bitcoin Knots built from source with --disable-wallet"

# Build args
ARG BITCOIN_KNOTS_TAG=v28.1.knots20250305
ARG CPU_CORES=4

# Set env for usage
ENV USERNAME=bitcoin
ENV HOME_DIR=/home/$USERNAME
ENV BITCOIN_SRC_DIR=$HOME_DIR/bitcoin

# Install dependencies
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

# Create user
RUN useradd -m -s /bin/bash $USERNAME

# Switch to user
USER $USERNAME
WORKDIR $HOME_DIR

# Clone and build Bitcoin Knots
RUN git clone https://github.com/bitcoinknots/bitcoin.git && \
    cd bitcoin && \
    git fetch --tags && \
    git checkout $BITCOIN_KNOTS_TAG && \
    ./autogen.sh && \
    ./configure --disable-wallet --disable-zmq --prefix=$BITCOIN_SRC_DIR && \
    make -j$CPU_CORES && \
    make install

# Back to root for running the daemon
USER root

# ✅ Add to root user's PATH as well (affects docker exec)
ENV PATH="/home/bitcoin/bitcoin/bin:${PATH}"

# Expose standard Bitcoin ports
EXPOSE 8333 8332

# Data directory as a volume
VOLUME ["/bitcoin/.bitcoin"]


# Run bitcoind on container start
ENTRYPOINT ["/home/bitcoin/bitcoin/bin/bitcoind", "-datadir=/bitcoin/.bitcoin", "-printtoconsole"]
