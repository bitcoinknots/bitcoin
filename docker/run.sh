#!/bin/bash

TAG="$1"       # e.g., v29.0.knots20251001
CORES="${2:-4}"  # Optional: for future use if needed

if [ -z "$TAG" ]; then
    echo "Usage: $0 <bitcoin_knots_tag> [cpu_cores]"
    exit 1
fi

# Ensure the data directory exists
mkdir -p "$HOME/bitcoin-knots-data"

# Run the Docker container
docker run -d \
  --name=bitcoinknots \
  -v "$HOME/bitcoin-knots-data:/bitcoin/.bitcoin" \
  -p 8333:8333 \
  -p 8332:8332 \
  "bitcoin-knots:$TAG"

