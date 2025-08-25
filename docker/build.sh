#!/bin/bash

TAG="$1"  # e.g., v29.0.knots20251001
CORES="${2:-4}"

if [ -z "$TAG" ]; then
    echo "Usage: $0 <bitcoin_knots_tag> [cpu_cores]"
    exit 1
fi

docker build \
  --build-arg BITCOIN_KNOTS_TAG="$TAG" \
  --build-arg CPU_CORES="$CORES" \
  -t "bitcoin-knots:$TAG" .
