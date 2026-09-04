#!/usr/bin/env bash
#
# Copyright (c) 2026-present The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

if [ "$(uname -m)" = "aarch64" ]; then
  export CONTAINER_NAME=ci_native_yyjson_arm64
else
  export CONTAINER_NAME=ci_native_yyjson
fi
export LC_ALL=C.UTF-8
export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"
export PACKAGES="clang llvm libevent-dev libboost-dev libsqlite3-dev"
export NO_DEPENDS=1
export RUN_UNIT_TESTS=true
export RUN_FUNCTIONAL_TESTS=false
export GOAL="install"
export BITCOIN_CONFIG="-DWITH_YYJSON=ON -DBUILD_GUI=OFF"