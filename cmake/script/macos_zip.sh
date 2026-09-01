#!/bin/sh
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

export LC_ALL=C

if [ -n "$SOURCE_DATE_EPOCH" ]; then
  find . -exec touch -d "@$SOURCE_DATE_EPOCH" {} +
else
  find . -exec touch {} +
fi

if [ -n "${3:-}" ] && [ -d Bitcoin-Qt.app ] && [ "$3" != "Bitcoin-Qt.app" ]; then
  rm -rf -- "$3"
  mv Bitcoin-Qt.app "$3"
fi

rm -f -- "$2"
find . | sort | "$1" -y -X@ "$2"
