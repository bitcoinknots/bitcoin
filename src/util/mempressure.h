// Copyright (c) 2023-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_MEMPRESSURE_H
#define BITCOIN_UTIL_MEMPRESSURE_H

#include <cstddef>
#include <cstdint>

extern size_t g_low_memory_threshold;

bool SystemNeedsMemoryReleased();
uint64_t GetTotalSystemMemory();

#endif // BITCOIN_UTIL_MEMPRESSURE_H
