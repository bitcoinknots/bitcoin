// Copyright (c) 2023-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_MEMPRESSURE_H
#define BITCOIN_UTIL_MEMPRESSURE_H

#include <cstddef>
#include <cstdint>

extern size_t g_low_memory_threshold;

/** Returns available system memory in bytes, or 0 if unknown. */
uint64_t GetAvailableSystemMemory();

bool SystemNeedsMemoryReleased();

#endif // BITCOIN_UTIL_MEMPRESSURE_H
