// Copyright (c) 2023-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_MEMPRESSURE_H
#define BITCOIN_UTIL_MEMPRESSURE_H

#include <atomic>
#include <cstddef>
#include <cstdint>

extern size_t g_low_memory_threshold;
extern std::atomic<bool> g_system_needs_memory_released;

/** Memory pressure information returned by platform-specific checks */
struct MemoryPressureInfo {
    bool under_pressure = false;
    size_t mem_available = 0;
    size_t mem_used = 0;
    bool is_containerized = false;
};

/** Checks system memory pressure and updates g_system_needs_memory_released flag.
 * This function is called periodically by the scheduler
 */
void CheckMemoryPressure();

bool SystemNeedsMemoryReleased();
void PauseMemoryPressureChecks();
void ResumeMemoryPressureChecks();

#endif // BITCOIN_UTIL_MEMPRESSURE_H
