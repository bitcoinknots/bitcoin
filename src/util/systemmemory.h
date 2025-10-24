// Copyright (c) 2023-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_SYSTEMMEMORY_H
#define BITCOIN_UTIL_SYSTEMMEMORY_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

#include <util/memory_profiler.h>

extern size_t g_low_memory_threshold;
extern std::atomic<bool> g_system_needs_memory_released;

/** System memory information */
struct MemoryInfo {
    bool under_pressure = false;
    size_t mem_available = 0;
    size_t mem_used = 0;
    bool is_containerized = false;
};

/** Get current system memory information
 * @return MemoryInfo struct with available/used memory, pressure status, and containerization
 */
MemoryInfo GetMemoryInfo();

/** Initialize memory pressure threshold based on database batch size
 * @param batch_size_bytes Database write batch size in bytes
 */
void InitializeMemoryThreshold(size_t batch_size_bytes);

/** Checks system memory pressure and updates g_system_needs_memory_released flag.
 * This function is called periodically by the scheduler
 */
void CheckMemoryPressure();

bool SystemNeedsMemoryReleased();
void ResetMemoryPressure();
void PauseMemoryPressureChecks();
void ResumeMemoryPressureChecks();

/** Report flush profile data */
void ReportFlushProfile(std::unique_ptr<MemoryProfiler::FlushProfile> profile, size_t cache_size_bytes);

#endif // BITCOIN_UTIL_SYSTEMMEMORY_H
