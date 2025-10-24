// Copyright (c) 2025 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_MEMORY_PROFILER_H
#define BITCOIN_UTIL_MEMORY_PROFILER_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <sync.h>
#include <util/time.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

/**
 * Memory profiler for tracking memory usage during database operations
 * Particularly focused on understanding memory overhead during LevelDB flushes
 */
class MemoryProfiler
{
public:
    struct MemorySample {
        std::chrono::steady_clock::time_point timestamp;
        size_t process_rss_mb;          // Process resident set size
        std::string phase;              // Current operation phase
    };

    struct FlushProfile {
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point end_time;
        size_t pre_flush_memory_mb;
        size_t peak_memory_mb;
        size_t post_flush_memory_mb;
        std::vector<MemorySample> samples;

        int64_t GetDurationMs() const {
            return std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        }
    };

    MemoryProfiler();
    ~MemoryProfiler();

    // Start profiling a flush operation
    void StartFlushProfiling() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    // Stop profiling and return the profile
    std::unique_ptr<FlushProfile> StopFlushProfiling() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    // Get historical flush profiles
    std::vector<FlushProfile> GetRecentProfiles(size_t count = 10) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    void ProfilerThread() NO_THREAD_SAFETY_ANALYSIS;
    MemorySample CaptureMemorySample(const std::string& phase) const NO_THREAD_SAFETY_ANALYSIS;
    MemorySample CaptureMemorySampleLocked(const std::string& phase, bool lock_already_held) const NO_THREAD_SAFETY_ANALYSIS;

    // Platform-specific memory tracking functions
    static size_t GetProcessRSS();

    mutable Mutex m_mutex;

    // Current profiling state
    std::atomic<bool> m_profiling{false};
    std::unique_ptr<FlushProfile> m_current_profile GUARDED_BY(m_mutex);

    // Historical data
    std::deque<FlushProfile> m_flush_history GUARDED_BY(m_mutex);
    static constexpr size_t MAX_HISTORY_SIZE = 100;

    // Profiler thread
    std::unique_ptr<std::thread> m_profiler_thread;
    std::atomic<bool> m_shutdown{false};
    mutable std::mutex m_cv_mutex;
    mutable std::condition_variable m_cv;
};

// Global instance (initialized in init.cpp if profiling is enabled)
extern std::unique_ptr<MemoryProfiler> g_memory_profiler;

#endif // BITCOIN_UTIL_MEMORY_PROFILER_H
