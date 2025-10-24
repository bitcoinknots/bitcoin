// Copyright (c) 2025 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <util/memory_profiler.h>

#include <algorithm>

#ifdef WIN32
#include <windows.h>
#include <psapi.h>
#elif defined(__linux__)
#include <fstream>
#include <sstream>
#include <string>
#elif defined(__APPLE__)
#include <sys/resource.h>
#include <mach/mach.h>
#endif

std::unique_ptr<MemoryProfiler> g_memory_profiler;

MemoryProfiler::MemoryProfiler()
{
    m_profiler_thread = std::make_unique<std::thread>(&MemoryProfiler::ProfilerThread, this);
}

MemoryProfiler::~MemoryProfiler()
{
    m_shutdown = true;
    {
        std::lock_guard<std::mutex> cv_lock(m_cv_mutex);
        m_cv.notify_all();
    }
    if (m_profiler_thread && m_profiler_thread->joinable()) {
        m_profiler_thread->join();
    }
}

size_t MemoryProfiler::GetProcessRSS()
{
#ifdef WIN32
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        return static_cast<size_t>(pmc.PrivateUsage);  // Current commit charge
    }
#elif defined(__linux__)
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.compare(0, 8, "RssAnon:") == 0) {
            size_t pos = line.find_first_of("0123456789");
            if (pos != std::string::npos) {
                size_t kb = std::stoull(line.substr(pos));
                return kb * 1024;
            }
        }
    }
#elif defined(__APPLE__)
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) == KERN_SUCCESS) {
        return static_cast<size_t>(info.resident_size);
    }
#endif
    return 0;
}

void MemoryProfiler::StartFlushProfiling()
{
    // Check if already profiling and stop previous profile if needed
    if (m_profiling.load()) {
        StopFlushProfiling();
    }

    LOCK(m_mutex);

    m_current_profile = std::make_unique<FlushProfile>();
    m_current_profile->start_time = std::chrono::steady_clock::now();

    // Capture initial memory state (lock already held)
    auto initial_sample = CaptureMemorySampleLocked("pre_flush", true);
    m_current_profile->pre_flush_memory_mb = initial_sample.process_rss_mb;
    m_current_profile->peak_memory_mb = initial_sample.process_rss_mb;
    m_current_profile->samples.push_back(initial_sample);

    m_profiling = true;

    // Notify profiler thread
    {
        std::lock_guard<std::mutex> cv_lock(m_cv_mutex);
        m_cv.notify_one();
    }
}

std::unique_ptr<MemoryProfiler::FlushProfile> MemoryProfiler::StopFlushProfiling()
{
    LOCK(m_mutex);

    if (!m_current_profile) {
        return nullptr;
    }

    m_profiling = false;

    // Capture final memory state
    auto final_sample = CaptureMemorySampleLocked("post_flush", true);
    m_current_profile->samples.push_back(final_sample);
    m_current_profile->post_flush_memory_mb = final_sample.process_rss_mb;
    m_current_profile->end_time = std::chrono::steady_clock::now();

    // Calculate peak from all samples
    for (const auto& sample : m_current_profile->samples) {
        m_current_profile->peak_memory_mb = std::max(m_current_profile->peak_memory_mb, sample.process_rss_mb);
    }

    // Store in history
    m_flush_history.push_back(*m_current_profile);
    if (m_flush_history.size() > MAX_HISTORY_SIZE) {
        m_flush_history.pop_front();
    }

    return std::move(m_current_profile);
}

std::vector<MemoryProfiler::FlushProfile> MemoryProfiler::GetRecentProfiles(size_t count) const
{
    LOCK(m_mutex);

    std::vector<FlushProfile> result;
    size_t start_idx = m_flush_history.size() > count ? m_flush_history.size() - count : 0;

    for (size_t i = start_idx; i < m_flush_history.size(); ++i) {
        result.push_back(m_flush_history[i]);
    }

    return result;
}

void MemoryProfiler::ProfilerThread()
{
    while (!m_shutdown) {
        std::unique_lock<std::mutex> cv_lock(m_cv_mutex);

        m_cv.wait_for(cv_lock, std::chrono::milliseconds(100), [this] {
            return m_profiling.load() || m_shutdown.load();
        });

        cv_lock.unlock();

        if (m_shutdown) break;

        if (m_profiling) {
            LOCK(m_mutex);
            if (m_current_profile) {
                auto profile_copy = *m_current_profile;
                LEAVE_CRITICAL_SECTION(m_mutex);

                auto sample = CaptureMemorySample("profiling");

                ENTER_CRITICAL_SECTION(m_mutex);
                if (m_current_profile && m_profiling) {
                    m_current_profile->samples.push_back(sample);
                    m_current_profile->peak_memory_mb = std::max(m_current_profile->peak_memory_mb, sample.process_rss_mb);
                }
            }
        }
    }
}

MemoryProfiler::MemorySample MemoryProfiler::CaptureMemorySample(const std::string& phase) const
{
    return CaptureMemorySampleLocked(phase, false);
}

MemoryProfiler::MemorySample MemoryProfiler::CaptureMemorySampleLocked(const std::string& phase, bool lock_already_held) const
{
    MemorySample sample;
    sample.timestamp = std::chrono::steady_clock::now();
    sample.phase = phase;

    size_t rss_bytes = GetProcessRSS();
    sample.process_rss_mb = rss_bytes > 0 ? rss_bytes / (1 << 20) : 0;

    return sample;
}
