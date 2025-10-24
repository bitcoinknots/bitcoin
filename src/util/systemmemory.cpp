// Copyright (c) 2023-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <util/systemmemory.h>

#include <logging.h>
#include <util/byte_units.h>
#include <util/memory_profiler.h>

#ifdef WIN32
#include <windows.h>
#include <psapi.h>
#endif

#ifdef __APPLE__
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#endif

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <fstream>
#include <string>

// Memory pressure threshold - initialized based on leveldb batch size
// Default will be set by InitializeMemoryThreshold()
size_t g_low_memory_threshold{0};
std::atomic<bool> g_system_needs_memory_released{false};

// If our periodic memory pressure checks are paused
static std::atomic<bool> checks_paused{false};

// Container detection state
enum class ContainerState {
    UNKNOWN,
    SYSTEM,
    CONTAINERIZED
};
static std::atomic<ContainerState> container_state{ContainerState::UNKNOWN};

namespace {
#ifdef WIN32
    MemoryInfo GetWindowsMemoryInfo();
#elif defined(__linux__)
    MemoryInfo GetLinuxMemoryInfo();
#elif defined(__APPLE__)
    MemoryInfo GetMacOSMemoryInfo();
#endif
}

void InitializeMemoryThreshold(size_t batch_size_bytes)
{
    // Calculate memory pressure threshold based on leveldb batch size
    // Formula uses moderate multiplier (2.9x) plus buffer (330 MB)
    // Based on empirical testing across platforms (Windows/Linux/VM) and batch sizes (64/128/256 MB)
    size_t batch_size_mb = batch_size_bytes / (1024 * 1024);
    size_t overhead_mb = static_cast<size_t>(batch_size_mb * 2.9);
    size_t threshold_mb = overhead_mb + 330;
    g_low_memory_threshold = threshold_mb * 1024 * 1024;
}

void CheckMemoryPressure()
{
    if (checks_paused.load(std::memory_order_relaxed)) {
        return;
    }

    if (g_low_memory_threshold <= 0) {
        g_system_needs_memory_released.store(false, std::memory_order_relaxed);
        return;
    }

#ifdef WIN32
    MemoryInfo info = GetWindowsMemoryInfo();
#elif defined(__linux__)
    MemoryInfo info = GetLinuxMemoryInfo();
#elif defined(__APPLE__)
    MemoryInfo info = GetMacOSMemoryInfo();
#else
    // Unsupported platform - disable pressure detection
    g_system_needs_memory_released.store(false, std::memory_order_relaxed);
    return;
#endif

    // LogDebug(BCLog::MEMPRESSURE, "%sMemAvailable=%.2f MB, MemUsed=%.2f MB, threshold=%.2f MB, trigger=%s\n",
    //          info.is_containerized ? "Container " : "",
    //          info.mem_available / (1024.0 * 1024.0),
    //          info.mem_used / (1024.0 * 1024.0),
    //          g_low_memory_threshold / (1024.0 * 1024.0),
    //          info.under_pressure ? "YES" : "NO");

    if (info.under_pressure) {
        LogPrintf("Mempressure detected - available: %.2f MB, threshold: %.2f MB\n",
                  info.mem_available / (1024.0 * 1024.0),
                  g_low_memory_threshold / (1024.0 * 1024.0));
    }

    g_system_needs_memory_released.store(info.under_pressure, std::memory_order_relaxed);
}

bool SystemNeedsMemoryReleased()
{
    if (g_low_memory_threshold <= 0) {
        return false;
    }

    return g_system_needs_memory_released.load(std::memory_order_relaxed);
}

void ResetMemoryPressure()
{
    g_system_needs_memory_released.store(false, std::memory_order_relaxed);
}

void PauseMemoryPressureChecks()
{
    checks_paused.store(true, std::memory_order_relaxed);
}

void ResumeMemoryPressureChecks()
{
    checks_paused.store(false, std::memory_order_relaxed);
    g_system_needs_memory_released.store(false, std::memory_order_relaxed);
}

MemoryInfo GetMemoryInfo()
{
#ifdef WIN32
    return GetWindowsMemoryInfo();
#elif defined(__linux__)
    return GetLinuxMemoryInfo();
#elif defined(__APPLE__)
    return GetMacOSMemoryInfo();
#else
    // Unsupported platform - return empty info
    return MemoryInfo{};
#endif
}

#ifdef WIN32
namespace {
    // Check Windows container memory status (Job Object)
    // Docker, etc on Windows use Job Objects to enforce memory limits.
    MemoryInfo GetWindowsContainerMemoryInfo()
    {
        MemoryInfo info;

        // Query information about the job object the current process belongs to
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info = {};
        if (!QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation,
                                       &job_info, sizeof(job_info), nullptr)) {
            return info;
        }

        if (!(job_info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY)) {
            return info;
        }

        info.is_containerized = true;
        size_t container_limit = static_cast<size_t>(job_info.JobMemoryLimit);

        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (!GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            return info;
        }

        info.mem_used = pmc.PrivateUsage;
        info.mem_available = (info.mem_used < container_limit)
                           ? (container_limit - info.mem_used)
                           : 0;

        // Windows container pressure: check threshold
        if (info.mem_available < g_low_memory_threshold) {
            info.under_pressure = true;
        }

        return info;
    }

    // Check system (non-container) Windows memory status
    MemoryInfo GetWindowsSystemMemoryInfo()
    {
        MemoryInfo info;

        PERFORMANCE_INFORMATION perf_info;
        if (!GetPerformanceInfo(&perf_info, sizeof(perf_info))) {
            return info;
        }

        size_t page_size = perf_info.PageSize;
        size_t commit_limit = static_cast<size_t>(perf_info.CommitLimit) * page_size;
        size_t commit_total = static_cast<size_t>(perf_info.CommitTotal) * page_size;
        size_t physical_available = static_cast<size_t>(perf_info.PhysicalAvailable) * page_size;

        size_t commit_available = (commit_total < commit_limit) ? (commit_limit - commit_total) : 0;

        // Use the minimum of commit available and physical available
        info.mem_available = std::min(commit_available, physical_available);
        info.mem_used = commit_total;

        if (info.mem_available < g_low_memory_threshold) {
            info.under_pressure = true;
        }

        return info;
    }

    MemoryInfo GetWindowsMemoryInfo()
    {
        ContainerState state = container_state.load(std::memory_order_relaxed);
        if (state == ContainerState::UNKNOWN || state == ContainerState::CONTAINERIZED) {
            MemoryInfo info = GetWindowsContainerMemoryInfo();
            if (info.is_containerized) {
                container_state.store(ContainerState::CONTAINERIZED, std::memory_order_relaxed);
                return info;
            }
        }
        if (state == ContainerState::UNKNOWN) {
            container_state.store(ContainerState::SYSTEM, std::memory_order_relaxed);
        }

        return GetWindowsSystemMemoryInfo();
    }
}
#endif

#ifdef __linux__
namespace {
    // Helper function to parse memory statistics with error handling
    std::optional<uint64_t> ParseMemoryStat(const std::string& value_str, const char* stat_name)
    {
        try {
            return std::stoull(value_str);
        } catch (const std::exception& e) {
            return std::nullopt;
        }
    }

    MemoryInfo GetCgroupV2MemoryInfo()
    {
        MemoryInfo info;

        std::ifstream v2_check("/sys/fs/cgroup/memory.max");
        std::string limit_str;
        if (!v2_check.is_open() || !std::getline(v2_check, limit_str)) {
            return info;
        }

        size_t container_limit = 0;
        if (limit_str != "max") {
            auto limit = ParseMemoryStat(limit_str, "memory.max");
            if (!limit) return info;
            if (*limit < UINT64_MAX / 2) { // sanity check
                container_limit = static_cast<size_t>(*limit);
            }
        }

        if (container_limit == 0) {
            return info;
        }

        size_t inactive_file = 0;
        std::ifstream stat_file("/sys/fs/cgroup/memory.stat");
        if (!stat_file.is_open()) {
            return info;
        }

        std::string stat_line;
        while (std::getline(stat_file, stat_line)) {
            if (stat_line.compare(0, 14, "inactive_file ") == 0) {
                auto value = ParseMemoryStat(stat_line.substr(14), "inactive_file");
                if (!value) return info;
                inactive_file = *value;
                break;
            }
        }

        size_t total = 0;
        std::ifstream current_file("/sys/fs/cgroup/memory.current");
        std::string current_str;
        if (!current_file.is_open() || !std::getline(current_file, current_str)) {
            return info;
        }

        auto value = ParseMemoryStat(current_str, "memory.current");
        if (!value) return info;
        total = *value;

        info.is_containerized = true;
        info.mem_used = (total > inactive_file) ? (total - inactive_file) : 0;
        info.mem_available = (info.mem_used < container_limit) ? (container_limit - info.mem_used) : 0;

        // Linux pressure detection: low available memory threshold
        if (info.mem_available < g_low_memory_threshold) {
            info.under_pressure = true;
        }

        return info;
    }

    MemoryInfo GetCgroupV1MemoryInfo()
    {
        MemoryInfo info;

        std::ifstream limit_file("/sys/fs/cgroup/memory/memory.limit_in_bytes");
        std::string limit_str;
        if (!limit_file.is_open() || !std::getline(limit_file, limit_str)) {
            return info;
        }

        size_t limit = 0, usage = 0, cache = 0;

        auto limit_val = ParseMemoryStat(limit_str, "memory.limit_in_bytes");
        if (!limit_val) return info;
        limit = *limit_val;
        if (limit >= UINT64_MAX / 2) {
            return info;
        }

        std::ifstream usage_file("/sys/fs/cgroup/memory/memory.usage_in_bytes");
        std::string usage_str;
        if (!usage_file.is_open() || !std::getline(usage_file, usage_str)) {
            return info;
        }

        auto usage_val = ParseMemoryStat(usage_str, "memory.usage_in_bytes");
        if (!usage_val) return info;
        usage = *usage_val;

        std::ifstream stat_file("/sys/fs/cgroup/memory/memory.stat");
        if (!stat_file.is_open()) {
            return info;
        }

        std::string line;
        while (std::getline(stat_file, line)) {
            if (line.compare(0, 6, "cache ") == 0) {
                auto cache_val = ParseMemoryStat(line.substr(6), "cache");
                if (cache_val) cache = *cache_val;
                break;
            }
        }

        info.is_containerized = true;
        info.mem_used = usage - cache;
        info.mem_available = (info.mem_used < limit) ? (limit - info.mem_used) : 0;

        // Linux pressure detection: low available memory threshold
        if (info.mem_available < g_low_memory_threshold) {
            info.under_pressure = true;
        }

        return info;
    }

    // Check system (non-container) Linux memory status
    MemoryInfo GetLinuxSystemMemoryInfo()
    {
        MemoryInfo info;

        std::ifstream meminfo("/proc/meminfo");
        if (!meminfo.is_open()) {
            return info;
        }

        std::string line;
        uint64_t mem_total_kb = 0;
        uint64_t mem_available_kb = 0;

        while (std::getline(meminfo, line)) {
            if (line.compare(0, 9, "MemTotal:") == 0) {
                size_t pos = line.find_first_of("0123456789");
                if (pos != std::string::npos) {
                    auto value = ParseMemoryStat(line.substr(pos), "MemTotal");
                    if (value) mem_total_kb = *value;
                }
            } else if (line.compare(0, 13, "MemAvailable:") == 0) {
                size_t pos = line.find_first_of("0123456789");
                if (pos != std::string::npos) {
                    auto value = ParseMemoryStat(line.substr(pos), "MemAvailable");
                    if (value) mem_available_kb = *value;
                }
            }

            if (mem_total_kb > 0 && mem_available_kb > 0) {
                break;
            }
        }

        if (mem_total_kb > 0 && mem_available_kb > 0) {
            // Check for overflow before multiplication
            if (mem_available_kb > UINT64_MAX / 1024 || mem_total_kb > UINT64_MAX / 1024) {
                // huge value is "plenty of memory"
                return info;
            }

            info.mem_available = mem_available_kb * 1024;
            size_t total_memory = mem_total_kb * 1024;
            info.mem_used = total_memory - info.mem_available;
        }

        // Linux pressure detection: low available memory threshold
        if (info.mem_available < g_low_memory_threshold) {
            info.under_pressure = true;
        }

        return info;
    }

    // Unified Linux memory info - tries cgroup v2, then v1, then system
    MemoryInfo GetLinuxMemoryInfo()
    {
        ContainerState state = container_state.load(std::memory_order_relaxed);
        if (state == ContainerState::UNKNOWN || state == ContainerState::CONTAINERIZED) {
            // Try cgroup v2 first
            MemoryInfo info = GetCgroupV2MemoryInfo();
            if (!info.is_containerized) {
                info = GetCgroupV1MemoryInfo();
            }

            if (info.is_containerized) {
                container_state.store(ContainerState::CONTAINERIZED, std::memory_order_relaxed);
                return info;
            }
        }
        if (state == ContainerState::UNKNOWN) {
            container_state.store(ContainerState::SYSTEM, std::memory_order_relaxed);
        }

        return GetLinuxSystemMemoryInfo();
    }
}
#endif

#ifdef __APPLE__
namespace {
    // TODO: Determine if kern.memorystatus_vm_pressure_level is useful for pressure detection,
    // or if we should just use mem_available < threshold like Linux.
    // PSI on Linux created a feedback loop where flushing triggered more pressure.
    // macOS pressure_level may have the same issue - needs testing.
    MemoryInfo GetMacOSMemoryInfo()
    {
        MemoryInfo info;

        vm_statistics64_data_t vm_stats;
        mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
        kern_return_t kr = host_statistics64(mach_host_self(), HOST_VM_INFO64,
                                            (host_info64_t)&vm_stats, &count);

        if (kr == KERN_SUCCESS) {
            vm_size_t page_size = 0;
            host_page_size(mach_host_self(), &page_size);

            // Calculate memory in bytes
            // Available = free + inactive pages (can be reclaimed)
            uint64_t free_pages = vm_stats.free_count;
            uint64_t inactive_pages = vm_stats.inactive_count;
            uint64_t active_pages = vm_stats.active_count;
            uint64_t wired_pages = vm_stats.wire_count;

            info.mem_available = (free_pages + inactive_pages) * page_size;
            info.mem_used = (active_pages + wired_pages) * page_size;
        }

        // macOS memory pressure levels:
        // - NORMAL (1): System is fine
        // - WARN (2): System experiencing pressure - should free memory if possible
        // - CRITICAL (4): System actively paging to disk - aggressive reclamation needed
        int pressure_level = 0;
        size_t size = sizeof(pressure_level);

        if (sysctlbyname("kern.memorystatus_vm_pressure_level", &pressure_level, &size, nullptr, 0) == 0) {
            // Trigger memory release at WARN level or higher
            if (pressure_level >= 2) {
                LogPrintf("CheckMemoryPressure: macOS memory pressure level %d (WARN or CRITICAL)\n", pressure_level);
                info.under_pressure = true;
            }
        }

        // macOS pressure detection: OS pressure level OR low available memory
        if (!info.under_pressure && info.mem_available < g_low_memory_threshold) {
            info.under_pressure = true;
        }

        return info;
    }
}
#endif

void ReportFlushProfile(std::unique_ptr<MemoryProfiler::FlushProfile> profile, size_t cache_size_bytes)
{
    if (!profile) return;

    size_t cache_size_mb = cache_size_bytes / (1024 * 1024);

    // Calculate overhead from peak - pre_flush
    size_t overhead_mb = (profile->peak_memory_mb >= profile->pre_flush_memory_mb)
        ? (profile->peak_memory_mb - profile->pre_flush_memory_mb)
        : 0;

    int64_t duration_ms = profile->GetDurationMs();

    // Get current system memory state
    MemoryInfo mem_info = GetMemoryInfo();
    size_t sys_memavail_mb = mem_info.mem_available / (1024 * 1024);

    // Log the flush profile
    LogDebug(BCLog::MEMPRESSURE, "Flush profile: cache_size=%zu MB, overhead=%zu MB, duration=%lld ms, "
             "pre_flush=%zu MB, peak=%zu MB, post_flush=%zu MB, sys_memavail=%zu MB\n",
             cache_size_mb, overhead_mb, (long long)duration_ms,
             profile->pre_flush_memory_mb, profile->peak_memory_mb, profile->post_flush_memory_mb, sys_memavail_mb);
}
