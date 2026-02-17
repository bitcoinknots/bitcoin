// Copyright (c) 2023-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <util/mempressure.h>

#include <logging.h>

#ifdef HAVE_LINUX_SYSINFO
#include <sys/sysinfo.h>
#endif
#ifdef WIN32
#include <windows.h>
#endif

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

size_t g_low_memory_threshold{0};

uint64_t GetAvailableSystemMemory()
{
#ifdef __linux__
    FILE* f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "MemAvailable:", 13) == 0) {
                const char* p = line + 13;
                while (*p == ' ') ++p;
                uint64_t val = 0;
                while (*p >= '0' && *p <= '9') {
                    val = val * 10 + (*p - '0');
                    ++p;
                }
                fclose(f);
                return val * 1024;
            }
        }
        fclose(f);
    }
#endif
#ifdef HAVE_LINUX_SYSINFO
    struct sysinfo sys_info;
    if (!sysinfo(&sys_info)) {
        const uint64_t free_ram = uint64_t(sys_info.freeram) * sys_info.mem_unit;
        const uint64_t buffer_ram = uint64_t(sys_info.bufferram) * sys_info.mem_unit;
        return free_ram + buffer_ram;
    }
#endif
#ifdef WIN32
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    if (GlobalMemoryStatusEx(&mem_status)) {
        return mem_status.ullAvailPhys;
    }
#endif
    return 0;
}

bool SystemNeedsMemoryReleased()
{
    if (g_low_memory_threshold == 0) {
        return false;
    }
#ifdef WIN32
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    if (GlobalMemoryStatusEx(&mem_status)) {
        if (mem_status.dwMemoryLoad >= 99 ||
            mem_status.ullAvailPhys < g_low_memory_threshold ||
            mem_status.ullAvailVirtual < g_low_memory_threshold) {
            LogPrintf("%s: YES: %s%% memory load; %" PRIu64 " available physical memory; %" PRIu64 " available virtual memory\n", __func__, int(mem_status.dwMemoryLoad), uint64_t(mem_status.ullAvailPhys), uint64_t(mem_status.ullAvailVirtual));
            return true;
        }
    }
    return false;
#endif
    const uint64_t avail = GetAvailableSystemMemory();
    if (avail > 0 && avail < g_low_memory_threshold) {
        LogPrintf("%s: YES: %" PRIu64 " bytes available memory\n", __func__, avail);
        return true;
    }
    return false;
}
