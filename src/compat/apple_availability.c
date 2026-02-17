// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Provide __isPlatformVersionAtLeast for macOS cross-compilation.
// When cross-compiling from Linux using clang + lld, the compiler-rt
// builtins for Darwin are not available. Qt6's Cocoa plugin uses
// @available() checks which emit calls to this function.
// At runtime on macOS 10.15+, _availability_version_check from dyld
// handles the actual version comparison.

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t platform;
    uint32_t version;
} dyld_build_version_t;

extern bool _availability_version_check(uint32_t count, dyld_build_version_t versions[]);

int32_t __isPlatformVersionAtLeast(uint32_t Platform, uint32_t Major, uint32_t Minor, uint32_t Subminor)
{
    dyld_build_version_t version = { Platform, Major * 65536 + Minor * 256 + Subminor };
    return _availability_version_check(1, &version);
}
