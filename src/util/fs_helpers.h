// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_FS_HELPERS_H
#define BITCOIN_UTIL_FS_HELPERS_H

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <util/fs.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <iosfwd>
#include <limits>
#include <optional>

#if defined(USE_FSEEKO)
#include <sys/types.h>
#endif

/**
 * Ensure file contents are fully committed to disk, using a platform-specific
 * feature analogous to fsync().
 */
bool FileCommit(FILE* file);

/**
 * Sync directory contents. This is required on some environments to ensure that
 * newly created files are committed to disk.
 */
void DirectoryCommit(const fs::path& dirname);

bool TruncateFile(FILE* file, uint64_t length);

/**
 * 64-bit-clean file positioning.
 *
 * The wrapper is necessary for Windows, because `long` is only 32 bits there,
 * even in 64-bit builds (LLP64).
 */
inline int FileSeek64(FILE* file, int64_t offset, int origin)
{
#if defined(WIN32)
    return _fseeki64(file, offset, origin);
#else
#if defined(USE_FSEEKO)
    using offset_type = off_t;
    const auto native_seek{[file](offset_type distance, int whence) { return fseeko(file, distance, whence); }};
#else
    using offset_type = long;
    const auto native_seek{[file](offset_type distance, int whence) { return std::fseek(file, distance, whence); }};
#endif
    if constexpr (std::numeric_limits<offset_type>::max() < std::numeric_limits<int64_t>::max()) {
        // off_t can be an extended integer type unsupported by std::in_range.
        const auto in_range{[min = std::numeric_limits<offset_type>::min(), max = std::numeric_limits<offset_type>::max()](int64_t value) {
            return min <= value && value <= max;
        }};
        if (!in_range(offset)) [[unlikely]] {
            const offset_type step{offset > 0 ? std::numeric_limits<offset_type>::max() : std::numeric_limits<offset_type>::min()};
            do {
                if (const int ret{native_seek(step, origin)}; ret != 0) return ret;
                offset -= step;
                origin = SEEK_CUR;
            } while (!in_range(offset));
        }
    }
    return native_seek(static_cast<offset_type>(offset), origin);
#endif
}

/**
 * 64-bit-clean file positioning.
 *
 * The wrapper is necessary for Windows, because `long` is only 32 bits there,
 * even in 64-bit builds (LLP64).
 */
inline int64_t FileTell64(FILE* file)
{
#if defined(WIN32)
    const auto offset{_ftelli64(file)};
#elif defined(USE_FTELLO)
    const auto offset{ftello(file)};
#else
    const auto offset{std::ftell(file)};
#endif
    if constexpr (std::numeric_limits<decltype(offset)>::max() > std::numeric_limits<int64_t>::max()) {
        // off_t can be an extended integer type unsupported by std::in_range.
        const auto in_range{[min = std::numeric_limits<int64_t>::min(), max = std::numeric_limits<int64_t>::max()](auto value) {
            return min <= value && value <= max;
        }};
        if (!in_range(offset)) {
            errno = EOVERFLOW;
            return -1;
        }
    }
    return static_cast<int64_t>(offset);
}

int RaiseFileDescriptorLimit(int nMinFD);
void AllocateFileRange(FILE* file, uint64_t offset, unsigned int length);

/**
 * Rename src to dest.
 * @return true if the rename was successful.
 */
[[nodiscard]] bool RenameOver(fs::path src, fs::path dest);

namespace util {
enum class LockResult {
    Success,
    ErrorWrite,
    ErrorLock,
};
[[nodiscard]] LockResult LockDirectory(const fs::path& directory, const fs::path& lockfile_name, bool probe_only = false);
} // namespace util
void UnlockDirectory(const fs::path& directory, const fs::path& lockfile_name);
bool CheckDiskSpace(const fs::path& dir, uint64_t additional_bytes = 0);

/** Get the size of a file by scanning it.
 *
 * @param[in] path The file path
 * @param[in] max Stop seeking beyond this limit
 * @return The file size or max
 */
std::streampos GetFileSize(const char* path, std::streamsize max = std::numeric_limits<std::streamsize>::max());

//! Return the original FILE* unchanged. On systems that support it,
//! also advise the OS that the file will be accessed sequentially.
FILE* AdviseSequential(FILE*);

//! Close a file and return the result of fclose(). On systems that
//! support it, advise the OS to remove the file contents from the page
//! cache (which can help on memory-constrained systems).
int CloseAndUncache(FILE*);

/** Release all directory locks. This is used for unit testing only, at runtime
 * the global destructor will take care of the locks.
 */
void ReleaseDirectoryLocks();

bool TryCreateDirectories(const fs::path& p);
fs::path GetDefaultDataDir();

/** Convert fs::perms to symbolic string of the form 'rwxrwxrwx'
 *
 * @param[in] p the perms to be converted
 * @return Symbolic permissions string
 */
std::string PermsToSymbolicString(fs::perms p);
/** Interpret a custom permissions level string as fs::perms
 *
 * @param[in] s Permission level string
 * @return Permissions as fs::perms
 */
std::optional<fs::perms> InterpretPermString(const std::string& s);

/** Check if a directory is writable by creating a temporary file on it.
 *
 * @param[in] dir_path Path of the directory to test
 * @return true if a temporary file could be created and removed, false otherwise.
 * @throw std::runtime_error if dir_path is not a directory.
 */
bool IsDirWritable(const fs::path& dir_path);

#ifdef WIN32
fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif

/** Determine whether the given path is a symbolic link or a reparse point on windows
 *
 * @param[in] path The path to check
 * @return Whether path is a symlink or reparse point
 */
bool IsSymlink(const fs::path& path);

#endif // BITCOIN_UTIL_FS_HELPERS_H
