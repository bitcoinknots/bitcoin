// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_UTIL_ZIP_H
#define BITCOIN_UTIL_ZIP_H

#include <util/fs.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/** List zip entry paths using forward slashes. */
std::optional<std::vector<std::string>> ZipListEntries(const fs::path& archive_path, std::string& error);

/**
 * Extract a zip archive into dest_dir using in-process inflation (no external tools).
 *
 * strip_components removes that many leading path components. skip() can ignore
 * entries such as __MACOSX. progress() is invoked periodically while writing.
 */
bool ZipExtractTo(const fs::path& archive_path,
                  const fs::path& dest_dir,
                  int strip_components,
                  const std::function<bool(std::string_view)>& skip,
                  std::string& error,
                  const std::function<void(uint64_t bytes_written)>& progress = {});

#endif // BITCOIN_UTIL_ZIP_H
