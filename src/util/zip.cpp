// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <util/zip.h>

#include <kernel/official_packages.h>
#include <util/fs.h>

#include <zlib.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <system_error>
#include <utility>

#ifdef _WIN32
#define ZIP_FSEEK _fseeki64
#define ZIP_FTELL _ftelli64
#else
#define ZIP_FSEEK fseeko
#define ZIP_FTELL ftello
#endif

namespace {

constexpr uint32_t SIG_LOCAL{0x04034b50};
constexpr uint32_t SIG_CENTRAL{0x02014b50};
constexpr uint32_t SIG_EOCD{0x06054b50};
constexpr uint32_t SIG_ZIP64_EOCD{0x06064b50};
constexpr uint32_t SIG_ZIP64_LOCATOR{0x07064b50};
constexpr uint16_t METHOD_STORE{0};
constexpr uint16_t METHOD_DEFLATE{8};
constexpr uint16_t FLAG_ENCRYPTED{0x0001};
constexpr uint16_t FLAG_STRONG_ENCRYPT{0x0040};
constexpr uint16_t ZIP64_MAGIC16{0xffff};
constexpr uint32_t ZIP64_MAGIC32{0xffffffffu};
constexpr uint16_t EXTRA_ZIP64{0x0001};
constexpr uint64_t MAX_CENTRAL_DIR_BYTES{64ULL << 20};
constexpr uint64_t MAX_ENTRY_BYTES{1ULL << 40};
constexpr uint32_t UNIX_IFMT{0170000};
constexpr uint32_t UNIX_IFDIR{0040000};
constexpr uint32_t UNIX_IFLNK{0120000};

uint16_t ReadLE16(const unsigned char* p)
{
    return static_cast<uint16_t>(p[0] | (uint16_t(p[1]) << 8));
}

uint32_t ReadLE32(const unsigned char* p)
{
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

uint64_t ReadLE64(const unsigned char* p)
{
    return uint64_t(ReadLE32(p)) | (uint64_t(ReadLE32(p + 4)) << 32);
}

bool SeekAbs(FILE* file, uint64_t offset)
{
    if (offset > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) return false;
    return ZIP_FSEEK(file, static_cast<int64_t>(offset), SEEK_SET) == 0;
}

bool ReadExact(FILE* file, void* buf, size_t n)
{
    return n == 0 || fread(buf, 1, n, file) == n;
}

bool ReadAt(FILE* file, uint64_t offset, void* buf, size_t n)
{
    return SeekAbs(file, offset) && ReadExact(file, buf, n);
}

std::string NormalizeZipPath(std::string name)
{
    for (char& c : name) {
        if (c == '\\') c = '/';
    }
    return name;
}

std::optional<std::string> StripPathComponents(const std::string& name, int strip_components)
{
    if (strip_components <= 0) return name;
    size_t pos = 0;
    for (int i = 0; i < strip_components; ++i) {
        const size_t slash = name.find('/', pos);
        if (slash == std::string::npos) return std::nullopt;
        pos = slash + 1;
    }
    return name.substr(pos);
}

fs::path PathFromZipName(const std::string& name)
{
    fs::path out;
    size_t start = 0;
    while (start < name.size()) {
        const size_t slash = name.find('/', start);
        const size_t end = slash == std::string::npos ? name.size() : slash;
        if (end > start) {
            out /= fs::PathFromString(name.substr(start, end - start));
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return out;
}

bool EnsureDirectory(const fs::path& dir, std::string& error, const char* message)
{
    try {
        fs::create_directories(dir);
    } catch (const fs::filesystem_error&) {
        error = message;
        return false;
    }
    if (!fs::is_directory(dir)) {
        error = message;
        return false;
    }
    return true;
}

bool DestStaysInside(const fs::path& dest_dir, const fs::path& dest_path)
{
    std::error_code ec;
    const fs::path root = fs::weakly_canonical(dest_dir, ec);
    if (ec) return false;
    const fs::path canonical = fs::weakly_canonical(dest_path, ec);
    if (ec) return false;
    auto mismatch = std::mismatch(root.begin(), root.end(), canonical.begin(), canonical.end());
    return mismatch.first == root.end();
}

struct ZipEntry {
    std::string name;
    uint16_t flags{0};
    uint16_t method{0};
    uint32_t crc32{0};
    uint64_t comp_size{0};
    uint64_t uncomp_size{0};
    uint64_t local_header_ofs{0};
    uint32_t external_attr{0};
};

bool ParseZip64Extra(const std::string& extra, ZipEntry& entry, bool need_uncomp, bool need_comp, bool need_offset)
{
    size_t pos = 0;
    while (pos + 4 <= extra.size()) {
        const auto tag = ReadLE16(reinterpret_cast<const unsigned char*>(extra.data() + pos));
        const auto size = ReadLE16(reinterpret_cast<const unsigned char*>(extra.data() + pos + 2));
        pos += 4;
        if (pos + size > extra.size()) return false;
        if (tag == EXTRA_ZIP64) {
            size_t off = 0;
            const auto take64 = [&](uint64_t& out, bool& needed) {
                if (!needed) return true;
                if (off + 8 > size) return true;
                out = ReadLE64(reinterpret_cast<const unsigned char*>(extra.data() + pos + off));
                off += 8;
                needed = false;
                return true;
            };
            take64(entry.uncomp_size, need_uncomp);
            take64(entry.comp_size, need_comp);
            take64(entry.local_header_ofs, need_offset);
        }
        pos += size;
    }
    return !need_uncomp && !need_comp && !need_offset;
}

class ZipReader
{
public:
    ~ZipReader()
    {
        if (m_file) {
            fclose(m_file);
            m_file = nullptr;
        }
    }

    bool Open(const fs::path& path, std::string& error)
    {
        m_file = fsbridge::fopen(path, "rb");
        if (!m_file) {
            error = "Could not open the archive.";
            return false;
        }
        if (ZIP_FSEEK(m_file, 0, SEEK_END) != 0) {
            error = "Could not read the archive.";
            return false;
        }
        const int64_t size = ZIP_FTELL(m_file);
        if (size < 22) {
            error = "Archive is not a zip file.";
            return false;
        }
        m_size = static_cast<uint64_t>(size);
        return ReadCentralDirectory(error);
    }

    const std::vector<ZipEntry>& Entries() const { return m_entries; }
    FILE* File() const { return m_file; }
    uint64_t Size() const { return m_size; }

private:
    bool ReadCentralDirectory(std::string& error)
    {
        const uint64_t max_comment = 65535;
        const uint64_t min_eocd = 22;
        if (m_size < min_eocd) {
            error = "Archive is not a zip file.";
            return false;
        }
        const uint64_t search_len = std::min(m_size, min_eocd + max_comment);
        std::vector<unsigned char> tail(search_len);
        if (!ReadAt(m_file, m_size - search_len, tail.data(), tail.size())) {
            error = "Could not read the archive.";
            return false;
        }

        std::optional<uint64_t> eocd_ofs;
        for (size_t i = tail.size() - min_eocd;; --i) {
            if (ReadLE32(tail.data() + i) == SIG_EOCD) {
                const uint16_t comment_len = ReadLE16(tail.data() + i + 20);
                const uint64_t abs = m_size - search_len + i;
                if (abs + min_eocd + comment_len == m_size) {
                    eocd_ofs = abs;
                    break;
                }
            }
            if (i == 0) break;
        }
        if (!eocd_ofs) {
            error = "Archive is not a zip file.";
            return false;
        }

        std::array<unsigned char, 22> eocd{};
        if (!ReadAt(m_file, *eocd_ofs, eocd.data(), eocd.size())) {
            error = "Could not read the archive.";
            return false;
        }
        const uint16_t disk = ReadLE16(eocd.data() + 4);
        const uint16_t cd_disk = ReadLE16(eocd.data() + 6);
        uint64_t entries = ReadLE16(eocd.data() + 10);
        uint64_t cd_size = ReadLE32(eocd.data() + 12);
        uint64_t cd_offset = ReadLE32(eocd.data() + 16);
        // ZIP64 archives (Info-ZIP, 7-Zip, Python) store 0xFFFF / 0xFFFFFFFF in the
        // 32-bit EOCD and put the real values in the ZIP64 EOCD. That is not multi-disk.
        if ((disk != 0 && disk != ZIP64_MAGIC16) || (cd_disk != 0 && cd_disk != ZIP64_MAGIC16)) {
            error = "Archive spans multiple disks and cannot be extracted.";
            return false;
        }

        const bool zip64 = disk == ZIP64_MAGIC16 || cd_disk == ZIP64_MAGIC16 ||
                           entries == ZIP64_MAGIC16 || cd_size == ZIP64_MAGIC32 ||
                           cd_offset == ZIP64_MAGIC32;
        if (zip64) {
            if (*eocd_ofs < 20) {
                error = "Archive is not a zip file.";
                return false;
            }
            std::array<unsigned char, 20> loc{};
            if (!ReadAt(m_file, *eocd_ofs - 20, loc.data(), loc.size()) || ReadLE32(loc.data()) != SIG_ZIP64_LOCATOR) {
                error = "Archive is not a zip file.";
                return false;
            }
            const uint64_t zip64_eocd_ofs = ReadLE64(loc.data() + 8);
            std::array<unsigned char, 56> z64{};
            if (!ReadAt(m_file, zip64_eocd_ofs, z64.data(), z64.size()) || ReadLE32(z64.data()) != SIG_ZIP64_EOCD) {
                error = "Archive is not a zip file.";
                return false;
            }
            if (ReadLE32(z64.data() + 16) != 0 || ReadLE32(z64.data() + 20) != 0) {
                error = "Archive spans multiple disks and cannot be extracted.";
                return false;
            }
            entries = ReadLE64(z64.data() + 32);
            cd_size = ReadLE64(z64.data() + 40);
            cd_offset = ReadLE64(z64.data() + 48);
        }

        if (cd_size > MAX_CENTRAL_DIR_BYTES || cd_offset > m_size || cd_size > m_size - cd_offset) {
            error = "Could not read the archive.";
            return false;
        }

        std::vector<unsigned char> cd(cd_size);
        if (!ReadAt(m_file, cd_offset, cd.data(), cd.size())) {
            error = "Could not read the archive.";
            return false;
        }

        m_entries.reserve(std::min<uint64_t>(entries, 1024));
        size_t pos = 0;
        for (uint64_t i = 0; i < entries; ++i) {
            if (pos + 46 > cd.size() || ReadLE32(cd.data() + pos) != SIG_CENTRAL) {
                error = "Archive is not a zip file.";
                return false;
            }
            ZipEntry entry;
            entry.flags = ReadLE16(cd.data() + pos + 8);
            entry.method = ReadLE16(cd.data() + pos + 10);
            entry.crc32 = ReadLE32(cd.data() + pos + 16);
            const uint32_t comp32 = ReadLE32(cd.data() + pos + 20);
            const uint32_t uncomp32 = ReadLE32(cd.data() + pos + 24);
            const uint16_t name_len = ReadLE16(cd.data() + pos + 28);
            const uint16_t extra_len = ReadLE16(cd.data() + pos + 30);
            const uint16_t comment_len = ReadLE16(cd.data() + pos + 32);
            const uint16_t start_disk = ReadLE16(cd.data() + pos + 34);
            entry.external_attr = ReadLE32(cd.data() + pos + 38);
            const uint32_t local32 = ReadLE32(cd.data() + pos + 42);
            entry.comp_size = comp32;
            entry.uncomp_size = uncomp32;
            entry.local_header_ofs = local32;
            pos += 46;
            if (pos + name_len + extra_len + comment_len > cd.size()) {
                error = "Archive is not a zip file.";
                return false;
            }
            entry.name = NormalizeZipPath(std::string(reinterpret_cast<const char*>(cd.data() + pos), name_len));
            pos += name_len;
            const std::string extra(reinterpret_cast<const char*>(cd.data() + pos), extra_len);
            pos += extra_len + comment_len;
            if (start_disk != 0 && start_disk != ZIP64_MAGIC16) {
                error = "Archive spans multiple disks and cannot be extracted.";
                return false;
            }
            const bool need_uncomp = uncomp32 == ZIP64_MAGIC32;
            const bool need_comp = comp32 == ZIP64_MAGIC32;
            const bool need_offset = local32 == ZIP64_MAGIC32;
            if ((need_uncomp || need_comp || need_offset) &&
                !ParseZip64Extra(extra, entry, need_uncomp, need_comp, need_offset)) {
                error = "Archive is not a zip file.";
                return false;
            }
            m_entries.push_back(std::move(entry));
        }
        return true;
    }

    FILE* m_file{nullptr};
    uint64_t m_size{0};
    std::vector<ZipEntry> m_entries;
};

bool LocalDataOffset(FILE* file, const ZipEntry& entry, uint64_t archive_size, uint64_t& data_ofs, std::string& error)
{
    std::array<unsigned char, 30> local{};
    if (!ReadAt(file, entry.local_header_ofs, local.data(), local.size()) || ReadLE32(local.data()) != SIG_LOCAL) {
        error = "Archive is not a zip file.";
        return false;
    }
    const uint16_t name_len = ReadLE16(local.data() + 26);
    const uint16_t extra_len = ReadLE16(local.data() + 28);
    data_ofs = entry.local_header_ofs + 30 + name_len + extra_len;
    if (data_ofs > archive_size || entry.comp_size > archive_size - data_ofs) {
        error = "Archive is not a zip file.";
        return false;
    }
    return true;
}

uint32_t Crc32Add(uint32_t crc, const unsigned char* data, size_t n)
{
    return static_cast<uint32_t>(crc32(crc, data, static_cast<uInt>(n)));
}

bool PumpProgress(uint64_t& bytes_written, uint64_t& last_progress, uint64_t n,
                  const std::function<void(uint64_t)>& progress)
{
    constexpr uint64_t interval = 64ULL << 20;
    bytes_written += n;
    if (progress && bytes_written - last_progress >= interval) {
        progress(bytes_written);
        last_progress = bytes_written;
        return true;
    }
    return false;
}

bool ExtractStored(FILE* in, FILE* out, uint64_t size, uint32_t expected_crc, uint64_t& bytes_written,
                   uint64_t& last_progress, const std::function<void(uint64_t)>& progress, std::string& error)
{
    uint32_t crc = static_cast<uint32_t>(crc32(0L, Z_NULL, 0));
    std::array<unsigned char, 1 << 16> buffer{};
    uint64_t remaining = size;
    while (remaining > 0) {
        const size_t n = static_cast<size_t>(std::min<uint64_t>(buffer.size(), remaining));
        if (!ReadExact(in, buffer.data(), n)) {
            error = "Archive entry is corrupt.";
            return false;
        }
        if (fwrite(buffer.data(), 1, n, out) != n) {
            error = "Could not write an extracted file.";
            return false;
        }
        crc = Crc32Add(crc, buffer.data(), n);
        remaining -= n;
        PumpProgress(bytes_written, last_progress, n, progress);
    }
    if (crc != expected_crc) {
        error = "Archive entry failed verification.";
        return false;
    }
    return true;
}

bool ExtractDeflate(FILE* in, FILE* out, uint64_t comp_size, uint64_t uncomp_size, uint32_t expected_crc,
                    uint64_t& bytes_written, uint64_t& last_progress,
                    const std::function<void(uint64_t)>& progress, std::string& error)
{
    z_stream strm{};
    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) {
        error = "Could not extract an archive entry.";
        return false;
    }

    uint32_t crc = static_cast<uint32_t>(crc32(0L, Z_NULL, 0));
    std::array<unsigned char, 1 << 16> in_buf{};
    std::array<unsigned char, 1 << 16> out_buf{};
    uint64_t remaining_in = comp_size;
    uint64_t produced = 0;
    int ret = Z_OK;
    bool ok = true;

    while (ok && ret != Z_STREAM_END) {
        if (strm.avail_in == 0) {
            if (remaining_in == 0) {
                error = "Archive entry is corrupt.";
                ok = false;
                break;
            }
            const size_t n = static_cast<size_t>(std::min<uint64_t>(in_buf.size(), remaining_in));
            if (!ReadExact(in, in_buf.data(), n)) {
                error = "Archive entry is corrupt.";
                ok = false;
                break;
            }
            remaining_in -= n;
            strm.next_in = in_buf.data();
            strm.avail_in = static_cast<uInt>(n);
        }

        strm.next_out = out_buf.data();
        strm.avail_out = static_cast<uInt>(out_buf.size());
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            error = "Archive entry is corrupt.";
            ok = false;
            break;
        }
        const size_t got = out_buf.size() - strm.avail_out;
        if (got > 0) {
            if (produced + got > uncomp_size) {
                error = "Archive entry is corrupt.";
                ok = false;
                break;
            }
            if (fwrite(out_buf.data(), 1, got, out) != got) {
                error = "Could not write an extracted file.";
                ok = false;
                break;
            }
            crc = Crc32Add(crc, out_buf.data(), got);
            produced += got;
            PumpProgress(bytes_written, last_progress, got, progress);
        }
    }

    inflateEnd(&strm);
    if (!ok) return false;
    if (remaining_in != 0 || produced != uncomp_size || crc != expected_crc) {
        error = "Archive entry failed verification.";
        return false;
    }
    return true;
}

bool IsUnixSymlink(const ZipEntry& entry)
{
    const uint32_t mode = (entry.external_attr >> 16) & 0xffff;
    return (mode & UNIX_IFMT) == UNIX_IFLNK;
}

bool IsDirectory(const ZipEntry& entry)
{
    if (!entry.name.empty() && entry.name.back() == '/') return true;
    const uint32_t mode = (entry.external_attr >> 16) & 0xffff;
    if ((mode & UNIX_IFMT) == UNIX_IFDIR) return true;
    return (entry.external_attr & 0x10) != 0 && entry.uncomp_size == 0;
}

} // namespace

std::optional<std::vector<std::string>> ZipListEntries(const fs::path& archive_path, std::string& error)
{
    ZipReader reader;
    if (!reader.Open(archive_path, error)) return std::nullopt;

    std::vector<std::string> entries;
    entries.reserve(reader.Entries().size());
    for (const auto& entry : reader.Entries()) {
        entries.push_back(entry.name);
    }
    return entries;
}

bool ZipExtractTo(const fs::path& archive_path,
                  const fs::path& dest_dir,
                  int strip_components,
                  const std::function<bool(std::string_view)>& skip,
                  std::string& error,
                  const std::function<void(uint64_t bytes_written)>& progress)
{
    ZipReader reader;
    if (!reader.Open(archive_path, error)) return false;

    if (!EnsureDirectory(dest_dir, error, "Could not create the destination directory.")) {
        return false;
    }

    uint64_t bytes_written{0};
    uint64_t last_progress{0};

    for (const auto& entry : reader.Entries()) {
        if (skip && skip(entry.name)) continue;
        if (!IsZipArchiveEntryPathSafe(entry.name)) {
            error = "Archive contains an unsafe path and cannot be extracted.";
            return false;
        }
        if (IsUnixSymlink(entry)) {
            error = "Archive contains a symbolic link and cannot be extracted.";
            return false;
        }
        if ((entry.flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPT)) != 0) {
            error = "Archive contains an encrypted entry and cannot be extracted.";
            return false;
        }
        if (entry.method != METHOD_STORE && entry.method != METHOD_DEFLATE) {
            error = "Archive contains an unsupported compression method.";
            return false;
        }
        if (entry.comp_size > MAX_ENTRY_BYTES || entry.uncomp_size > MAX_ENTRY_BYTES) {
            error = "Archive contains an oversized entry and cannot be extracted.";
            return false;
        }

        const auto stripped = StripPathComponents(entry.name, strip_components);
        if (!stripped || stripped->empty() || *stripped == "/") continue;
        if (!IsZipArchiveEntryPathSafe(*stripped)) {
            error = "Archive contains an unsafe path and cannot be extracted.";
            return false;
        }

        const bool is_dir = IsDirectory(entry) || stripped->back() == '/';
        const fs::path dest_path = dest_dir / PathFromZipName(*stripped);
        if (!DestStaysInside(dest_dir, dest_path)) {
            error = "Archive extraction escaped the destination directory.";
            return false;
        }

        if (is_dir) {
            if (!EnsureDirectory(dest_path, error, "Could not create an archive directory.")) {
                return false;
            }
            continue;
        }

        if (dest_path.has_parent_path() &&
            !EnsureDirectory(dest_path.parent_path(), error, "Could not create an archive directory.")) {
            return false;
        }

        uint64_t data_ofs = 0;
        if (!LocalDataOffset(reader.File(), entry, reader.Size(), data_ofs, error)) return false;
        if (!SeekAbs(reader.File(), data_ofs)) {
            error = "Could not read the archive.";
            return false;
        }

        FILE* out = fsbridge::fopen(dest_path, "wb");
        if (!out) {
            error = "Could not write an extracted file.";
            return false;
        }

        bool ok = true;
        if (entry.method == METHOD_STORE) {
            if (entry.comp_size != entry.uncomp_size) {
                error = "Archive entry is corrupt.";
                ok = false;
            } else {
                ok = ExtractStored(reader.File(), out, entry.uncomp_size, entry.crc32, bytes_written,
                                   last_progress, progress, error);
            }
        } else {
            ok = ExtractDeflate(reader.File(), out, entry.comp_size, entry.uncomp_size, entry.crc32,
                                bytes_written, last_progress, progress, error);
        }
        if (fclose(out) != 0 && ok) {
            error = "Could not write an extracted file.";
            ok = false;
        }
        if (!ok) return false;
    }

    if (progress) progress(bytes_written);
    return true;
}
