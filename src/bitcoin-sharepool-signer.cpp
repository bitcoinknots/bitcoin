// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/** POSIX-only, walletless owner signer for the experimental SPN1 regtest profile. */
#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <common/system.h>
#include <key.h>
#include <sharepool/signer.h>
#include <streams.h>
#include <support/allocators/secure.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/acl.h>
#endif

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
constexpr std::array<unsigned char, 8> MAGIC{'S', 'P', 'K', 'E', 'Y', '0', '0', '1'};
constexpr size_t MAX_RECORD{MAGIC.size() + sharepool::signer::MAX_POLICY_BYTES + 32};
using SecretBytes = std::vector<unsigned char, secure_allocator<unsigned char>>;

class Descriptor {
    int m_fd;
public:
    explicit Descriptor(int fd) : m_fd(fd) { if (fd < 0) throw std::runtime_error("cannot open signer key file"); }
    ~Descriptor() { close(m_fd); }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    int get() const { return m_fd; }
};

void CheckFile(int fd)
{
    struct stat st{};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 07777) != 0600 ||
        st.st_uid != geteuid() || st.st_nlink != 1 || st.st_size < 0 || static_cast<uint64_t>(st.st_size) > MAX_RECORD) {
        throw std::runtime_error("key file must be an owned mode-0600 regular file with one link");
    }
#ifdef __APPLE__
    // macOS extended ACLs can grant access independently of mode bits. Reject
    // even restrictive ACL entries, so the local policy remains unambiguous.
    errno = 0;
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (acl == nullptr) {
        if (errno == ENOENT) return; // No extended ACL is the safe native state.
        throw std::runtime_error("cannot inspect signer key ACL");
    }
    acl_entry_t entry;
    const bool valid = acl_valid(acl) == 0;
    errno = 0;
    const int first = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    const int entry_error = errno;
    acl_free(acl);
    if (!valid || first == 0 || entry_error != EINVAL) throw std::runtime_error("signer key file has an extended ACL");
#endif
}

std::vector<unsigned char> Input(size_t maximum)
{
    // Bound bytes while reading, before hex decoding or deserialization. EOF is
    // required; callers using a pipe must close stdin and enforce their deadline.
    std::string line;
    char ch;
    while (std::cin.get(ch)) {
        if (line.size() >= maximum * 2 + 1) throw std::invalid_argument("signer stdin byte bound");
        line += ch;
    }
    if (!std::cin.eof()) throw std::runtime_error("cannot read signer input");
    if (!line.empty() && line.back() == '\n') line.pop_back();
    if (line.empty() || line.size() > maximum * 2 || !IsHex(line)) throw std::invalid_argument("signer input must be one hex line");
    return ParseHex(line);
}

std::pair<sharepool::signer::Policy, CKey> Load(const char* path)
{
    const Descriptor file{open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)};
    CheckFile(file.get());
    SecretBytes bytes(MAX_RECORD + 1);
    size_t count{0};
    while (count < bytes.size()) {
        const auto got = read(file.get(), bytes.data() + count, bytes.size() - count);
        if (got < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("cannot read signer key file");
        }
        if (got == 0) break;
        count += got;
    }
    CheckFile(file.get());
    if (count > MAX_RECORD || count < MAGIC.size() + 32 || !std::equal(MAGIC.begin(), MAGIC.end(), bytes.begin())) {
        throw std::runtime_error("invalid signer key file");
    }
    const auto policy = sharepool::signer::DecodePolicy(Span{bytes.data() + MAGIC.size(), count - MAGIC.size() - 32});
    CKey key;
    key.Set(bytes.begin() + count - 32, bytes.begin() + count, true);
    if (!key.IsValid()) throw std::runtime_error("invalid signer key file");
    return {policy, std::move(key)};
}

CKey Create(const char* path, const sharepool::signer::Policy& policy)
{
    DataStream encoded;
    encoded << policy;
    CKey key;
    key.MakeNewKey(true);
    const Descriptor file{open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)};
    // A restrictive inherited umask may remove owner bits. Set the exact safe
    // mode on the just-created descriptor; never chmod an existing path.
    if (fchmod(file.get(), 0600) != 0) throw std::runtime_error("cannot secure signer key file");
#ifdef __APPLE__
    acl_t empty_acl = acl_init(0);
    if (empty_acl == nullptr) throw std::runtime_error("cannot initialize private signer ACL");
    const int acl_result = acl_set_fd_np(file.get(), empty_acl, ACL_TYPE_EXTENDED);
    acl_free(empty_acl);
    if (acl_result != 0) throw std::runtime_error("cannot clear inherited signer ACL");
#endif
    CheckFile(file.get());
    SecretBytes bytes(MAGIC.begin(), MAGIC.end());
    bytes.insert(bytes.end(), UCharCast(encoded.data()), UCharCast(encoded.data()) + encoded.size());
    bytes.insert(bytes.end(), UCharCast(key.data()), UCharCast(key.data()) + key.size());
    size_t done{0};
    while (done < bytes.size()) {
        const auto written = write(file.get(), bytes.data() + done, bytes.size() - done);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) throw std::runtime_error("cannot write signer key file; incomplete file retained");
        done += written;
    }
    if (fsync(file.get()) != 0) throw std::runtime_error("cannot sync signer key file; file retained");
    CheckFile(file.get());
    const std::string filename{path};
    const auto slash = filename.rfind('/');
    const std::string parent = slash == std::string::npos ? "." : (slash == 0 ? "/" : filename.substr(0, slash));
    const Descriptor directory{open(parent.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY)};
    if (fsync(directory.get()) != 0) throw std::runtime_error("cannot sync signer directory; key file retained");
    return key;
}
} // namespace

int main(int argc, char* argv[])
{
    if (argc == 2 && std::string{argv[1]} == "--help") {
        std::cout << "Usage: bitcoin-sharepool-signer {init|pubkey|sign|sign-job} KEYFILE\n"
                     "Regtest only. init reads canonical policy hex from stdin and creates a new mode-0600 key file.\n"
                     "pubkey reads no stdin. sign reads canonical SPN1 Envelope hex from stdin.\n"
                     "sign-job reads a v3 binding followed by exact job/content hashes (360 bytes maximum).\n"
                     "Output is only the x-only public key (init/pubkey) or BIP340 signature (sign).\n"
                     "No private key import. The caller validates the current chain and complete template.\n";
        return EXIT_SUCCESS;
    }
    if (argc != 3 || (std::string{argv[1]} != "init" && std::string{argv[1]} != "pubkey" && std::string{argv[1]} != "sign" && std::string{argv[1]} != "sign-job")) {
        std::cerr << "error: expected {init|pubkey|sign|sign-job} KEYFILE; see --help\n";
        return EXIT_FAILURE;
    }
    try {
        // Prevent process core files from writing private key memory to disk.
        const struct rlimit no_core{0, 0};
        if (setrlimit(RLIMIT_CORE, &no_core) != 0) throw std::runtime_error("cannot disable signer core dumps");
        SetupEnvironment();
        const ECC_Context context;
        if (!ECC_InitSanityCheck()) throw std::runtime_error("signer elliptic curve self-check failed");
        const std::string command{argv[1]};
        if (command == "init") {
            const auto policy = sharepool::signer::DecodePolicy(Input(sharepool::signer::MAX_POLICY_BYTES));
            const auto key = Create(argv[2], policy);
            std::cout << HexStr(sharepool::signer::PublicKey(key)) << '\n';
        } else {
            auto [policy, key] = Load(argv[2]);
            if (command == "pubkey") {
                std::cout << HexStr(sharepool::signer::PublicKey(key)) << '\n';
            } else if (command == "sign-job") {
                const auto job = sharepool::signer::DecodeJob(Input(sharepool::signer::MAX_JOB_BYTES));
                std::cout << HexStr(sharepool::signer::SignJob(policy, key, job)) << '\n';
            } else {
                const auto envelope = sharepool::signer::DecodeEnvelope(Input(sharepool::signer::MAX_ENVELOPE_BYTES));
                std::cout << HexStr(sharepool::signer::SignOwner(policy, key, envelope)) << '\n';
            }
        }
        return EXIT_SUCCESS;
    } catch (const std::exception&) {
        // Never echo file contents, input, exception text, or key material.
        std::cerr << "error: signer rejected input or could not safely use the local key file\n";
        return EXIT_FAILURE;
    }
}
