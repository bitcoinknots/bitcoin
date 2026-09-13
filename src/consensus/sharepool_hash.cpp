// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/sharepool_hash.h>

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <pow.h>
#include <pubkey.h>
#include <script/script.h>
#include <sharepool/tides_history.h>
#include <streams.h>
#include <versionbits.h>

#include <boost/multiprecision/cpp_int.hpp>

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace sharepool::hashonly {
namespace {
// These are minimum *wire byte* sizes, not independent consensus count quotas.
constexpr size_t MIN_TEMPLATE_BYTES{164 + 1 + 60};
constexpr size_t MIN_TEMPLATE_RECORD_BYTES{32 + 164 + 1 + 1};
constexpr size_t MIN_SHARE_BYTES{164 + 284 + 64};
constexpr size_t MIN_STATE_BYTES{36};
constexpr size_t MIN_PAYOUT_BYTES{8 + 1 + 22};
constexpr size_t MIN_CREDIT_BYTES{4 + 4 + 32 + 32 + 4 + 1 + 22};
constexpr size_t CERTIFICATE_BYTES{4 + 32 + 32 + 32};

Result Bad(const std::string& reason) { return Result::Invalid("bad-sharepool-hash-" + reason); }

bool LessProof(const uint256& a, const uint256& b)
{
    return UintToArith256(a) < UintToArith256(b);
}

template <size_t N, typename... T>
uint256 DomainHash(const char (&domain)[N], const T&... values)
{
    HashWriter writer;
    writer.write(AsBytes(Span{domain, N}));
    (writer << ... << values);
    return writer.GetHash();
}

struct TransactionTable {
    std::map<Wtxid, std::pair<CTransactionRef, uint32_t>> entries;
    explicit TransactionTable(const Snapshot& snapshot)
    {
        size_t expanded{0}, references{0};
        for (const auto& item : snapshot.templates) {
            if (item.block.vtx.size() > MAX_TEMPLATE_TX_REFERENCES - references ||
                std::any_of(item.block.vtx.begin(), item.block.vtx.end(), [](const auto& tx) { return !tx; })) {
                throw std::ios_base::failure("template transaction reference budget");
            }
            const auto size = GetSerializeSize(TX_WITH_WITNESS(item.block));
            if (size < MIN_TEMPLATE_BYTES || size > MAX_TEMPLATE_BYTES ||
                size > MAX_EXPANDED_TEMPLATE_BYTES - expanded ||
                item.block.vtx.size() > MAX_TEMPLATE_TX_REFERENCES - references) {
                throw std::ios_base::failure("expanded template budget");
            }
            expanded += size;
            references += item.block.vtx.size();
            for (const auto& tx : item.block.vtx) {
                entries.try_emplace(tx->GetWitnessHash(), tx, 0);
            }
        }
        uint32_t index{0};
        for (auto& [id, entry] : entries) entry.second = index++;
    }
};

template <typename Stream>
void WriteSnapshot(Stream& stream, const Snapshot& snapshot, bool unsigned_contents = false)
{
    const TransactionTable table{snapshot};
    stream << snapshot.binding << (unsigned_contents ? Signature{} : snapshot.authorization) << snapshot.job_commitment;
    WriteCompactSize(stream, table.entries.size());
    for (const auto& [id, entry] : table.entries) {
        WriteCompactSize(stream, GetSerializeSize(TX_WITH_WITNESS(*entry.first)));
        stream << TX_WITH_WITNESS(*entry.first);
    }
    WriteCompactSize(stream, snapshot.templates.size());
    for (const auto& item : snapshot.templates) {
        stream << item.id << item.block.GetBlockHeader();
        WriteCompactSize(stream, item.block.vtx.size());
        for (const auto& tx : item.block.vtx) WriteCompactSize(stream, table.entries.at(tx->GetWitnessHash()).second);
    }
    stream << snapshot.shares << snapshot.post_state << snapshot.payouts;
    if (snapshot.binding.version == LEDGER_VERSION) stream << snapshot.pending << snapshot.settled << snapshot.certificates;
    if (snapshot.binding.version == TIDES_VERSION) stream << snapshot.certificates << snapshot.history_head;
}

bool CreditLess(const LedgerCredit& a, const LedgerCredit& b)
{
    return a.admitted_height != b.admitted_height ? a.admitted_height < b.admitted_height : LessProof(a.proof_id, b.proof_id);
}

void CreditBounds(const std::vector<LedgerCredit>& credits, size_t maximum)
{
    if (credits.size() > maximum / MIN_CREDIT_BYTES) throw std::ios_base::failure("ledger credit count bound");
    for (const auto& credit : credits) {
        if (!IsPayoutScript(credit.payout_script)) throw std::ios_base::failure("ledger payout script shape");
    }
    if (GetSerializeSize(credits) > maximum) throw std::ios_base::failure("ledger credit byte bound");
}

bool CreditsOrdered(const std::vector<LedgerCredit>& credits)
{
    for (size_t i{1}; i < credits.size(); ++i) if (!CreditLess(credits[i - 1], credits[i])) return false;
    return true;
}

bool CertificatesOrdered(const std::vector<OriginCertificate>& certificates)
{
    for (size_t i{1}; i < certificates.size(); ++i) if (!(certificates[i - 1].identity < certificates[i].identity)) return false;
    return true;
}

size_t EncodedSize(const Snapshot& snapshot)
{
    if (snapshot.binding.version == LEDGER_VERSION) {
        CreditBounds(snapshot.pending, MAX_PENDING_BYTES);
        CreditBounds(snapshot.settled, MAX_SETTLED_BYTES);
        if (snapshot.certificates.size() > MAX_CERTIFICATE_BYTES / CERTIFICATE_BYTES ||
            GetSerializeSize(snapshot.certificates) > MAX_CERTIFICATE_BYTES) throw std::ios_base::failure("certificate byte bound");
    } else if (snapshot.binding.version == TIDES_VERSION) {
        if (!snapshot.pending.empty() || !snapshot.settled.empty() ||
            GetSerializeSize(snapshot.certificates) > MAX_CERTIFICATE_BYTES) throw std::ios_base::failure("TIDES fields or certificate budget");
    } else if (!snapshot.pending.empty() || !snapshot.settled.empty() || !snapshot.certificates.empty()) {
        throw std::ios_base::failure("snapshot profile or ledger fields");
    }
    if (snapshot.binding.version != TIDES_VERSION && !snapshot.history_head.IsNull()) throw std::ios_base::failure("unexpected history head");
    if (snapshot.binding.payout_script.size() > 34 ||
        snapshot.templates.size() > MAX_SNAPSHOT_BYTES / MIN_TEMPLATE_RECORD_BYTES ||
        snapshot.shares.size() > MAX_SNAPSHOT_BYTES / MIN_SHARE_BYTES ||
        snapshot.post_state.size() > MAX_SNAPSHOT_BYTES / MIN_STATE_BYTES ||
        snapshot.payouts.size() > MAX_SNAPSHOT_BYTES / MIN_PAYOUT_BYTES) {
        throw std::ios_base::failure("snapshot count exceeds byte bound");
    }
    for (const auto& share : snapshot.shares) {
        if (share.origin.payout_script.size() > 34) throw std::ios_base::failure("share payout script byte bound");
    }
    for (const auto& payout : snapshot.payouts) {
        if (payout.scriptPubKey.size() > 34) throw std::ios_base::failure("payout script byte bound");
    }
    SizeComputer size;
    WriteSnapshot(size, snapshot);
    if (size.size() == 0 || size.size() > MAX_SNAPSHOT_BYTES) throw std::ios_base::failure("snapshot byte bound");
    return size.size();
}

size_t ReadCount(SpanReader& reader, size_t minimum)
{
    const auto count = ReadCompactSize(reader);
    if (count > reader.size() / minimum) throw std::ios_base::failure("snapshot count exceeds remaining bytes");
    return count;
}

std::vector<unsigned char> ReadBytes(SpanReader& reader, size_t minimum, size_t maximum)
{
    const auto count = ReadCompactSize(reader);
    if (count < minimum || count > maximum || count > reader.size()) throw std::ios_base::failure("snapshot byte vector bound");
    std::vector<unsigned char> bytes(count);
    reader.read(AsWritableBytes(Span{bytes}));
    return bytes;
}

bool ReservedZero(const Envelope& binding)
{
    return binding.shares_root.IsNull() && binding.state_root.IsNull() && binding.payouts_root.IsNull();
}

bool WireBinding(const Envelope& binding)
{
    return (binding.version == VERSION || binding.version == LEDGER_VERSION || binding.version == TIDES_VERSION) && ReservedZero(binding) && IsPayoutScript(binding.payout_script);
}

bool SameBinding(const Envelope& a, const Envelope& b)
{
    return a.version == b.version && a.genesis == b.genesis && a.rules == b.rules && a.height == b.height &&
        a.native_parent == b.native_parent && a.pool == b.pool && a.owner == b.owner && a.payout_script == b.payout_script &&
        a.shares_root == b.shares_root && a.state_root == b.state_root && a.payouts_root == b.payouts_root;
}

bool HeaderShape(const CBlockHeader& header)
{
    return header.m_header_v2 && header.m_flags == 0 && header.m_xor_key.IsNull() &&
        header.m_xor_key_mask_clear_bits == 0 && header.m_txcount > 0 &&
        (header.nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS;
}

bool SearchFieldsZero(const CBlockHeader& header)
{
    return header.nNonce == 0 && header.m_nonce2 == 0 && header.m_nonce3 == 0 &&
        header.m_extranonce.IsNull() && header.m_time_offset == 0;
}

void SkipBytes(SpanReader& reader, size_t count)
{
    if (count > reader.size()) throw std::ios_base::failure("truncated template field");
    reader.ignore(count);
}

void PreflightTransaction(SpanReader& reader)
{
    SkipBytes(reader, 4);
    auto inputs = ReadCount(reader, 41);
    uint8_t flags{0};
    if (inputs == 0) {
        reader >> flags;
        if (flags > 1) throw std::ios_base::failure("unknown transaction flags");
        if (flags) inputs = ReadCount(reader, 41);
    }
    for (size_t input{0}; input < inputs; ++input) {
        SkipBytes(reader, 36);
        SkipBytes(reader, ReadCount(reader, 1));
        SkipBytes(reader, 4);
    }
    if (inputs || flags) {
        const auto outputs = ReadCount(reader, 9);
        for (size_t output{0}; output < outputs; ++output) {
            SkipBytes(reader, 8);
            SkipBytes(reader, ReadCount(reader, 1));
        }
    }
    if (flags & 1) {
        for (size_t input{0}; input < inputs; ++input) {
            const auto items = ReadCount(reader, 1);
            for (size_t item{0}; item < items; ++item) SkipBytes(reader, ReadCount(reader, 1));
        }
    }
    SkipBytes(reader, 4);
}

/** Validate all nested allocation counts against bytes actually present before
 * invoking the ordinary native transaction decoder. This does not set separate
 * transaction/input/output/witness quotas or allocate attacker-sized vectors. */
void PreflightTemplate(Span<const unsigned char> bytes)
{
    SpanReader reader{bytes};
    CBlockHeader header;
    reader >> header;
    if (!header.m_header_v2) throw std::ios_base::failure("v2 template required");
    const auto transactions = ReadCount(reader, 10);
    for (size_t tx{0}; tx < transactions; ++tx) PreflightTransaction(reader);
    if (!reader.empty()) throw std::ios_base::failure("trailing template bytes");
}

CBlock ReadBlock(Span<const unsigned char> bytes, bool normalized)
{
    if (bytes.size() < MIN_TEMPLATE_BYTES || bytes.size() > MAX_TEMPLATE_BYTES) throw std::ios_base::failure("template byte bound");
    PreflightTemplate(bytes);
    SpanReader reader{bytes};
    CBlock block;
    reader >> TX_WITH_WITNESS(block);
    DataStream canonical;
    canonical << TX_WITH_WITNESS(block);
    if (!reader.empty() || canonical.size() != bytes.size() ||
        !std::equal(bytes.begin(), bytes.end(), UCharCast(canonical.data())) ||
        !block.m_header_v2 || (normalized && !SearchFieldsZero(block)) || block.vtx.empty() ||
        block.m_txcount != block.vtx.size() || BlockMerkleRoot(block) != block.hashMerkleRoot) {
        throw std::ios_base::failure("noncanonical normalized full template");
    }
    return block;
}

CBlock ReadTemplate(Span<const unsigned char> bytes) { return ReadBlock(bytes, true); }

bool OwnerValid(const Snapshot& snapshot)
{
    const XOnlyPubKey owner{Span{snapshot.binding.owner}};
    return !snapshot.job_commitment.IsNull() && owner.IsFullyValid() &&
        owner.VerifySchnorr(hashonly::OwnerHash(snapshot), snapshot.authorization);
}

Result CheckBinding(const Envelope& binding, const Consensus::Params& consensus,
                    uint32_t height, const uint256& parent)
{
    if (binding.version != ProfileVersion(consensus)) return Bad("version");
    if (!ReservedZero(binding)) return Bad("reserved-roots");
    if (binding.genesis != consensus.hashGenesisBlock || binding.rules != hashonly::RulesHash(binding.version) ||
        binding.height != height || binding.native_parent != parent || binding.pool.IsNull() ||
        !IsPayoutScript(binding.payout_script) || !XOnlyPubKey{Span{binding.owner}}.IsFullyValid()) return Bad("binding");
    return Result::Valid();
}

bool StateOrdered(const std::vector<StateEntry>& state)
{
    for (size_t i{1}; i < state.size(); ++i) if (!LessProof(state[i - 1].proof_id, state[i].proof_id)) return false;
    return true;
}

bool PayoutsOrdered(const std::vector<CTxOut>& payouts)
{
    for (size_t i{0}; i < payouts.size(); ++i) {
        if (!IsPayoutScript(payouts[i].scriptPubKey) || !MoneyRange(payouts[i].nValue) ||
            (i && !(payouts[i - 1].scriptPubKey < payouts[i].scriptPubKey))) return false;
    }
    return !payouts.empty();
}

bool WitnessOutput(const CTxOut& output)
{
    static constexpr unsigned char prefix[]{OP_RETURN, 0x24, 0xaa, 0x21, 0xa9, 0xed};
    return output.nValue == 0 && output.scriptPubKey.size() == 38 &&
        std::equal(std::begin(prefix), std::end(prefix), output.scriptPubKey.begin());
}

/** Local memo identity, never a protocol commitment. Immutable Wtxids bind the
 * exact canonical witness bytes without rehashing a multi-megabyte body for
 * every dependency edge. The header and ordered vector also bind the claimed
 * transaction root, count, native parent and snapshot commitment. */
uint256 OriginMemoId(const CBlock& block)
{
    static constexpr char domain[]{"SharePool/origin-cache/v4"};
    HashWriter writer;
    writer.write(AsBytes(Span{domain}));
    writer << block.GetBlockHeader();
    WriteCompactSize(writer, block.vtx.size());
    for (const auto& tx : block.vtx) {
        if (!tx) throw std::ios_base::failure("null origin transaction");
        writer << tx->GetWitnessHash();
    }
    return writer.GetHash();
}

/** One bounded local validation walk, with no network or consensus-global state. */
class Checker {
    const Consensus::Params& m_consensus;
    const Lookup& m_lookup;
    const ValidateOrigin& m_validate_origin;
    std::map<uint256, std::shared_ptr<const Snapshot>> m_snapshots;
    size_t m_dependency_bytes{0};
    std::set<uint256> m_visiting;
    std::set<uint256> m_unique_origins;
    std::set<const Snapshot*> m_authorized;
    bool m_certificates_initialized{false};
    Result m_certificate_context{Result::Valid()};
    std::map<uint256, OriginCertificate> m_parent_certificates;

    bool Authorized(const Snapshot& snapshot)
    {
        if (m_authorized.count(&snapshot)) return true;
        if (!OwnerValid(snapshot)) return false;
        m_authorized.insert(&snapshot);
        return true;
    }
    struct CheckedOrigin {
        Result result;
        uint32_t descendant_depth;
    };
    // Cache intrinsic subtree depth, not the depth at which it was visited.
    // Reuse must still fit the remaining path budget. A dense DAG is therefore
    // checked once per origin, without hiding a longer route through that DAG.
    // The parent hash makes the native-context/reward dependency explicit.
    std::map<std::pair<uint256, uint256>, CheckedOrigin> m_checked_origins;
    uint32_t* m_descendant_depth{nullptr};

    void IncludeChildDepth(uint32_t child_depth)
    {
        if (m_descendant_depth) *m_descendant_depth = std::max(*m_descendant_depth, child_depth + 1);
    }

    Result Fetch(const uint256& hash, std::shared_ptr<const Snapshot>& result)
    {
        // The empty preimage is already known locally and cannot encode a
        // snapshot. P2P uses total=0 as its not-found sentinel, so requesting
        // this commitment would otherwise leave an invalid block pending.
        const uint256 EMPTY_HASH{ProfileSnapshotHash(Span<const unsigned char>{}, ProfileVersion(m_consensus))};
        if (hash == EMPTY_HASH) return Bad("snapshot-encoding");
        if (const auto found = m_snapshots.find(hash); found != m_snapshots.end()) {
            result = found->second;
            return Result::Valid();
        }
        try { result = m_lookup(hash); }
        catch (const MalformedSnapshot&) { return Bad("snapshot-encoding"); }
        catch (const std::exception&) { return Result::Missing({hash}); }
        if (!result) return Result::Missing({hash});
        size_t size;
        try {
            size = EncodedSize(*result);
            if (ProfileSnapshotHash(*result, ProfileVersion(m_consensus)) != hash) return Result::Missing({hash});
        } catch (const std::ios_base::failure&) { return Bad("snapshot-encoding"); }
        if (size > MAX_DEPENDENCY_BYTES - m_dependency_bytes) return Bad("dependency-bytes");
        m_dependency_bytes += size;
        m_snapshots.emplace(hash, result);
        return Result::Valid();
    }

    Result PrepareCertificates(const CBlockIndex* previous)
    {
        if (!m_consensus.SharePoolAdmittedLedger && !m_consensus.SharePoolTides) return Result::Valid();
        // Freeze this context at the top caller's actual native parent. A
        // recursive origin or proposed certificate can never replace it.
        if (m_certificates_initialized) return m_certificate_context;
        m_certificates_initialized = true;
        const auto prepare = [&]() -> Result {
            if (!previous || int64_t{previous->nHeight} + 1 < m_consensus.SharePoolHeight) return Bad("inactive");
            if (int64_t{previous->nHeight} + 1 == m_consensus.SharePoolHeight) return Result::Valid();
            if (!previous->pprev) return Bad("parent");
            std::shared_ptr<const Snapshot> parent;
            const auto available = Fetch(previous->m_mm_rhs, parent);
            if (!available.IsValid()) return available;
            if (!CheckBinding(parent->binding, m_consensus, previous->nHeight, previous->pprev->GetBlockHash()).IsValid() ||
                !Authorized(*parent) || !CertificatesOrdered(parent->certificates)) return Bad("parent");
            const int64_t parent_oldest = std::max<int64_t>(m_consensus.SharePoolHeight, int64_t{previous->nHeight} - MAX_SHARE_AGE);
            const int64_t oldest = std::max<int64_t>(m_consensus.SharePoolHeight, int64_t{previous->nHeight} + 1 - MAX_SHARE_AGE);
            for (const auto& certificate : parent->certificates) {
                if (certificate.origin_height < parent_oldest || certificate.origin_height > uint32_t(previous->nHeight) ||
                    certificate.identity.IsNull() || certificate.snapshot_hash.IsNull()) return Bad("parent-certificates");
                if (certificate.origin_height >= oldest) m_parent_certificates.emplace(certificate.identity, certificate);
            }
            return Result::Valid();
        };
        m_certificate_context = prepare();
        return m_certificate_context;
    }

    Result Origin(const CBlock& block, const CBlockIndex* parent, uint32_t depth)
    {
        if (depth > MAX_DEPENDENCY_DEPTH) return Bad("dependency-depth");
        // Even unavailable children consume their already declared edge. A
        // cached MissingData subtree must not hide that edge on a longer path.
        IncludeChildDepth(0);
        if (!parent || block.hashPrevBlock != parent->GetBlockHash() ||
            int64_t{block.m_height} != int64_t{parent->nHeight} + 1) return Bad("origin-parent");
        const auto identity = OriginMemoId(block);
        if (m_unique_origins.insert(identity).second && m_unique_origins.size() > MAX_ORIGIN_CHECKS) return Bad("origin-budget");
        const auto id = std::make_pair(identity, parent->GetBlockHash());
        if (const auto found = m_checked_origins.find(id); found != m_checked_origins.end()) {
            if (found->second.descendant_depth > MAX_DEPENDENCY_DEPTH - depth) return Bad("dependency-depth");
            IncludeChildDepth(found->second.descendant_depth);
            return found->second.result;
        }
        // Decoded records have already passed this check. Keep it for pure
        // verifier callers constructing snapshots directly, but only once per
        // exact body. Header or witness changes cannot reuse the memo above.
        if (!block.m_header_v2 || !SearchFieldsZero(block) || block.vtx.empty() ||
            block.m_txcount != block.vtx.size() || BlockMerkleRoot(block) != block.hashMerkleRoot) return Bad("template-encoding");
        // Do not spend native script-validation work before the origin's own
        // snapshot is locally available and authenticates its expected hash.
        std::shared_ptr<const Snapshot> snapshot;
        const auto available = Fetch(block.m_mm_rhs, snapshot);
        if (!available.IsValid()) return available;
        const auto binding = CheckBinding(snapshot->binding, m_consensus, block.m_height, block.hashPrevBlock);
        if (!binding.IsValid()) return binding;
        if (!Authorized(*snapshot)) return Bad("owner");
        if (snapshot->job_commitment != JobHash(block)) return Bad("job-commitment");
        if (m_consensus.SharePoolAdmittedLedger || m_consensus.SharePoolTides) {
            const auto certificate = m_parent_certificates.find(OriginCertificateId(block));
            if (certificate != m_parent_certificates.end() && int64_t{certificate->second.origin_height} == block.m_height &&
                certificate->second.native_parent == block.hashPrevBlock && certificate->second.snapshot_hash == block.m_mm_rhs) {
                // The active native parent certified this exact witness body
                // and recursive state. Direct owner/job binding above remains
                // mandatory; standalone proof binding is checked separately.
                const auto result = Result::Valid();
                m_checked_origins.emplace(id, CheckedOrigin{result, 0});
                return result;
            }
        }
        Result native;
        try { native = m_validate_origin(block, parent); }
        catch (const std::exception&) { return Result::Missing({block.m_mm_rhs}, "bad-sharepool-hash-origin-unavailable"); }
        if (native.status == Status::Invalid) return Bad("origin-body: " + native.reason);
        if (native.IsMissing()) return native;
        if (!native.expected_reward || !MoneyRange(*native.expected_reward)) return Bad("origin-reward");
        uint32_t descendant_depth{0};
        Result result;
        {
            struct DepthScope {
                uint32_t*& current;
                uint32_t* previous;
                DepthScope(uint32_t*& value, uint32_t& local) : current{value}, previous{value} { current = &local; }
                ~DepthScope() { current = previous; }
            } scope{m_descendant_depth, descendant_depth};
            result = Check(block, parent, native.expected_reward, depth);
        }
        m_checked_origins.emplace(id, CheckedOrigin{result, descendant_depth});
        IncludeChildDepth(descendant_depth);
        return result;
    }

    const CBlockIndex* OriginParent(const CBlockHeader& header, const CBlockIndex* previous, uint32_t time) const
    {
        if (!previous || !HeaderShape(header)) return nullptr;
        const int64_t height = int64_t{previous->nHeight} + 1;
        if (header.m_height < std::max<int64_t>(m_consensus.SharePoolHeight, height - MAX_SHARE_AGE) ||
            header.m_height > height) return nullptr;
        const auto* parent = previous->GetAncestor(header.m_height - 1);
        if (!parent || header.hashPrevBlock != parent->GetBlockHash() ||
            header.nBits != GetNextWorkRequired(parent, &header, m_consensus) ||
            header.GetBlockTime() <= parent->GetMedianTimePast() ||
            header.GetBlockTime() > int64_t{time} + 7200) return nullptr;
        return parent;
    }

public:
    Checker(const Consensus::Params& consensus, const Lookup& lookup, const ValidateOrigin& validate_origin)
        : m_consensus{consensus}, m_lookup{lookup}, m_validate_origin{validate_origin} {}

    Result MiningJob(const CBlock& block, const CBlockIndex* previous,
                     std::optional<CAmount> expected_reward, bool allow_unsigned)
    {
        if (!SearchFieldsZero(block)) return Bad("job-search-fields");
        // A future settlement must embed this body in addition to its children.
        // Ordinary block validity deliberately keeps its unreserved depth zero.
        m_unique_origins.insert(OriginMemoId(block));
        return Check(block, previous, expected_reward, 1, allow_unsigned);
    }

    Result HistoricalTemplate(const CBlock& origin, const CBlockIndex* previous, uint32_t time)
    {
        const auto context = PrepareCertificates(previous);
        if (!context.IsValid()) return context;
        const auto* parent = OriginParent(origin, previous, time);
        if (!parent) return Bad("template-context");
        return Origin(origin, parent, 0);
    }

    Result ShareProof(const Share& share, const CBlock& origin, const CBlockIndex* previous,
                      uint32_t time, uint32_t depth, bool origin_checked = false)
    {
        const auto context = PrepareCertificates(previous);
        if (!context.IsValid()) return context;
        const auto* parent = OriginParent(share.header, previous, time);
        if (!parent) return Bad("share-context");
        if (!SearchFieldsZero(origin) || NormalizedHeader(share.header) != NormalizedHeader(origin)) return Bad("share-template");
        const auto binding = CheckBinding(share.origin, m_consensus, share.header.m_height, parent->GetBlockHash());
        if (!binding.IsValid()) return binding;
        if (m_consensus.SharePoolTides && share.header.GetHash().IsNull()) return Bad("share-identity");
        if (UintToArith256(share.header.GetHash()) > UintToArith256(ShareTarget(share.header.nBits, ProfileVersion(m_consensus)))) return Bad("share-target");
        std::shared_ptr<const Snapshot> snapshot;
        auto result = Fetch(origin.m_mm_rhs, snapshot);
        if (!result.IsValid()) return result;
        if (!SameBinding(snapshot->binding, share.origin)) return Bad("share-binding");
        if (share.authorization != snapshot->authorization) return Bad("share-authorization");
        // The containing snapshot already visited every full body exactly once,
        // including any MissingData result. Avoid hashing a4MiB body again for
        // every small proof referring to it (which would amplify work by count).
        if (origin_checked) return Result::Valid();
        return Origin(origin, parent, depth);
    }

    Result Check(const CBlock& block, const CBlockIndex* previous, std::optional<CAmount> expected_reward, uint32_t depth, bool allow_unsigned = false)
    {
        if (!m_consensus.SharePoolHashOnly || !previous || m_consensus.SharePoolHeight == std::numeric_limits<int>::max() ||
            int64_t{previous->nHeight} + 1 < m_consensus.SharePoolHeight) return Bad("inactive");
        if (depth > MAX_DEPENDENCY_DEPTH) return Bad("dependency-depth");
        const int64_t height = int64_t{previous->nHeight} + 1;
        if (!HeaderShape(block) || block.m_height != height || block.hashPrevBlock != previous->GetBlockHash()) return Bad("context");
        if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) return Bad("coinbase");
        if (block.m_mm_rhs.IsNull()) return Bad("commitment");
        const auto certificate_context = PrepareCertificates(previous);
        if (!certificate_context.IsValid()) return certificate_context;
        if (!m_visiting.insert(block.m_mm_rhs).second) return Bad("dependency-cycle");
        struct Pop { std::set<uint256>& visiting; uint256 hash; ~Pop() { visiting.erase(hash); } } pop{m_visiting, block.m_mm_rhs};
        std::shared_ptr<const Snapshot> snapshot;
        auto result = Fetch(block.m_mm_rhs, snapshot);
        if (!result.IsValid()) return result;
        result = CheckBinding(snapshot->binding, m_consensus, height, previous->GetBlockHash());
        if (!result.IsValid()) return result;
        if (!allow_unsigned && !Authorized(*snapshot)) return Bad("owner");
        if (allow_unsigned && snapshot->authorization != Signature{}) return Bad("unsigned-authorization");
        if (snapshot->job_commitment != JobHash(block)) return Bad("job-commitment");
        if (!StateOrdered(snapshot->post_state)) return Bad("state-order");
        if (!(m_consensus.SharePoolTides && snapshot->payouts.empty()) && !PayoutsOrdered(snapshot->payouts)) return Bad("payout-order");
        for (size_t i{1}; i < snapshot->shares.size(); ++i) {
            if (!LessProof(snapshot->shares[i - 1].header.GetHash(), snapshot->shares[i].header.GetHash())) return Bad("share-order");
        }

        std::set<uint256> missing;
        std::string missing_reason{"bad-sharepool-hash-missing-data"};
        bool missing_any{false};
        const auto collect_missing = [&](const Result& missing_result) {
            missing_any = true;
            missing.insert(missing_result.missing.begin(), missing_result.missing.end());
            missing_reason = missing_result.reason;
        };
        std::vector<StateEntry> next;
        std::set<arith_uint256> paid;
        std::shared_ptr<const Snapshot> native_parent;
        if (height != m_consensus.SharePoolHeight) {
            if (!previous->pprev) return Bad("parent");
            auto& parent = native_parent;
            result = Fetch(previous->m_mm_rhs, parent);
            if (result.IsMissing()) collect_missing(result);
            else if (!result.IsValid()) return result;
            else {
                const auto context = CheckBinding(parent->binding, m_consensus, previous->nHeight, previous->pprev->GetBlockHash());
                if (!context.IsValid() || !Authorized(*parent) || !StateOrdered(parent->post_state)) return Bad("parent");
                if (m_consensus.SharePoolAdmittedLedger) {
                    if (!CreditsOrdered(parent->pending)) return Bad("parent-ledger");
                    for (const auto& credit : parent->pending) paid.insert(UintToArith256(credit.proof_id));
                }
                for (const auto& entry : parent->post_state) {
                    if (entry.origin_height < std::max<int64_t>(m_consensus.SharePoolHeight, int64_t{previous->nHeight} - MAX_SHARE_AGE) ||
                        entry.origin_height > uint32_t(previous->nHeight)) return Bad("parent-state");
                    paid.insert(UintToArith256(entry.proof_id));
                    if (entry.origin_height >= std::max<int64_t>(m_consensus.SharePoolHeight, height - MAX_SHARE_AGE)) next.push_back(entry);
                }
            }
        }

        // Immutable transaction refs are shared. The compact wire bytes and
        // expanded body/reference budgets are checked before this walk.
        std::map<uint256, const CBlock*> origins;
        const auto containing_id = TemplateId(block);
        const auto containing_proof = block.GetHash();
        uint256 last_template;
        bool have_template{false};
        for (const auto& record : snapshot->templates) {
            if (have_template && !(last_template < record.id)) return Bad("template-order");
            have_template = true;
            last_template = record.id;
            if (record.id == containing_id) return Bad("self-template");
            const CBlock& origin = record.block;
            if (TemplateId(origin) != record.id) return Bad("template-id");
            const auto* parent = OriginParent(origin, previous, block.nTime);
            if (!parent) return Bad("template-context");
            if (origin.m_mm_rhs == block.m_mm_rhs) return Bad("self-snapshot");
            result = Origin(origin, parent, depth + 1);
            if (result.IsMissing()) collect_missing(result);
            else if (!result.IsValid()) return result;
            origins.emplace(record.id, &origin);
        }
        for (const auto& share : snapshot->shares) {
            if (!m_consensus.SharePoolAdmittedLedger && !m_consensus.SharePoolTides && share.origin.pool != snapshot->binding.pool) return Bad("share-pool");
            const auto id = share.header.GetHash();
            if (id == containing_proof) return Bad("self-proof");
            if (!paid.insert(UintToArith256(id)).second) return Bad("repeat-payment");
            const auto found = origins.find(TemplateId(share.header));
            if (found == origins.end()) return Bad("share-template-missing");
            result = ShareProof(share, *found->second, previous, block.nTime, depth + 1, true);
            if (result.IsMissing()) collect_missing(result);
            else if (!result.IsValid()) return result;
            next.push_back({uint32_t(share.header.m_height), id});
        }
        if (missing_any) return Result::Missing(std::vector<uint256>(missing.begin(), missing.end()), missing_reason);
        std::sort(next.begin(), next.end(), [](const auto& a, const auto& b) { return LessProof(a.proof_id, b.proof_id); });
        if (next.size() != snapshot->post_state.size()) return Bad("state");
        for (size_t i{0}; i < next.size(); ++i) {
            if (next[i].origin_height != snapshot->post_state[i].origin_height || next[i].proof_id != snapshot->post_state[i].proof_id) return Bad("state");
        }
        if (m_consensus.SharePoolAdmittedLedger) {
            Snapshot expected{*snapshot};
            try { ApplyLedgerState(expected, native_parent.get()); }
            catch (const std::invalid_argument&) { return Bad("ledger-state"); }
            catch (const std::ios_base::failure&) { return Bad("ledger-capacity"); }
            if (snapshot->pending != expected.pending) return Bad("ledger-pending");
            if (snapshot->settled != expected.settled) return Bad("ledger-settled");
            if (snapshot->certificates != expected.certificates) return Bad("ledger-certificates");
        }
        if (m_consensus.SharePoolTides) {
            Snapshot expected{*snapshot};
            try { ApplyTidesState(expected, native_parent.get()); }
            catch (const std::invalid_argument&) { return Bad("tides-state"); }
            catch (const std::ios_base::failure&) { return Bad("tides-capacity"); }
            if (snapshot->history_head != expected.history_head) return Bad("tides-history");
            if (snapshot->certificates != expected.certificates) return Bad("tides-certificates");
        }
        std::vector<CTxOut> payouts;
        for (const auto& output : block.vtx[0]->vout) {
            if (!IsPayoutScript(output.scriptPubKey)) break;
            payouts.push_back(output);
        }
        const auto& all_outputs = block.vtx[0]->vout;
        if ((!m_consensus.SharePoolTides && payouts.empty()) || (payouts.size() != all_outputs.size() &&
            (payouts.size() + 1 != all_outputs.size() || !WitnessOutput(all_outputs.back())))) return Bad("coinbase-layout");
        if (payouts != snapshot->payouts) return Bad("payouts");
        CAmount total{0};
        for (const auto& output : payouts) {
            if (!MoneyRange(output.nValue) || output.nValue > MAX_MONEY - total) return Bad("payouts");
            total += output.nValue;
        }
        if (m_consensus.SharePoolTides) {
            if (!expected_reward) return Result::Missing({}, "bad-sharepool-hash-tides-native-reward-unavailable");
            std::vector<CTxOut> expected_payouts;
            const auto accounting = CalculateTidesPayouts(*snapshot, previous, block.nBits, m_consensus,
                                                         m_lookup, *expected_reward, expected_payouts);
            if (!accounting.IsValid()) return accounting;
            if (payouts != expected_payouts) return Bad("tides-payouts");
        } else {
            if (expected_reward && (!MoneyRange(*expected_reward) || total != *expected_reward)) return Bad("reward");
            if (payouts != hashonly::CalculatePayouts(*snapshot, total)) return Bad("payouts");
        }
        return Result::Valid(expected_reward);
    }
};
} // namespace

std::vector<unsigned char> EncodeSnapshot(const Snapshot& snapshot)
{
    const auto size = EncodedSize(snapshot);
    std::vector<unsigned char> bytes;
    bytes.reserve(size);
    VectorWriter writer{bytes, 0};
    WriteSnapshot(writer, snapshot);
    return bytes;
}

CBlock DecodeTemplate(Span<const unsigned char> bytes) { return ReadTemplate(bytes); }
CBlock DecodeBlock(Span<const unsigned char> bytes) { return ReadBlock(bytes, false); }

CTransactionRef DecodeTransaction(Span<const unsigned char> bytes)
{
    if (bytes.size() < 10 || bytes.size() > MAX_TEMPLATE_BYTES) throw std::ios_base::failure("transaction byte bound");
    SpanReader preflight{bytes};
    PreflightTransaction(preflight);
    if (!preflight.empty()) throw std::ios_base::failure("trailing transaction bytes");
    SpanReader encoded{bytes};
    CMutableTransaction decoded;
    encoded >> TX_WITH_WITNESS(decoded);
    auto tx = MakeTransactionRef(std::move(decoded));
    DataStream canonical;
    canonical << TX_WITH_WITNESS(*tx);
    if (!encoded.empty() || canonical.size() != bytes.size() ||
        !std::equal(bytes.begin(), bytes.end(), UCharCast(canonical.data()))) throw std::ios_base::failure("noncanonical transaction");
    return tx;
}

Snapshot DecodeSnapshot(Span<const unsigned char> bytes)
{
    if (bytes.empty() || bytes.size() > MAX_SNAPSHOT_BYTES) throw std::ios_base::failure("snapshot byte bound");
    SpanReader reader{bytes};
    Snapshot snapshot;
    reader >> snapshot.binding >> snapshot.authorization >> snapshot.job_commitment;
    if (!WireBinding(snapshot.binding)) throw std::ios_base::failure("invalid hash profile binding");
    const auto transaction_count = ReadCount(reader, 11);
    std::vector<CTransactionRef> transactions;
    transactions.reserve(transaction_count);
    std::vector<size_t> transaction_sizes;
    transaction_sizes.reserve(transaction_count);
    for (size_t i{0}; i < transaction_count; ++i) {
        const auto raw = ReadBytes(reader, 10, MAX_TEMPLATE_BYTES);
        auto tx = DecodeTransaction(raw);
        if (i && !(transactions.back()->GetWitnessHash() < tx->GetWitnessHash())) {
            throw std::ios_base::failure("transaction table order or encoding");
        }
        transactions.push_back(std::move(tx));
        transaction_sizes.push_back(raw.size());
    }
    std::vector<bool> used(transactions.size(), false);
    const auto template_count = ReadCount(reader, MIN_TEMPLATE_RECORD_BYTES);
    snapshot.templates.reserve(template_count);
    size_t expanded{0}, references{0};
    for (size_t i{0}; i < template_count; ++i) {
        TemplateRecord record;
        CBlockHeader header;
        reader >> record.id >> header;
        record.block = CBlock{header};
        if (!header.m_header_v2 || !SearchFieldsZero(header)) throw std::ios_base::failure("template header shape");
        const auto count = ReadCount(reader, 1);
        if (!count || count != header.m_txcount || count > MAX_TEMPLATE_TX_REFERENCES - references) {
            throw std::ios_base::failure("template transaction reference budget");
        }
        references += count;
        size_t body_bytes = GetSerializeSize(header) + GetSizeOfCompactSize(count);
        record.block.vtx.reserve(count);
        for (size_t j{0}; j < count; ++j) {
            const auto index = ReadCompactSize(reader);
            if (index >= transactions.size() || transaction_sizes[index] > MAX_TEMPLATE_BYTES - body_bytes) {
                throw std::ios_base::failure("template transaction index or byte budget");
            }
            body_bytes += transaction_sizes[index];
            used[index] = true;
            record.block.vtx.push_back(transactions[index]);
        }
        if (body_bytes > MAX_EXPANDED_TEMPLATE_BYTES - expanded) throw std::ios_base::failure("expanded template budget");
        expanded += body_bytes;
        if (i && !(snapshot.templates.back().id < record.id)) throw std::ios_base::failure("template order");
        if (TemplateId(record.block) != record.id || BlockMerkleRoot(record.block) != record.block.hashMerkleRoot) {
            throw std::ios_base::failure("template id or transaction root");
        }
        snapshot.templates.push_back(std::move(record));
    }
    if (std::find(used.begin(), used.end(), false) != used.end()) throw std::ios_base::failure("unused transaction table entry");
    const auto share_count = ReadCount(reader, MIN_SHARE_BYTES);
    snapshot.shares.reserve(share_count);
    for (size_t i{0}; i < share_count; ++i) {
        Share share;
        reader >> share;
        if (!share.header.m_header_v2 || !WireBinding(share.origin) ||
            (i && !LessProof(snapshot.shares.back().header.GetHash(), share.header.GetHash()))) throw std::ios_base::failure("share wire shape or order");
        snapshot.shares.push_back(std::move(share));
    }
    const auto state_count = ReadCount(reader, MIN_STATE_BYTES);
    snapshot.post_state.resize(state_count);
    for (auto& entry : snapshot.post_state) reader >> entry;
    if (!StateOrdered(snapshot.post_state)) throw std::ios_base::failure("state order");
    const auto payout_count = ReadCount(reader, MIN_PAYOUT_BYTES);
    snapshot.payouts.reserve(payout_count);
    for (size_t i{0}; i < payout_count; ++i) {
        CAmount amount;
        reader >> amount;
        const auto script = ReadBytes(reader, 22, 34);
        snapshot.payouts.emplace_back(amount, CScript{script.begin(), script.end()});
    }
    if (!(snapshot.binding.version == TIDES_VERSION && snapshot.payouts.empty()) && !PayoutsOrdered(snapshot.payouts)) throw std::ios_base::failure("payout order or shape");
    if (snapshot.binding.version == LEDGER_VERSION) {
        const auto read_credits = [&](std::vector<LedgerCredit>& credits, size_t maximum) {
            const auto before = reader.size();
            const auto count = ReadCount(reader, MIN_CREDIT_BYTES);
            if (count > maximum / MIN_CREDIT_BYTES) throw std::ios_base::failure("ledger credit count bound");
            credits.reserve(count);
            for (size_t i{0}; i < count; ++i) {
                LedgerCredit credit;
                reader >> credit.admitted_height >> credit.origin_height >> credit.proof_id >> credit.pool >> credit.native_bits;
                credit.payout_script = ReadBytes(reader, 22, 34);
                if (!IsPayoutScript(credit.payout_script)) throw std::ios_base::failure("ledger payout script shape");
                credits.push_back(std::move(credit));
            }
            if (before - reader.size() > maximum || !CreditsOrdered(credits)) throw std::ios_base::failure("ledger byte bound or order");
        };
        read_credits(snapshot.pending, MAX_PENDING_BYTES);
        read_credits(snapshot.settled, MAX_SETTLED_BYTES);
    }
    if (snapshot.binding.version == LEDGER_VERSION || snapshot.binding.version == TIDES_VERSION) {
        const auto before = reader.size();
        const auto count = ReadCount(reader, CERTIFICATE_BYTES);
        if (count > MAX_CERTIFICATE_BYTES / CERTIFICATE_BYTES) throw std::ios_base::failure("certificate count bound");
        snapshot.certificates.resize(count);
        for (auto& certificate : snapshot.certificates) reader >> certificate;
        if (before - reader.size() > MAX_CERTIFICATE_BYTES || !CertificatesOrdered(snapshot.certificates)) {
            throw std::ios_base::failure("certificate byte bound or order");
        }
    }
    if (snapshot.binding.version == TIDES_VERSION) reader >> snapshot.history_head;
    const auto canonical = EncodeSnapshot(snapshot);
    if (!reader.empty() || canonical.size() != bytes.size() ||
        !std::equal(canonical.begin(), canonical.end(), bytes.begin())) throw std::ios_base::failure("noncanonical snapshot");
    return snapshot;
}

uint256 SnapshotHash(Span<const unsigned char> bytes)
{
    if (bytes.size() > MAX_SNAPSHOT_BYTES) throw std::ios_base::failure("snapshot byte bound");
    static constexpr char old_domain[]{"SharePool/snapshot/v4"};
    static constexpr char new_domain[]{"SharePool/snapshot/v5"};
    HashWriter writer;
    writer.write(AsBytes(!bytes.empty() && bytes[0] == LEDGER_VERSION ? Span{new_domain} : Span{old_domain}));
    writer.write(AsBytes(bytes));
    return writer.GetHash();
}

uint256 SnapshotHash(const Snapshot& snapshot)
{
    // Preserve legacy object hashing for deliberately malformed version tags.
    return ProfileSnapshotHash(snapshot, snapshot.binding.version == TIDES_VERSION ? TIDES_VERSION : VERSION);
}

uint256 ProfileSnapshotHash(Span<const unsigned char> bytes, uint32_t version)
{
    if (version == VERSION || version == LEDGER_VERSION) return SnapshotHash(bytes);
    if (version != TIDES_VERSION) throw std::invalid_argument("unknown snapshot hash profile");
    if (bytes.size() > MAX_SNAPSHOT_BYTES) throw std::ios_base::failure("snapshot byte bound");
    static constexpr char domain[]{"SharePool/snapshot/v6"};
    HashWriter writer;
    writer.write(AsBytes(Span{domain}));
    writer.write(AsBytes(bytes));
    return writer.GetHash();
}

uint256 ProfileSnapshotHash(const Snapshot& snapshot, uint32_t version)
{
    if (version != VERSION && version != LEDGER_VERSION && version != TIDES_VERSION) {
        throw std::invalid_argument("unknown snapshot hash profile");
    }
    EncodedSize(snapshot);
    static constexpr char old_domain[]{"SharePool/snapshot/v4"};
    static constexpr char new_domain[]{"SharePool/snapshot/v5"};
    static constexpr char tides_domain[]{"SharePool/snapshot/v6"};
    HashWriter writer;
    writer.write(AsBytes(version == TIDES_VERSION ? Span{tides_domain} :
                        snapshot.binding.version == LEDGER_VERSION ? Span{new_domain} : Span{old_domain}));
    WriteSnapshot(writer, snapshot);
    return writer.GetHash();
}

uint32_t ProfileVersion(const Consensus::Params& consensus)
{
    return consensus.SharePoolTides ? TIDES_VERSION : consensus.SharePoolAdmittedLedger ? LEDGER_VERSION : VERSION;
}

uint256 RulesHash(uint32_t version)
{
    if (version == TIDES_VERSION) {
        return DomainHash("SharePool/rules/v6", SHARE_BITS, SHARE_TARGET_SHIFT, MAX_SHARE_AGE, MAX_SNAPSHOT_BYTES,
                          MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES,
                          MAX_EXPANDED_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES, MAX_ORIGIN_CHECKS,
                          MAX_CERTIFICATE_BYTES, uint32_t{8}, uint32_t{1});
    }
    if (version == LEDGER_VERSION) {
        return DomainHash("SharePool/rules/v5", SHARE_BITS, SHARE_TARGET_SHIFT, MAX_SHARE_AGE, MAX_SNAPSHOT_BYTES,
                          MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES,
                          MAX_EXPANDED_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES, MAX_ORIGIN_CHECKS,
                          MAX_PENDING_BYTES, MAX_SETTLED_BYTES, MAX_CERTIFICATE_BYTES);
    }
    if (version != VERSION) throw std::invalid_argument("unknown hash profile version");
    return DomainHash("SharePool/rules/v4", SHARE_BITS, SHARE_TARGET_SHIFT, MAX_SHARE_AGE, MAX_SNAPSHOT_BYTES,
                      MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES,
                      MAX_EXPANDED_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES, MAX_ORIGIN_CHECKS);
}

uint256 SnapshotContentsHash(const Snapshot& snapshot)
{
    // Stream rather than copying a potentially 16 MiB snapshot.
    EncodedSize(snapshot);
    HashWriter writer;
    static constexpr char old_domain[]{"SharePool/contents/v4"};
    static constexpr char new_domain[]{"SharePool/contents/v5"};
    static constexpr char tides_domain[]{"SharePool/contents/v6"};
    writer.write(AsBytes(snapshot.binding.version == TIDES_VERSION ? Span{tides_domain} :
                        snapshot.binding.version == LEDGER_VERSION ? Span{new_domain} : Span{old_domain}));
    WriteSnapshot(writer, snapshot, true);
    return writer.GetHash();
}

uint256 OwnerHash(const Envelope& binding, const uint256& job, const uint256& contents)
{
    if (binding.version == TIDES_VERSION) return DomainHash("SharePool/owner/v6", binding, job, contents);
    if (binding.version == LEDGER_VERSION) return DomainHash("SharePool/owner/v5", binding, job, contents);
    return DomainHash("SharePool/owner/v4", binding, job, contents);
}

uint256 OwnerHash(const Snapshot& snapshot)
{
    return OwnerHash(snapshot.binding, snapshot.job_commitment, SnapshotContentsHash(snapshot));
}

uint256 JobHash(const CBlock& block)
{
    CBlockHeader header{block};
    header.m_mm_rhs.SetNull();
    HashWriter writer;
    static constexpr char domain[]{"SharePool/job/v4"};
    writer.write(AsBytes(Span{domain}));
    writer.write(AsBytes(Span{NormalizedHeader(header)}));
    writer << TX_WITH_WITNESS(block.vtx);
    return writer.GetHash();
}

uint256 OriginCertificateId(const CBlock& block)
{
    HashWriter writer;
    static constexpr char domain[]{"SharePool/origin-certificate/v5"};
    writer.write(AsBytes(Span{domain}));
    writer.write(AsBytes(Span{NormalizedHeader(block)}));
    WriteCompactSize(writer, block.vtx.size());
    for (const auto& tx : block.vtx) {
        if (!tx) throw std::ios_base::failure("null certificate transaction");
        writer << tx->GetWitnessHash();
    }
    return writer.GetHash();
}

namespace {
tides::Work NumericWork(const uint256& value)
{
    tides::Work result{0};
    for (size_t i{value.size()}; i > 0; --i) { result <<= 8; result += value.begin()[i - 1]; }
    return result;
}

uint256 NativeTarget(uint32_t native_bits)
{
    bool negative{false}, overflow{false};
    arith_uint256 native;
    native.SetCompact(native_bits, &negative, &overflow);
    if (negative || overflow || native == 0 || native.GetCompact() != native_bits) {
        throw std::invalid_argument("noncanonical native target");
    }
    return ArithToUint256(native);
}
} // namespace

uint256 TidesShareWork(uint32_t native_bits)
{
    // Assign an exact integer expected-hash weight before the miner works.
    // The target 2^256/work - 1 then succeeds with probability 1/work.
    const tides::Work network = (tides::Work{1} << 256) / (NumericWork(NativeTarget(native_bits)) + 1);
    const tides::Work desired = std::max(tides::Work{1}, tides::Work{network >> SHARE_TARGET_SHIFT});
    const tides::Work work = tides::Work{1} << boost::multiprecision::msb(desired);
    return uint256::FromUserHex(work.str(0, std::ios_base::hex)).value();
}

uint256 ShareTarget(uint32_t native_bits, uint32_t version)
{
    if (version == TIDES_VERSION) {
        const auto work = UintToArith256(TidesShareWork(native_bits));
        return ArithToUint256(~arith_uint256{} / work);
    }
    if (version != VERSION && version != LEDGER_VERSION) throw std::invalid_argument("unknown share target profile");
    bool negative{false}, overflow{false};
    arith_uint256 native;
    native.SetCompact(native_bits, &negative, &overflow);
    if (negative || overflow || native == 0 || native.GetCompact() != native_bits) {
        throw std::invalid_argument("noncanonical native target");
    }
    const auto maximum = arith_uint256{}.SetCompact(SHARE_BITS);
    if (native > (maximum >> SHARE_TARGET_SHIFT)) return ArithToUint256(maximum);
    native <<= SHARE_TARGET_SHIFT;
    return ArithToUint256(native);
}

std::vector<unsigned char> NormalizedHeader(const CBlockHeader& source)
{
    CBlockHeader header{source};
    header.nNonce = header.m_nonce2 = header.m_nonce3 = header.m_time_offset = 0;
    header.m_extranonce.SetNull();
    std::vector<unsigned char> bytes;
    VectorWriter{bytes, 0} << header;
    return bytes;
}

uint256 TemplateId(const CBlockHeader& header)
{
    const auto bytes = NormalizedHeader(header);
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256{}.Write(bytes.data(), bytes.size()).Finalize(digest);
    uint256 result;
    std::reverse_copy(std::begin(digest), std::end(digest), result.begin());
    return result;
}

void ApplyLedgerState(Snapshot& snapshot, const Snapshot* parent)
{
    if (snapshot.binding.version != LEDGER_VERSION || snapshot.binding.height == 0 ||
        snapshot.binding.pool.IsNull() || snapshot.binding.rules != RulesHash(LEDGER_VERSION)) {
        throw std::invalid_argument("ledger profile or binding");
    }
    const uint32_t height = snapshot.binding.height;
    const uint32_t oldest = height > MAX_SHARE_AGE ? height - MAX_SHARE_AGE : 0;
    std::vector<LedgerCredit> pending, settled;
    std::vector<StateEntry> state;
    std::map<uint256, OriginCertificate> certificates;
    std::set<uint256> admitted;
    if (parent) {
        if (parent->binding.version != LEDGER_VERSION || parent->binding.height != height - 1 ||
            parent->binding.genesis != snapshot.binding.genesis || parent->binding.rules != snapshot.binding.rules ||
            !CreditsOrdered(parent->pending) || !StateOrdered(parent->post_state) || !CertificatesOrdered(parent->certificates)) {
            throw std::invalid_argument("ledger parent context or order");
        }
        CreditBounds(parent->pending, MAX_PENDING_BYTES);
        if (GetSerializeSize(parent->certificates) > MAX_CERTIFICATE_BYTES) throw std::ios_base::failure("certificate byte bound");
        size_t settlement_bytes{0};
        bool prefix_full{false};
        for (const auto& credit : parent->pending) {
            if (!credit.admitted_height || credit.admitted_height > parent->binding.height ||
                !credit.origin_height || credit.origin_height > credit.admitted_height ||
                uint64_t{credit.admitted_height} - credit.origin_height > MAX_SHARE_AGE || credit.pool.IsNull() ||
                !admitted.insert(credit.proof_id).second) throw std::invalid_argument("ledger parent credit");
            ShareTarget(credit.native_bits);
            if (credit.pool == snapshot.binding.pool && !prefix_full) {
                const size_t bytes = GetSerializeSize(credit);
                if (settlement_bytes + bytes + GetSizeOfCompactSize(settled.size() + 1) <= MAX_SETTLED_BYTES) {
                    settlement_bytes += bytes;
                    settled.push_back(credit);
                    continue;
                }
                prefix_full = true;
            }
            pending.push_back(credit);
        }
        const uint32_t parent_oldest = parent->binding.height > MAX_SHARE_AGE ? parent->binding.height - MAX_SHARE_AGE : 0;
        for (const auto& entry : parent->post_state) {
            if (entry.origin_height < parent_oldest || entry.origin_height > parent->binding.height) {
                throw std::invalid_argument("ledger parent admission state");
            }
            admitted.insert(entry.proof_id);
            if (entry.origin_height >= oldest) state.push_back(entry);
        }
        for (const auto& certificate : parent->certificates) {
            if (certificate.origin_height < parent_oldest || certificate.origin_height > parent->binding.height ||
                certificate.identity.IsNull() || certificate.snapshot_hash.IsNull()) throw std::invalid_argument("ledger parent certificate");
            if (certificate.origin_height >= oldest) certificates.emplace(certificate.identity, certificate);
        }
    }
    std::map<uint256, const CBlock*> origins;
    for (const auto& record : snapshot.templates) {
        if (!origins.emplace(record.id, &record.block).second) throw std::invalid_argument("ledger duplicate origin");
    }
    for (const auto& share : snapshot.shares) {
        const auto proof_id = share.header.GetHash();
        if (!admitted.insert(proof_id).second) throw std::invalid_argument("ledger repeated admission");
        if (share.header.m_height < int64_t{oldest} || share.header.m_height > int64_t{height} || share.header.m_height <= 0 ||
            share.origin.version != LEDGER_VERSION || int64_t{share.origin.height} != share.header.m_height ||
            share.origin.pool.IsNull() || !IsPayoutScript(share.origin.payout_script)) throw std::invalid_argument("ledger admission context");
        ShareTarget(share.header.nBits);
        const auto origin = origins.find(TemplateId(share.header));
        if (origin == origins.end() || NormalizedHeader(*origin->second) != NormalizedHeader(share.header)) {
            throw std::invalid_argument("ledger admission origin");
        }
        pending.push_back({height, uint32_t(share.header.m_height), proof_id, share.origin.pool,
                           share.header.nBits, share.origin.payout_script});
        state.push_back({uint32_t(share.header.m_height), proof_id});
        OriginCertificate certificate{uint32_t(share.header.m_height), share.header.hashPrevBlock,
                                      OriginCertificateId(*origin->second), share.header.m_mm_rhs};
        const auto [found, inserted] = certificates.emplace(certificate.identity, certificate);
        if (!inserted && found->second != certificate) throw std::invalid_argument("ledger certificate collision");
    }
    std::sort(pending.begin(), pending.end(), CreditLess);
    std::sort(state.begin(), state.end(), [](const auto& a, const auto& b) { return LessProof(a.proof_id, b.proof_id); });
    CreditBounds(pending, MAX_PENDING_BYTES);
    CreditBounds(settled, MAX_SETTLED_BYTES);
    std::vector<OriginCertificate> next_certificates;
    next_certificates.reserve(certificates.size());
    for (const auto& [identity, certificate] : certificates) next_certificates.push_back(certificate);
    if (GetSerializeSize(next_certificates) > MAX_CERTIFICATE_BYTES) throw std::ios_base::failure("certificate byte bound");
    snapshot.pending = std::move(pending);
    snapshot.settled = std::move(settled);
    snapshot.post_state = std::move(state);
    snapshot.certificates = std::move(next_certificates);
}

void ApplyTidesState(Snapshot& snapshot, const Snapshot* parent)
{
    if (snapshot.binding.version != TIDES_VERSION || !snapshot.binding.height || snapshot.binding.pool.IsNull() ||
        snapshot.binding.rules != RulesHash(TIDES_VERSION) || !snapshot.pending.empty() || !snapshot.settled.empty()) {
        throw std::invalid_argument("TIDES profile or binding");
    }
    const uint32_t height = snapshot.binding.height;
    const uint32_t oldest = height > MAX_SHARE_AGE ? height - MAX_SHARE_AGE : 0;
    std::vector<StateEntry> state;
    std::set<uint256> admitted;
    std::map<uint256, OriginCertificate> certificates;
    if (parent) {
        if (parent->binding.version != TIDES_VERSION || parent->binding.height != height - 1 ||
            parent->binding.genesis != snapshot.binding.genesis || parent->binding.rules != snapshot.binding.rules ||
            parent->history_head.IsNull() || !parent->pending.empty() || !parent->settled.empty() ||
            !StateOrdered(parent->post_state) || !CertificatesOrdered(parent->certificates)) {
            throw std::invalid_argument("TIDES native parent state");
        }
        const uint32_t parent_oldest = parent->binding.height > MAX_SHARE_AGE ? parent->binding.height - MAX_SHARE_AGE : 0;
        for (const auto& entry : parent->post_state) {
            if (entry.origin_height < parent_oldest || entry.origin_height > parent->binding.height) {
                throw std::invalid_argument("TIDES parent admission age");
            }
            admitted.insert(entry.proof_id);
            if (entry.origin_height >= oldest) state.push_back(entry);
        }
        for (const auto& certificate : parent->certificates) {
            if (certificate.origin_height < parent_oldest || certificate.origin_height > parent->binding.height ||
                certificate.identity.IsNull() || certificate.snapshot_hash.IsNull()) {
                throw std::invalid_argument("TIDES parent certificate");
            }
            if (certificate.origin_height >= oldest) certificates.emplace(certificate.identity, certificate);
        }
    }
    std::map<uint256, const CBlock*> origins;
    for (const auto& record : snapshot.templates) {
        if (!origins.emplace(record.id, &record.block).second) throw std::invalid_argument("TIDES duplicate template");
    }
    std::map<uint256, OriginCertificate> template_certificates;
    std::vector<LedgerCredit> delta;
    for (const auto& share : snapshot.shares) {
        const auto id = share.header.GetHash();
        if (id.IsNull() || !admitted.insert(id).second || share.origin.version != TIDES_VERSION ||
            share.header.m_height <= 0 || share.header.m_height < int64_t(oldest) || share.header.m_height > int64_t(height) ||
            int64_t(share.origin.height) != share.header.m_height || share.origin.pool.IsNull() || !IsPayoutScript(share.origin.payout_script)) {
            throw std::invalid_argument("TIDES admission identity or age");
        }
        TidesShareWork(share.header.nBits);
        const auto origin = origins.find(TemplateId(share.header));
        if (origin == origins.end() || NormalizedHeader(*origin->second) != NormalizedHeader(share.header)) {
            throw std::invalid_argument("TIDES admission template");
        }
        state.push_back({share.origin.height, id});
        delta.push_back({height, share.origin.height, id, share.origin.pool, share.header.nBits, share.origin.payout_script});
        auto cached = template_certificates.find(origin->first);
        if (cached == template_certificates.end()) {
            cached = template_certificates.emplace(origin->first, OriginCertificate{share.origin.height, share.header.hashPrevBlock,
                OriginCertificateId(*origin->second), share.header.m_mm_rhs}).first;
        }
        const auto& certificate = cached->second;
        const auto [found, inserted] = certificates.emplace(certificate.identity, certificate);
        if (!inserted && found->second != certificate) throw std::invalid_argument("TIDES certificate collision");
    }
    if (!CreditsOrdered(delta)) throw std::invalid_argument("TIDES admission order");
    std::sort(state.begin(), state.end(), [](const auto& a, const auto& b) { return LessProof(a.proof_id, b.proof_id); });
    std::vector<OriginCertificate> next_certificates;
    for (const auto& [identity, certificate] : certificates) next_certificates.push_back(certificate);
    if (GetSerializeSize(next_certificates) > MAX_CERTIFICATE_BYTES) throw std::ios_base::failure("TIDES certificate capacity");
    snapshot.post_state = std::move(state);
    snapshot.certificates = std::move(next_certificates);
    snapshot.history_head = DomainHash("SharePool/history/v6", snapshot.binding.genesis, snapshot.binding.native_parent,
                                      height, parent ? parent->history_head : uint256{}, delta);
}

Result CalculateTidesPayouts(const Snapshot& snapshot, const CBlockIndex* previous,
                            uint32_t native_bits, const Consensus::Params& consensus,
                            const Lookup& lookup, CAmount reward,
                            std::vector<CTxOut>& payouts, bool reserve_scripts)
{
    if (!consensus.SharePoolTides || snapshot.binding.version != TIDES_VERSION || !previous ||
        snapshot.binding.native_parent != previous->GetBlockHash() || !MoneyRange(reward)) return Bad("tides-accounting-context");
    using tides::Work;
    const Work denominator = NumericWork(NativeTarget(native_bits)) + 1;
    const Work requested = Work{8} << 256;
    Work current_work{0};
    std::vector<tides::Admission> current;
    for (const auto& share : snapshot.shares) {
        if (share.origin.pool != snapshot.binding.pool) continue;
        const auto work = TidesShareWork(share.header.nBits);
        current.push_back({share.header.GetHash(), share.origin.pool, share.origin.payout_script, work});
        current_work += NumericWork(work);
    }
    const Work needed = (requested + denominator - 1) / denominator;
    // The cache owns only immutable derived data/cursors. It retains no native
    // index pointers and is private to this validation/RPC thread.
    thread_local tides::HistoryIndex history;
    history.SetCacheBudget(tides::ConfiguredHistoryCacheBudget());
    const auto fetch = [&](const CBlockIndex& index) -> tides::DeltaResult {
        std::shared_ptr<const Snapshot> old;
        try { old = lookup(index.m_mm_rhs); }
        catch (const MalformedSnapshot&) { return tides::DeltaResult::Invalid("tides-history-encoding"); }
        catch (const std::exception&) { return tides::DeltaResult::Missing({index.m_mm_rhs}); }
        if (!old) return tides::DeltaResult::Missing({index.m_mm_rhs});
        if (ProfileSnapshotHash(*old, TIDES_VERSION) != index.m_mm_rhs) return tides::DeltaResult::Missing({index.m_mm_rhs});
        if (!index.pprev || !CheckBinding(old->binding, consensus, index.nHeight, index.pprev->GetBlockHash()).IsValid() ||
            !OwnerValid(*old) || old->history_head.IsNull()) return tides::DeltaResult::Invalid("tides-history-binding");
        auto delta = std::make_shared<tides::HistoryDelta>();
        delta->block_hash = index.GetBlockHash();
        delta->parent_hash = index.pprev->GetBlockHash();
        delta->snapshot_hash = index.m_mm_rhs;
        delta->height = index.nHeight;
        delta->encoded_bytes = EncodedSize(*old);
        // These summaries belong to the candidate's exact native ancestry.
        // On an unconnected competing branch they remain CONDITIONAL on native
        // validation of every ancestor during activation. Requiring connected
        // script status here would prevent a shorter branch becoming longer.
        // Proposed/foreign snapshots cannot substitute a different ancestor.
        for (const auto& share : old->shares) {
            delta->admissions.push_back({share.header.GetHash(), share.origin.pool,
                                        share.origin.payout_script, TidesShareWork(share.header.nBits)});
        }
        return tides::DeltaResult::Ready(std::move(delta));
    };
    const auto old = history.ReadPool(previous, consensus.SharePoolHeight, snapshot.binding.pool,
                                      current_work >= needed ? Work{0} : Work{needed - current_work}, fetch);
    if (old.status == tides::HistoryStatus::Invalid) return Bad(old.reason);
    if (old.status != tides::HistoryStatus::Ready) {
        const bool progress = old.status == tides::HistoryStatus::ResourceLimit && old.scanned_blocks > 0;
        return Result::Missing(old.missing, "bad-sharepool-hash-" + old.reason + (progress ? "-progress" : ""));
    }
    std::map<std::vector<unsigned char>, Work> weights;
    Work remaining = requested;
    const auto add = [&](const std::vector<unsigned char>& script, const uint256& work) {
        if (!IsPayoutScript(script)) throw std::invalid_argument("TIDES payout script");
        const Work included = std::min(remaining, Work{NumericWork(work) * denominator});
        if (included != 0) weights[script] += included;
        remaining -= included;
    };
    for (auto it = current.rbegin(); it != current.rend() && remaining != 0; ++it) add(it->payout_script, it->work);
    for (auto it = old.entries.rbegin(); it != old.entries.rend() && remaining != 0; ++it) add(it->payout_script, it->work);
    if (remaining != 0 && !old.complete_to_activation) return Result::Missing({}, "bad-sharepool-hash-tides-history-incomplete");
    std::vector<CTxOut> result;
    if (weights.empty()) {
        // Explicit permissionless new-pool bootstrap. This path is available
        // only after the complete actual-parent pool history is known empty.
        if (!old.complete_to_activation) return Result::Missing({}, "bad-sharepool-hash-tides-history-incomplete");
        if (!IsPayoutScript(snapshot.binding.payout_script)) return Bad("tides-bootstrap-script");
        result.emplace_back(reserve_scripts ? 0 : reward, CScript{snapshot.binding.payout_script.begin(), snapshot.binding.payout_script.end()});
    } else {
        const Work counted = requested - remaining;
        for (const auto& [script, work] : weights) {
            const CAmount amount = (Work{reward} * work / counted).convert_to<CAmount>();
            if (reserve_scripts || amount > 0) result.emplace_back(reserve_scripts ? 0 : amount, CScript{script.begin(), script.end()});
        }
    }
    payouts = std::move(result);
    return Result::Valid(reward);
}

std::vector<CTxOut> CalculatePayouts(const Snapshot& snapshot, CAmount reward)
{
    if (snapshot.binding.version == TIDES_VERSION) throw std::invalid_argument("TIDES payouts require actual parent history and native target");
    if (!MoneyRange(reward) || snapshot.shares.size() > MAX_SNAPSHOT_BYTES / MIN_SHARE_BYTES) throw std::invalid_argument("payout byte or reward bound");
    // Exact integers: a 256-bit per-proof work value plus the byte-bounded
    // proof count and monetary multiplication can exceed uint256/uint64.
    using boost::multiprecision::cpp_int;
    std::map<std::vector<unsigned char>, cpp_int> weights;
    cpp_int total{0};
    const auto add_weight = [&](const std::vector<unsigned char>& script, uint32_t native_bits) {
        if (!IsPayoutScript(script)) throw std::invalid_argument("payout script shape");
        const auto target = ShareTarget(native_bits);
        cpp_int numeric{0};
        for (size_t i{target.size()}; i > 0; --i) { numeric <<= 8; numeric += target.begin()[i - 1]; }
        const cpp_int work = (cpp_int{1} << 256) / (numeric + 1);
        weights[script] += work;
        total += work;
    };
    if (snapshot.binding.version == LEDGER_VERSION) {
        CreditBounds(snapshot.settled, MAX_SETTLED_BYTES);
        for (const auto& credit : snapshot.settled) add_weight(credit.payout_script, credit.native_bits);
    } else {
        for (const auto& share : snapshot.shares) add_weight(share.origin.payout_script, share.header.nBits);
    }
    if (weights.empty()) {
        if (!IsPayoutScript(snapshot.binding.payout_script)) throw std::invalid_argument("empty snapshot owner payout script");
        weights[snapshot.binding.payout_script] = total = 1;
    }
    struct Allocation { std::vector<unsigned char> script; CAmount amount; cpp_int remainder; };
    std::vector<Allocation> allocations;
    CAmount allocated{0};
    for (const auto& [script, weight] : weights) {
        const cpp_int numerator = cpp_int{reward} * weight;
        const CAmount amount = (numerator / total).convert_to<CAmount>();
        allocations.push_back({script, amount, numerator % total});
        allocated += amount;
    }
    std::sort(allocations.begin(), allocations.end(), [](const auto& a, const auto& b) {
        return a.remainder != b.remainder ? a.remainder > b.remainder : a.script < b.script;
    });
    for (CAmount i{0}; i < reward - allocated; ++i) ++allocations.at(i).amount;
    std::sort(allocations.begin(), allocations.end(), [](const auto& a, const auto& b) { return a.script < b.script; });
    std::vector<CTxOut> result;
    for (const auto& value : allocations) result.emplace_back(value.amount, CScript{value.script.begin(), value.script.end()});
    return result;
}

Result CheckSnapshot(const CBlock& block, const CBlockIndex* previous, const Consensus::Params& consensus,
                     const Lookup& lookup, const ValidateOrigin& validate_origin,
                     std::optional<CAmount> expected_reward, uint32_t depth, bool allow_unsigned)
{
    try { return Checker{consensus, lookup, validate_origin}.Check(block, previous, expected_reward, depth, allow_unsigned); }
    catch (const std::ios_base::failure&) { return Bad("encoding"); }
    catch (const std::invalid_argument&) { return Bad("encoding"); }
    // Allocation failures and unrelated internal/local errors are not evidence
    // that a block is invalid. Let the caller handle them without failed-block
    // persistence, rather than converting all std::exception values to Invalid.
}

Result CheckMiningJob(const CBlock& block, const CBlockIndex* previous,
                      const Consensus::Params& consensus, const Lookup& lookup,
                      const ValidateOrigin& validate_origin,
                      std::optional<CAmount> expected_reward, bool allow_unsigned)
{
    try { return Checker{consensus, lookup, validate_origin}.MiningJob(block, previous, expected_reward, allow_unsigned); }
    catch (const std::ios_base::failure&) { return Bad("encoding"); }
    catch (const std::invalid_argument&) { return Bad("encoding"); }
}

Result CheckHistoricalTemplate(const CBlock& full_origin, const CBlockIndex* previous, uint32_t time,
                               const Consensus::Params& consensus, const Lookup& lookup,
                               const ValidateOrigin& validate_origin)
{
    if (!consensus.SharePoolHashOnly || !previous || consensus.SharePoolHeight == std::numeric_limits<int>::max() ||
        int64_t{previous->nHeight} + 1 < consensus.SharePoolHeight) return Bad("inactive");
    try {
        SizeComputer size;
        size << TX_WITH_WITNESS(full_origin);
        if (size.size() > MAX_TEMPLATE_BYTES) return Bad("template-encoding");
        std::vector<unsigned char> raw;
        raw.reserve(size.size());
        VectorWriter{raw, 0} << TX_WITH_WITNESS(full_origin);
        const auto canonical = ReadTemplate(raw);
        return Checker{consensus, lookup, validate_origin}.HistoricalTemplate(canonical, previous, time);
    } catch (const std::ios_base::failure&) { return Bad("template-encoding"); }
    catch (const std::invalid_argument&) { return Bad("template-encoding"); }
}

Result CheckShareProof(const Share& share, const CBlock& full_origin, const CBlockIndex* previous,
                       uint32_t time, const Consensus::Params& consensus, const Lookup& lookup,
                       const ValidateOrigin& validate_origin)
{
    if (!consensus.SharePoolHashOnly || !previous || consensus.SharePoolHeight == std::numeric_limits<int>::max() ||
        int64_t{previous->nHeight} + 1 < consensus.SharePoolHeight) return Bad("inactive");
    try {
        // Enforce the same canonical full-body byte bound as snapshot records.
        SizeComputer size;
        size << TX_WITH_WITNESS(full_origin);
        if (size.size() > MAX_TEMPLATE_BYTES) return Bad("template-encoding");
        std::vector<unsigned char> raw;
        raw.reserve(size.size());
        VectorWriter{raw, 0} << TX_WITH_WITNESS(full_origin);
        const auto canonical = ReadTemplate(raw);
        return Checker{consensus, lookup, validate_origin}.ShareProof(share, canonical, previous, time, 1);
    } catch (const std::ios_base::failure&) { return Bad("template-encoding"); }
    catch (const std::invalid_argument&) { return Bad("template-encoding"); }
}
} // namespace sharepool::hashonly
