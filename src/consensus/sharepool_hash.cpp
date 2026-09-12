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
}

size_t EncodedSize(const Snapshot& snapshot)
{
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
    return binding.version == VERSION && ReservedZero(binding) && IsPayoutScript(binding.payout_script);
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
    if (binding.version != VERSION) return Bad("version");
    if (!ReservedZero(binding)) return Bad("reserved-roots");
    if (binding.genesis != consensus.hashGenesisBlock || binding.rules != hashonly::RulesHash() ||
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
        static const uint256 EMPTY_HASH{SnapshotHash(Span<const unsigned char>{})};
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
            if (SnapshotHash(*result) != hash) return Result::Missing({hash});
        } catch (const std::exception&) { return Bad("snapshot-encoding"); }
        if (size > MAX_DEPENDENCY_BYTES - m_dependency_bytes) return Bad("dependency-bytes");
        m_dependency_bytes += size;
        m_snapshots.emplace(hash, result);
        return Result::Valid();
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

    Result ShareProof(const Share& share, const CBlock& origin, const CBlockIndex* previous,
                      uint32_t time, uint32_t depth, bool origin_checked = false)
    {
        const auto* parent = OriginParent(share.header, previous, time);
        if (!parent) return Bad("share-context");
        if (!SearchFieldsZero(origin) || NormalizedHeader(share.header) != NormalizedHeader(origin)) return Bad("share-template");
        const auto binding = CheckBinding(share.origin, m_consensus, share.header.m_height, parent->GetBlockHash());
        if (!binding.IsValid()) return binding;
        if (UintToArith256(share.header.GetHash()) > UintToArith256(ShareTarget(share.header.nBits))) return Bad("share-target");
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
        if (!PayoutsOrdered(snapshot->payouts)) return Bad("payout-order");
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
        if (height != m_consensus.SharePoolHeight) {
            if (!previous->pprev) return Bad("parent");
            std::shared_ptr<const Snapshot> parent;
            result = Fetch(previous->m_mm_rhs, parent);
            if (result.IsMissing()) collect_missing(result);
            else if (!result.IsValid()) return result;
            else {
                const auto context = CheckBinding(parent->binding, m_consensus, previous->nHeight, previous->pprev->GetBlockHash());
                if (!context.IsValid() || !Authorized(*parent) || !StateOrdered(parent->post_state)) return Bad("parent");
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
            if (share.origin.pool != snapshot->binding.pool) return Bad("share-pool");
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
        std::vector<CTxOut> payouts;
        for (const auto& output : block.vtx[0]->vout) {
            if (!IsPayoutScript(output.scriptPubKey)) break;
            payouts.push_back(output);
        }
        const auto& all_outputs = block.vtx[0]->vout;
        if (payouts.empty() || (payouts.size() != all_outputs.size() &&
            (payouts.size() + 1 != all_outputs.size() || !WitnessOutput(all_outputs.back())))) return Bad("coinbase-layout");
        if (payouts != snapshot->payouts) return Bad("payouts");
        CAmount total{0};
        for (const auto& output : payouts) {
            if (!MoneyRange(output.nValue) || output.nValue > MAX_MONEY - total) return Bad("payouts");
            total += output.nValue;
        }
        if (expected_reward && (!MoneyRange(*expected_reward) || total != *expected_reward)) return Bad("reward");
        if (payouts != hashonly::CalculatePayouts(*snapshot, total)) return Bad("payouts");
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
    if (!WireBinding(snapshot.binding)) throw std::ios_base::failure("invalid v4 binding");
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
    if (!PayoutsOrdered(snapshot.payouts)) throw std::ios_base::failure("payout order or shape");
    const auto canonical = EncodeSnapshot(snapshot);
    if (!reader.empty() || canonical.size() != bytes.size() ||
        !std::equal(canonical.begin(), canonical.end(), bytes.begin())) throw std::ios_base::failure("noncanonical snapshot");
    return snapshot;
}

uint256 SnapshotHash(Span<const unsigned char> bytes)
{
    if (bytes.size() > MAX_SNAPSHOT_BYTES) throw std::ios_base::failure("snapshot byte bound");
    static constexpr char domain[]{"SharePool/snapshot/v4"};
    HashWriter writer;
    writer.write(AsBytes(Span{domain}));
    writer.write(AsBytes(bytes));
    return writer.GetHash();
}

uint256 SnapshotHash(const Snapshot& snapshot)
{
    EncodedSize(snapshot);
    static constexpr char domain[]{"SharePool/snapshot/v4"};
    HashWriter writer;
    writer.write(AsBytes(Span{domain}));
    WriteSnapshot(writer, snapshot);
    return writer.GetHash();
}

uint256 RulesHash()
{
    return DomainHash("SharePool/rules/v4", SHARE_BITS, SHARE_TARGET_SHIFT, MAX_SHARE_AGE, MAX_SNAPSHOT_BYTES,
                      MAX_TEMPLATE_BYTES, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_BYTES,
                      MAX_EXPANDED_TEMPLATE_BYTES, MAX_TEMPLATE_TX_REFERENCES, MAX_ORIGIN_CHECKS);
}

uint256 SnapshotContentsHash(const Snapshot& snapshot)
{
    // Stream rather than copying a potentially 16 MiB snapshot.
    EncodedSize(snapshot);
    HashWriter writer;
    static constexpr char domain[]{"SharePool/contents/v4"};
    writer.write(AsBytes(Span{domain}));
    WriteSnapshot(writer, snapshot, true);
    return writer.GetHash();
}

uint256 OwnerHash(const Envelope& binding, const uint256& job, const uint256& contents)
{
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

uint256 ShareTarget(uint32_t native_bits)
{
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

std::vector<CTxOut> CalculatePayouts(const Snapshot& snapshot, CAmount reward)
{
    if (!MoneyRange(reward) || snapshot.shares.size() > MAX_SNAPSHOT_BYTES / MIN_SHARE_BYTES) throw std::invalid_argument("payout byte or reward bound");
    // Exact integers: a 256-bit per-proof work value plus the byte-bounded
    // proof count and monetary multiplication can exceed uint256/uint64.
    using boost::multiprecision::cpp_int;
    std::map<std::vector<unsigned char>, cpp_int> weights;
    cpp_int total{0};
    for (const auto& share : snapshot.shares) {
        if (!IsPayoutScript(share.origin.payout_script)) throw std::invalid_argument("payout script shape");
        const auto target = ShareTarget(share.header.nBits);
        cpp_int numeric{0};
        for (size_t i{target.size()}; i > 0; --i) { numeric <<= 8; numeric += target.begin()[i - 1]; }
        const cpp_int work = (cpp_int{1} << 256) / (numeric + 1);
        weights[share.origin.payout_script] += work;
        total += work;
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
    catch (const std::exception&) { return Bad("encoding"); }
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
        return Checker{consensus, lookup, validate_origin}.ShareProof(share, canonical, previous, time, 0);
    } catch (const std::exception&) { return Bad("template-encoding"); }
}
} // namespace sharepool::hashonly
