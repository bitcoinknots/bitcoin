// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sharepool/relay.h>

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <consensus/sharepool.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <limits>
#include <type_traits>

namespace sharepool {
namespace {
std::vector<unsigned char> NormalizedHeader(const CBlockHeader& source)
{
    CBlockHeader header{source};
    header.nNonce = header.m_nonce2 = header.m_nonce3 = header.m_time_offset = 0;
    header.m_extranonce.SetNull();
    DataStream encoded;
    encoded << header;
    return {UCharCast(encoded.data()), UCharCast(encoded.data()) + encoded.size()};
}

bool ProfileActive(ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    const auto& params = chainman.GetParams();
    const auto* tip = chainman.ActiveChain().Tip();
    return params.GetChainType() == ChainType::REGTEST && tip &&
           params.GetConsensus().SharePoolHeight != std::numeric_limits<int>::max() &&
           tip->nHeight + 1 >= params.GetConsensus().SharePoolHeight;
}

template <typename T>
bool Canonical(Span<const unsigned char> raw, const T& decoded)
{
    DataStream encoded;
    if constexpr (std::is_same_v<T, CBlock>) encoded << TX_WITH_WITNESS(decoded);
    else encoded << decoded;
    return encoded.size() == raw.size() && std::equal(raw.begin(), raw.end(), UCharCast(encoded.data()));
}
} // namespace

uint256 RelayDigest(Span<const unsigned char> bytes)
{
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256{}.Write(bytes.data(), bytes.size()).Finalize(digest);
    uint256 result;
    std::reverse_copy(std::begin(digest), std::end(digest), result.begin());
    return result;
}

uint256 RelayTemplateId(const CBlockHeader& header)
{
    return RelayDigest(NormalizedHeader(header));
}

bool RelayStore::Active(ChainstateManager& chainman) const
{
    AssertLockHeld(cs_main);
    return !m_pool.IsNull() && ProfileActive(chainman);
}

bool RelayStore::Room(uint8_t kind, size_t size) const
{
    AssertLockHeld(cs_main);
    const auto count = static_cast<size_t>(std::count_if(m_objects.begin(), m_objects.end(),
        [kind](const auto& entry) { return entry.first.kind == kind; }));
    return m_bytes + size <= MAX_RELAY_BYTES && count < MAX_RELAY_ITEMS / 2;
}

bool RelayStore::Configure(ChainstateManager& chainman, const uint256& pool, std::string& error)
{
    AssertLockHeld(cs_main);
    if (!ProfileActive(chainman) || pool.IsNull()) {
        error = "Evidence relay requires an active regtest SPN1 profile and nonzero pool";
        return false;
    }
    if (!m_pool.IsNull() && m_pool != pool) {
        error = "Evidence relay pool cannot change before restart";
        return false;
    }
    m_pool = pool;
    error.clear();
    return true;
}

void RelayStore::Prune(ChainstateManager& chainman)
{
    AssertLockHeld(cs_main);
    if (!Active(chainman)) {
        if (!m_objects.empty()) ++m_revision;
        m_objects.clear();
        m_bytes = 0;
        return;
    }
    const auto* tip = chainman.ActiveChain().Tip();
    const auto floor = std::max<int64_t>(chainman.GetParams().GetConsensus().SharePoolHeight,
                                       int64_t{tip->nHeight} + 1 - MAX_SHARE_AGE);
    for (auto it = m_objects.begin(); it != m_objects.end();) {
        const auto& object = *it->second;
        const auto* parent = object.origin_height > 0 && object.origin_height <= uint32_t(tip->nHeight + 1)
            ? tip->GetAncestor(object.origin_height - 1) : nullptr;
        if (object.origin_height < floor || !parent || parent->GetBlockHash() != object.origin_parent) {
            m_bytes -= object.data.size();
            it = m_objects.erase(it);
            ++m_revision;
        } else {
            ++it;
        }
    }
}

std::vector<RelayItem> RelayStore::Inventory(ChainstateManager& chainman)
{
    Prune(chainman);
    std::vector<RelayItem> result;
    result.reserve(m_objects.size());
    for (const auto& [item, object] : m_objects) result.push_back(item);
    return result;
}

bool RelayStore::Has(ChainstateManager& chainman, uint8_t kind, const uint256& id)
{
    Prune(chainman);
    return m_objects.contains(RelayItem{kind, id});
}

std::shared_ptr<const RelayObject> RelayStore::Get(ChainstateManager& chainman, uint8_t kind, const uint256& id)
{
    Prune(chainman);
    const auto found = m_objects.find(RelayItem{kind, id});
    return found == m_objects.end() ? nullptr : found->second;
}

std::optional<RelayItem> RelayStore::Add(ChainstateManager& chainman, uint8_t kind,
                                      Span<const unsigned char> raw, std::string& error,
                                      std::optional<RelayItem> expected)
{
    AssertLockHeld(cs_main);
    const auto fail = [&](const std::string& reason) -> std::optional<RelayItem> { error = reason; return std::nullopt; };
    if (!Active(chainman)) return fail("Evidence relay is disabled");
    if ((kind != RELAY_TEMPLATE && kind != RELAY_RECEIPT) || raw.empty() ||
        raw.size() > (kind == RELAY_TEMPLATE ? MAX_RELAY_TEMPLATE : MAX_RELAY_RECEIPT)) {
        return fail("Evidence kind or byte bound is invalid");
    }
    Prune(chainman);
    auto object = std::make_shared<RelayObject>();
    object->item.kind = kind;
    object->pool = m_pool;
    try {
        DataStream stream{raw};
        if (kind == RELAY_TEMPLATE) {
            CBlock block;
            stream >> TX_WITH_WITNESS(block);
            if (!stream.empty() || !Canonical(raw, block) || block.vtx.empty()) return fail("Noncanonical template");
            std::vector<CTxOut> payouts;
            const auto manifest = ParseCoinbaseManifest(*block.vtx[0], payouts);
            if (manifest.current.pool != m_pool) return fail("Template belongs to another pool");
            object->item.id = object->template_id = RelayTemplateId(block);
            if (expected && *expected != object->item) return fail("Template differs from requested identity");
            object->origin_height = manifest.current.height;
            object->origin_parent = block.hashPrevBlock;
            const auto found = m_objects.find(object->item);
            if (found != m_objects.end()) {
                // Search-field variants identify the same immutable template.
                // Never replace its validated body with another body under that ID.
                const auto& saved = found->second->data;
                if (raw.size() < 164 || saved.size() != raw.size() ||
                    !std::equal(raw.begin() + 164, raw.end(), saved.begin() + 164)) {
                    return fail("Conflicting template body for existing identity");
                }
                error.clear();
                return object->item;
            }
            if (!Room(kind, raw.size())) return fail("Evidence relay cache is full");
            auto* parent = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
            BlockValidationState state;
            if (!TestSharePoolTemplateOnAncestor(state, chainman.GetParams(), chainman.ActiveChainstate(), block, parent)) {
                return fail(state.ToString());
            }
        } else {
            Share share;
            stream >> share;
            if (!stream.empty() || !Canonical(raw, share)) return fail("Noncanonical receipt");
            if (share.origin.pool != m_pool) return fail("Receipt belongs to another pool");
            object->item.id = share.header.GetHash();
            if (expected && *expected != object->item) return fail("Receipt differs from requested identity");
            object->template_id = RelayTemplateId(share.header);
            object->origin_height = share.origin.height;
            object->origin_parent = share.origin.native_parent;
            const auto origin = Get(chainman, RELAY_TEMPLATE, object->template_id);
            if (!origin) return fail("Receipt has no locally validated full origin template");
            DataStream source{origin->data};
            CBlockHeader header;
            source >> header;
            if (NormalizedHeader(header) != NormalizedHeader(share.header)) return fail("Receipt origin mismatch");
            const auto* tip = chainman.ActiveChain().Tip();
            const auto time = std::max<int64_t>(tip->GetMedianTimePast() + 1, GetTime());
            if (time < 0 || time > std::numeric_limits<uint32_t>::max() ||
                !CheckShare(share, tip, static_cast<uint32_t>(time), chainman.GetParams().GetConsensus(), error)) {
                return fail(error.empty() ? "Receipt time outside native range" : error);
            }
            const auto found = m_objects.find(object->item);
            if (found != m_objects.end()) {
                if (found->second->data.size() != raw.size() ||
                    !std::equal(raw.begin(), raw.end(), found->second->data.begin())) return fail("Conflicting receipt identity");
                error.clear();
                return object->item;
            }
        }
    } catch (const std::exception&) {
        return fail("Malformed native evidence");
    }
    if (!Room(kind, raw.size())) return fail("Evidence relay cache is full");
    object->data.assign(raw.begin(), raw.end());
    object->body_hash = RelayDigest(raw);
    m_bytes += object->data.size();
    m_objects.emplace(object->item, object);
    ++m_revision;
    error.clear();
    return object->item;
}
} // namespace sharepool
