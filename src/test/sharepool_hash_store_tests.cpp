// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include <consensus/sharepool_hash.h>
#include <dbwrapper.h>
#include <hash.h>
#include <script/script.h>
#include <sharepool/hash_store.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <versionbits.h>

#include <algorithm>
#include <array>

#include <boost/test/unit_test.hpp>

namespace sharepool {
/** Fault injection into this fixture's open database, bypassing production
 * admission only to reproduce post-startup disk damage before a cache miss.
 */
struct HashSnapshotStoreTest {
    static void ClearSources(HashSnapshotStore& store) EXCLUSIVE_LOCKS_REQUIRED(cs_main) { store.m_template_sources.clear(); }
    static size_t CacheCount(const HashSnapshotStore& store) EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return store.m_cache.size(); }
    static void DamageMetadata(HashSnapshotStore& store, const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        BOOST_REQUIRE(store.m_db.Write(std::make_pair(uint8_t{'m'}, hash), std::vector<unsigned char>{0}, true));
    }
    static void DamageSnapshot(HashSnapshotStore& store, const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        BOOST_REQUIRE(store.m_db.Write(std::make_pair(uint8_t{'s'}, hash), std::vector<unsigned char>{0}, true));
    }
    static void DamageSources(HashSnapshotStore& store, const uint256& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        store.m_template_sources.clear();
        BOOST_REQUIRE(store.m_db.Write(std::make_pair(uint8_t{'i'}, id), std::vector<unsigned char>{0}, true));
    }
    static uint256 DamageFirstSource(HashSnapshotStore& store, const uint256& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        const auto hash = store.TemplateSources(id).front().first;
        BOOST_REQUIRE(store.m_db.Write(std::make_pair(uint8_t{'s'}, hash), std::vector<unsigned char>{0}, true));
        return hash;
    }
};
} // namespace sharepool

namespace {
namespace ho = sharepool::hashonly;

/** Exact local record format, used only to alter our own saved fixture records
 * after closing the store. Paths, keys and values all originate in this test.
 */
struct DiskTemplate {
    CBlockHeader header;
    std::vector<Wtxid> transactions;
    uint256 body_hash;
    SERIALIZE_METHODS(DiskTemplate, obj) { READWRITE(obj.header, obj.transactions, obj.body_hash); }
};

struct RawRecord {
    std::vector<std::byte> bytes;
    template <typename Stream> void Serialize(Stream& s) const { s.write(bytes); }
};

std::array<std::pair<uint256, std::vector<unsigned char>>, 2> ArchiveKeySides()
{
    // Canonical authenticated preimages on both sides of the malformed
    // mid-range key {prefix, 0x80}; ordering is by serialized hash bytes.
    std::array<std::pair<uint256, std::vector<unsigned char>>, 2> sides;
    for (uint32_t i{0}; i < 65536; ++i) {
        DataStream stream;
        stream << uint8_t{ho::TIDES_VERSION} << i;
        const std::vector<unsigned char> raw{UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
        const auto hash = ho::ProfileSnapshotHash(raw, ho::TIDES_VERSION);
        if (hash.begin()[0] < 0x80) sides[0] = {hash, raw};
        if (hash.begin()[0] > 0x80) sides[1] = {hash, raw};
        if (!sides[0].second.empty() && !sides[1].second.empty()) return sides;
    }
    throw std::logic_error("could not construct archive key fixture");
}

RawRecord MalformedArchiveKey(uint8_t prefix, unsigned shape, const uint256& before)
{
    DataStream stream;
    stream << prefix;
    // Include a short key before the canonical zero hash, a mid-range short
    // key, and a trailing-byte key whose decoded hash equals a valid record.
    if (shape == 1) stream << uint8_t{0x80};
    if (shape == 2) stream << before << uint8_t{0};
    return {{stream.begin(), stream.end()}};
}

std::vector<unsigned char> Bytes(const CTransaction& tx)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(tx);
    return {UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
}

std::vector<unsigned char> Bytes(const CBlock& block)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(block);
    return {UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
}

struct StoreFixture : BasicTestingSetup {
    CBlock block;
    ho::Snapshot source;
    StoreFixture()
    {
        const CScript payout = CScript{} << OP_0 << std::vector<unsigned char>(20, 0x61);
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript{} << int64_t{1} << OP_0;
        coinbase.vout.emplace_back(5000000000, payout);
        block.m_header_v2 = true;
        block.nVersion = VERSIONBITS_TOP_BITS;
        block.m_height = 1;
        block.hashPrevBlock = uint256{uint8_t{1}};
        block.m_mm_rhs = uint256{uint8_t{2}};
        block.nTime = 1700000001;
        block.nBits = sharepool::SHARE_BITS;
        block.m_txcount = 1;
        block.vtx = {MakeTransactionRef(std::move(coinbase))};
        block.hashMerkleRoot = BlockMerkleRoot(block);
        source.binding.version = ho::VERSION;
        source.binding.genesis = source.binding.native_parent = uint256{uint8_t{1}};
        source.binding.rules = ho::RulesHash();
        source.binding.pool = uint256{uint8_t{3}};
        source.binding.height = 1;
        source.binding.payout_script.assign(payout.begin(), payout.end());
        source.templates.push_back({ho::TemplateId(block), block});
        source.payouts = block.vtx[0]->vout;
    }

    size_t Save(const fs::path& path, bool snapshot = false, bool shared = false)
    {
        sharepool::HashSnapshotStore store{path};
        LOCK(cs_main);
        store.RememberTemplate(block);
        // Index the snapshot after the standalone record: that ordering must
        // not leave an empty standalone sentinel masking future fallback.
        if (snapshot) store.Put(ho::EncodeSnapshot(source));
        if (shared) {
            CBlock second{block};
            ++second.nTime;
            store.RememberTemplate(second);
        }
        return store.TemplateBytes();
    }

    enum class Damage { TEMPLATE_CHECKSUM, TEMPLATE_TRUNCATED, TEMPLATE_TRAILING,
                        TRANSACTION_IDENTITY, TRANSACTION_TRUNCATED, TRANSACTION_TRAILING,
                        TRANSACTION_MISSING };

    void Alter(const fs::path& path, Damage damage)
    {
        CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
        const auto template_key = std::make_pair(uint8_t{'t'}, ho::TemplateId(block));
        const auto transaction_key = std::make_pair(uint8_t{'u'}, block.vtx[0]->GetWitnessHash());
        if (damage == Damage::TEMPLATE_CHECKSUM || damage == Damage::TEMPLATE_TRAILING) {
            DiskTemplate record;
            BOOST_REQUIRE(db.Read(template_key, record));
            if (damage == Damage::TEMPLATE_CHECKSUM) {
                record.body_hash = uint256{uint8_t{99}};
                BOOST_REQUIRE(db.Write(template_key, record, true));
            } else {
                DataStream stream;
                stream << record << uint8_t{0};
                BOOST_REQUIRE(db.Write(template_key, RawRecord{{stream.begin(), stream.end()}}, true));
            }
        } else if (damage == Damage::TEMPLATE_TRUNCATED) {
            BOOST_REQUIRE(db.Write(template_key, RawRecord{{std::byte{0}}}, true));
        } else if (damage == Damage::TRANSACTION_MISSING) {
            BOOST_REQUIRE(db.Erase(transaction_key, true));
        } else if (damage == Damage::TRANSACTION_IDENTITY) {
            CMutableTransaction changed{*block.vtx[0]};
            --changed.vout[0].nValue;
            BOOST_REQUIRE(db.Write(transaction_key, Bytes(CTransaction{changed}), true));
        } else if (damage == Damage::TRANSACTION_TRUNCATED) {
            BOOST_REQUIRE(db.Write(transaction_key, std::vector<unsigned char>{0}, true));
        } else {
            DataStream stream;
            stream << Bytes(*block.vtx[0]) << uint8_t{0};
            BOOST_REQUIRE(db.Write(transaction_key, RawRecord{{stream.begin(), stream.end()}}, true));
        }
    }

    void CheckBlock(const std::shared_ptr<const CBlock>& restored, const CBlock& expected)
    {
        BOOST_REQUIRE(restored);
        BOOST_CHECK(ho::JobHash(*restored) == ho::JobHash(expected));
        BOOST_REQUIRE_EQUAL(restored->vtx.size(), expected.vtx.size());
        for (size_t i{0}; i < expected.vtx.size(); ++i) BOOST_CHECK(Bytes(*restored->vtx[i]) == Bytes(*expected.vtx[i]));
    }

    std::array<CBlock, 2> WitnessVariants()
    {
        // Storage fixtures with correctly constructed witness commitments.
        // Their hypothetical funding outpoint is not a native UTXO fixture.
        std::array<CBlock, 2> variants{block, block};
        for (size_t i{0}; i < variants.size(); ++i) {
            auto& candidate = variants[i];
            CMutableTransaction spend;
            spend.vin.resize(1);
            spend.vin[0].prevout = COutPoint{Txid::FromUint256(uint256{uint8_t{42}}), 0};
            spend.vin[0].scriptWitness.stack = {
                std::vector<unsigned char>(500, i == 0 ? 0x41 : 0x42), {OP_DROP, OP_TRUE}};
            spend.vout.emplace_back(1, CScript{} << OP_TRUE);
            candidate.vtx.push_back(MakeTransactionRef(std::move(spend)));
            candidate.m_txcount = candidate.vtx.size();
            CMutableTransaction coinbase{*candidate.vtx[0]};
            const std::vector<unsigned char> reserved(32);
            coinbase.vin[0].scriptWitness.stack = {reserved};
            auto witness_root = BlockWitnessMerkleRoot(candidate);
            CHash256().Write(witness_root).Write(reserved).Finalize(witness_root);
            std::vector<unsigned char> commitment{0xaa, 0x21, 0xa9, 0xed};
            commitment.insert(commitment.end(), witness_root.begin(), witness_root.end());
            coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << commitment);
            candidate.vtx[0] = MakeTransactionRef(std::move(coinbase));
            candidate.hashMerkleRoot = BlockMerkleRoot(candidate);
        }
        return variants;
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(sharepool_hash_store_tests, StoreFixture)

BOOST_AUTO_TEST_CASE(snapshot_dependencies_are_hints_and_pending_blocks_own_requirements)
{
    const auto path = m_path_root / "request-provenance";
    auto pending = std::make_shared<CBlock>(block);
    pending->m_mm_rhs = uint256{uint8_t{7}};
    const auto block_id = pending->GetHash();
    const auto child = uint256{uint8_t{8}};
    {
        sharepool::HashSnapshotStore store{path};
        LOCK(cs_main);
        // This unsigned structural snapshot is legitimate relay content, but
        // it does not authenticate any pending-block requirement.
        store.Put(ho::EncodeSnapshot(source));
        BOOST_CHECK(store.Needed().empty());
        BOOST_CHECK(store.Speculative() == std::vector<uint256>({block.m_mm_rhs}));
        store.NeedForBlock(block_id, {child});
        BOOST_CHECK(store.Needed().empty());
        BOOST_CHECK(!store.HasPendingBlock(block_id));
        BOOST_REQUIRE(store.QueueBlock(pending));
        BOOST_CHECK(store.HasPendingBlock(block_id));
        BOOST_CHECK(!store.HasPendingBlock(child));
        store.NeedForBlock(block_id, {child});
        BOOST_CHECK(store.Needed() == std::vector<uint256>({pending->m_mm_rhs, child}));
    }
    {
        sharepool::HashSnapshotStore restored{path};
        LOCK(cs_main);
        // Restart reconstructs only durable pending roots. The worker will
        // rediscover their authenticated descendants, never unrelated hints.
        BOOST_CHECK(restored.Needed() == std::vector<uint256>({pending->m_mm_rhs}));
        BOOST_CHECK(restored.HasPendingBlock(block_id));
        BOOST_CHECK(restored.Speculative().empty());
        restored.NeedForBlock(block_id, {});
        BOOST_CHECK(restored.Needed() == std::vector<uint256>({pending->m_mm_rhs}));
        restored.RemoveBlock(block_id);
        BOOST_CHECK(!restored.HasPendingBlock(block_id));
        BOOST_CHECK(restored.Needed().empty());
        restored.NeedForBlock(block_id, {child});
        BOOST_CHECK(restored.Needed().empty());
    }
}

BOOST_AUTO_TEST_CASE(damaged_snapshot_records_are_quarantined_repaired_and_reopened)
{
    const auto original = ho::EncodeSnapshot(source);
    const auto hash = ho::SnapshotHash(original);
    for (size_t damage{0}; damage < 4; ++damage) {
        const auto path = m_path_root / fs::PathFromString("snapshot-record-repair-" + std::to_string(damage));
        auto pending = std::make_shared<CBlock>(block);
        pending->m_mm_rhs = hash;
        {
            sharepool::HashSnapshotStore store{path};
            LOCK(cs_main);
            BOOST_CHECK(store.Put(original) == hash);
            BOOST_REQUIRE(store.QueueBlock(pending));
        }
        size_t damaged_bytes{0};
        {
            CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
            const auto key = std::make_pair(uint8_t{'s'}, hash);
            DataStream stream;
            if (damage == 0) {
                auto changed = source;
                ++changed.binding.height;
                stream << ho::EncodeSnapshot(changed); // Decodable, wrong content identity.
            } else if (damage == 1) {
                stream << original << uint8_t{0}; // Valid preimage, damaged local wrapper.
            } else if (damage == 2) {
                stream << std::vector<unsigned char>{0}; // Malformed snapshot at another hash's key.
            } else {
                stream << uint8_t{253}; // Truncated CompactSize local vector wrapper.
            }
            damaged_bytes = stream.size();
            BOOST_REQUIRE(db.Write(key, RawRecord{{stream.begin(), stream.end()}}, true));
        }
        {
            sharepool::HashSnapshotStore restored{path};
            LOCK(cs_main);
            BOOST_CHECK(restored.GetStartupStats().fast_path);
            BOOST_CHECK_EQUAL(restored.GetStartupStats().records_scanned, 0);
            // Ready checkpoints avoid reading historical payloads at startup.
            // The first actual retrieval authenticates and quarantines damage.
            BOOST_CHECK(!restored.Get(hash));
            BOOST_CHECK_EQUAL(restored.Count(), 0);
            BOOST_CHECK_EQUAL(restored.Bytes(), damaged_bytes);
            BOOST_CHECK(!restored.Has(hash));
            BOOST_CHECK(!restored.Get(hash));
            BOOST_CHECK(!restored.Lookup(hash));
            BOOST_CHECK(restored.Inventory().empty());
            BOOST_CHECK(restored.Needed() == std::vector<uint256>{hash});
            BOOST_CHECK(restored.MatchesPendingBlock(*pending));
            BOOST_CHECK(restored.Put(original, hash) == hash);
            BOOST_CHECK_EQUAL(restored.Count(), 1);
            BOOST_CHECK_EQUAL(restored.Bytes(), original.size());
            BOOST_REQUIRE(restored.Get(hash));
            BOOST_CHECK(*restored.Get(hash) == original);
            BOOST_CHECK(restored.Needed().empty());
            CheckBlock(restored.Template(ho::TemplateId(block)), block);
        }
        {
            sharepool::HashSnapshotStore reopened{path};
            LOCK(cs_main);
            BOOST_CHECK_EQUAL(reopened.Count(), 1);
            BOOST_CHECK_EQUAL(reopened.Bytes(), original.size());
            BOOST_CHECK(reopened.Has(hash));
            BOOST_CHECK(reopened.Needed().empty());
            CheckBlock(reopened.Template(ho::TemplateId(block)), block);
        }
    }
}

BOOST_AUTO_TEST_CASE(hash_correct_malformed_snapshot_preimage_remains_consensus_evidence)
{
    const auto path = m_path_root / "malformed-committed-preimage";
    const std::vector<unsigned char> malformed{0};
    const auto hash = ho::SnapshotHash(malformed);
    {
        sharepool::HashSnapshotStore store{path};
        LOCK(cs_main);
        BOOST_CHECK(store.Put(malformed, hash) == hash);
        BOOST_CHECK_THROW(store.Lookup(hash), ho::MalformedSnapshot);
    }
    {
        sharepool::HashSnapshotStore reopened{path};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(reopened.Count(), 1);
        BOOST_CHECK_EQUAL(reopened.Bytes(), malformed.size());
        BOOST_CHECK(reopened.Has(hash));
        BOOST_CHECK(reopened.Inventory() == std::vector<uint256>{hash});
        BOOST_REQUIRE(reopened.Get(hash));
        BOOST_CHECK(*reopened.Get(hash) == malformed);
        BOOST_CHECK_THROW(reopened.Lookup(hash), ho::MalformedSnapshot);
    }
}

BOOST_AUTO_TEST_CASE(selected_profile_preserves_legacy_malformed_hashes_and_isolates_v6_storage)
{
    // Golden hashes use the original v4/v5 byte-selection rule, including
    // malformed inputs advertising a future or unknown version. Extending
    // raw-byte autodetection would silently change old consensus evidence.
    const std::array<std::pair<unsigned char, const char*>, 5> malformed{{
        {0, "b595ce5d265eac73f0e0ab5cfb84b966cc9e8b9fee1c5184a31b2efd98725dc2"},
        {4, "5a0ff066f50423fd670ebd719c5b58e31eb2822c3ba7398ff4d14ab4896e0f8c"},
        {5, "4f0f02b741c37771f10d38ccf2070cf35212dee95c840b291daa27dee5d8b745"},
        {6, "07d92947d649986828d63bb73c6e0c9c2626f6e9b3f618818e35b4ec2a8cf9c9"},
        {7, "f45032411af95fd472cc48fcc5c6cdb28daf055d0a1ddfddd63a29d6f9613cb1"},
    }};
    for (const uint32_t profile : {4U, 5U, 6U}) {
        const auto path = m_path_root / fs::PathFromString("profile-evidence-v" + std::to_string(profile));
        {
            sharepool::HashSnapshotStore store{path, false, profile};
            LOCK(cs_main);
            for (const auto& [byte, golden] : malformed) {
                const std::vector<unsigned char> raw{byte};
                const auto legacy_hash = ho::SnapshotHash(raw);
                BOOST_CHECK_EQUAL(legacy_hash.GetHex(), golden);
                const auto selected_hash = ho::ProfileSnapshotHash(raw, profile);
                const auto other_hash = ho::ProfileSnapshotHash(raw, profile == 6 ? 4 : 6);
                BOOST_CHECK(selected_hash != other_hash);
                BOOST_CHECK((selected_hash == legacy_hash) == (profile != 6));
                BOOST_CHECK_THROW(store.Put(raw, other_hash), std::runtime_error);
                BOOST_CHECK(!store.Has(other_hash));
                BOOST_CHECK(store.Put(raw, selected_hash) == selected_hash);
                BOOST_CHECK(store.Has(selected_hash));
                BOOST_CHECK_THROW(store.Lookup(selected_hash), ho::MalformedSnapshot);
            }
            BOOST_CHECK_EQUAL(store.Count(), malformed.size());
            BOOST_CHECK_EQUAL(store.Bytes(), malformed.size());
        }
        {
            sharepool::HashSnapshotStore reopened{path, false, profile};
            LOCK(cs_main);
            BOOST_CHECK_EQUAL(reopened.Count(), malformed.size());
            BOOST_CHECK_EQUAL(reopened.Bytes(), malformed.size());
            for (const auto& [byte, golden] : malformed) {
                const std::vector<unsigned char> raw{byte};
                const auto selected_hash = ho::ProfileSnapshotHash(raw, profile);
                const auto other_hash = ho::ProfileSnapshotHash(raw, profile == 6 ? 4 : 6);
                BOOST_CHECK(reopened.Has(selected_hash));
                BOOST_CHECK(!reopened.Has(other_hash));
                BOOST_REQUIRE(reopened.Get(selected_hash));
                BOOST_CHECK(*reopened.Get(selected_hash) == raw);
                BOOST_CHECK_THROW(reopened.Lookup(selected_hash), ho::MalformedSnapshot);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(v6_store_retains_wrong_version_preimage_for_profile_validation)
{
    const auto path = m_path_root / "v6-wrong-version-preimage";
    const auto raw = ho::EncodeSnapshot(source);
    const auto legacy_hash = ho::SnapshotHash(raw);
    const auto hash = ho::ProfileSnapshotHash(raw, 6);
    BOOST_CHECK(hash != legacy_hash);
    {
        sharepool::HashSnapshotStore store{path, false, 6};
        LOCK(cs_main);
        BOOST_CHECK(store.Put(raw, hash) == hash);
        BOOST_CHECK(!store.Has(legacy_hash));
    }
    {
        sharepool::HashSnapshotStore reopened{path, false, 6};
        LOCK(cs_main);
        const auto decoded = reopened.Lookup(hash);
        BOOST_REQUIRE(decoded);
        BOOST_CHECK_EQUAL(decoded->binding.version, 4);
        // The selected profile authenticates these bytes before its validator
        // rejects their version. They must never masquerade as unavailable.
        BOOST_CHECK(ho::ProfileSnapshotHash(*decoded, 6) == hash);
        BOOST_CHECK(ho::ProfileSnapshotHash(*decoded, 4) == legacy_hash);
        BOOST_CHECK(ho::ProfileSnapshotHash(*decoded, 5) == legacy_hash);
        BOOST_REQUIRE(reopened.Get(hash));
        BOOST_CHECK(*reopened.Get(hash) == raw);
    }
    BOOST_CHECK_THROW((sharepool::HashSnapshotStore{m_path_root / "unknown-profile", false, 99}), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(damaged_pending_records_do_not_suppress_downloads_and_accept_exact_repair)
{
    const auto hash = block.GetHash();
    for (size_t damage{0}; damage < 7; ++damage) {
        const auto path = m_path_root / fs::PathFromString("pending-record-repair-" + std::to_string(damage));
        {
            sharepool::HashSnapshotStore store{path};
            LOCK(cs_main);
            BOOST_REQUIRE(store.QueueBlock(std::make_shared<CBlock>(block)));
        }
        {
            CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
            const auto key = std::make_pair(uint8_t{'b'}, hash);
            DataStream stream;
            if (damage == 0) {
                CBlock changed{block};
                ++changed.nTime;
                stream << Bytes(changed); // Valid body at a different header key.
            } else if (damage == 1) {
                stream << Bytes(block) << uint8_t{0}; // Trailing local wrapper bytes.
            } else if (damage == 2) {
                stream << std::vector<unsigned char>{0}; // Malformed inner block.
            } else if (damage == 3) {
                auto trailing = Bytes(block);
                trailing.push_back(0);
                stream << trailing; // Trailing bytes inside the block encoding.
            } else if (damage == 4) {
                stream << uint8_t{253}; // Malformed local vector wrapper.
            } else {
                CBlock changed{block};
                CMutableTransaction coinbase{*changed.vtx[0]};
                if (damage == 5) --coinbase.vout[0].nValue; // Same header, changed txid/Merkle root.
                else coinbase.vin[0].scriptWitness.stack = {{1}}; // Same header and txid, invalid witness.
                changed.vtx[0] = MakeTransactionRef(std::move(coinbase));
                BOOST_CHECK(changed.GetHash() == hash);
                stream << Bytes(changed);
            }
            BOOST_REQUIRE(db.Write(key, RawRecord{{stream.begin(), stream.end()}}, true));
        }
        {
            sharepool::HashSnapshotStore restored{path};
            LOCK(cs_main);
            BOOST_CHECK(!restored.HasPendingBlock(hash));
            BOOST_CHECK(!restored.MatchesPendingBlock(block));
            BOOST_CHECK(restored.PendingBlocks().empty());
            BOOST_CHECK(restored.Needed().empty());
            BOOST_REQUIRE(restored.QueueBlock(std::make_shared<CBlock>(block)));
            BOOST_CHECK(restored.HasPendingBlock(hash));
            BOOST_CHECK(restored.MatchesPendingBlock(block));
            BOOST_CHECK(restored.Needed() == std::vector<uint256>{block.m_mm_rhs});
        }
        {
            sharepool::HashSnapshotStore reopened{path};
            LOCK(cs_main);
            BOOST_CHECK(reopened.HasPendingBlock(hash));
            BOOST_CHECK(reopened.MatchesPendingBlock(block));
            BOOST_CHECK(reopened.Needed() == std::vector<uint256>{block.m_mm_rhs});
            reopened.RemoveBlock(hash);
            BOOST_CHECK(!reopened.HasPendingBlock(hash));
            BOOST_CHECK(reopened.Needed().empty());
        }
    }
}

BOOST_AUTO_TEST_CASE(quarantined_pending_records_keep_count_quota_until_repaired_or_removed)
{
    const auto path = m_path_root / "pending-quarantine-quota";
    std::vector<CBlock> blocks;
    for (size_t i{0}; i < sharepool::HashRequestQueue<uint256>::MAX_BLOCKS + 1; ++i) {
        blocks.push_back(block);
        blocks.back().nTime += i;
    }
    {
        sharepool::HashSnapshotStore store{path};
        LOCK(cs_main);
        for (size_t i{0}; i + 1 < blocks.size(); ++i) {
            BOOST_REQUIRE(store.QueueBlock(std::make_shared<CBlock>(blocks[i])));
        }
        BOOST_CHECK(!store.QueueBlock(std::make_shared<CBlock>(blocks.back())));
    }
    {
        CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
        for (size_t i{0}; i + 1 < blocks.size(); ++i) {
            BOOST_REQUIRE(db.Write(std::make_pair(uint8_t{'b'}, blocks[i].GetHash()), std::vector<unsigned char>{0}, true));
        }
    }
    {
        sharepool::HashSnapshotStore restored{path};
        LOCK(cs_main);
        BOOST_CHECK(restored.PendingBlocks().empty());
        BOOST_CHECK(!restored.QueueBlock(std::make_shared<CBlock>(blocks.back())));
        BOOST_REQUIRE(restored.QueueBlock(std::make_shared<CBlock>(blocks.front())));
        BOOST_CHECK(restored.MatchesPendingBlock(blocks.front()));
        BOOST_CHECK(!restored.QueueBlock(std::make_shared<CBlock>(blocks.back())));
        restored.RemoveBlock(blocks[1].GetHash());
        BOOST_REQUIRE(restored.QueueBlock(std::make_shared<CBlock>(blocks.back())));
    }
    {
        sharepool::HashSnapshotStore reopened{path};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(reopened.PendingBlocks().size(), 2);
        BOOST_CHECK(reopened.MatchesPendingBlock(blocks.front()));
        BOOST_CHECK(reopened.MatchesPendingBlock(blocks.back()));
    }
}

BOOST_AUTO_TEST_CASE(pending_body_matching_includes_witness_bytes)
{
    const auto variants = WitnessVariants();
    CBlock altered{variants[0]};
    altered.vtx[1] = variants[1].vtx[1];
    BOOST_CHECK(altered.GetHash() == variants[0].GetHash());
    BOOST_CHECK(altered.hashMerkleRoot == BlockMerkleRoot(altered));
    BOOST_CHECK(Bytes(altered) != Bytes(variants[0]));
    sharepool::HashSnapshotStore store{m_path_root / "pending-exact-body"};
    LOCK(cs_main);
    BOOST_CHECK(!store.MatchesPendingBlock(variants[0]));
    BOOST_REQUIRE(store.QueueBlock(std::make_shared<CBlock>(variants[0])));
    BOOST_CHECK(store.MatchesPendingBlock(variants[0]));
    BOOST_CHECK(store.HasPendingBlock(altered.GetHash()));
    BOOST_CHECK(!store.MatchesPendingBlock(altered));
    store.RemoveBlock(variants[0].GetHash());
    BOOST_CHECK(!store.MatchesPendingBlock(variants[0]));
}

BOOST_AUTO_TEST_CASE(alternative_snapshot_sources_survive_a_damaged_source_and_exact_repair)
{
    const auto path = m_path_root / "alternative-snapshot-sources";
    std::vector<std::vector<unsigned char>> snapshots;
    for (uint8_t i{0}; i < 6; ++i) {
        auto alternative = source;
        alternative.binding.pool = uint256{static_cast<uint8_t>(10 + i)};
        snapshots.push_back(ho::EncodeSnapshot(alternative));
    }
    std::sort(snapshots.begin(), snapshots.end(), [](const auto& a, const auto& b) {
        return ho::SnapshotHash(a) < ho::SnapshotHash(b);
    });
    {
        sharepool::HashSnapshotStore store{path};
        LOCK(cs_main);
        for (const auto& snapshot : snapshots) store.Put(snapshot);
        CheckBlock(store.Template(ho::TemplateId(block)), block);
    }
    {
        CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
        for (size_t i{0}; i < 5; ++i) {
            BOOST_REQUIRE(db.Write(std::make_pair(uint8_t{'s'}, ho::SnapshotHash(snapshots[i])),
                std::vector<unsigned char>{0}, true));
        }
    }
    {
        sharepool::HashSnapshotStore restored{path};
        LOCK(cs_main);
        BOOST_CHECK(restored.GetStartupStats().fast_path);
        // The bounded index retains the newest durable source. Discover disk
        // corruption lazily; a checkpoint never authenticates payload bytes.
        CheckBlock(restored.Template(ho::TemplateId(block)), block);
        for (size_t i{0}; i < 5; ++i) BOOST_CHECK(!restored.Get(ho::SnapshotHash(snapshots[i])));
        BOOST_CHECK_EQUAL(restored.Count(), 1);
        CheckBlock(restored.Template(ho::TemplateId(block)), block);
        for (const auto& snapshot : snapshots) restored.Put(snapshot);
        BOOST_CHECK_EQUAL(restored.Count(), snapshots.size());
        CheckBlock(restored.Template(ho::TemplateId(block)), block);
    }
    {
        sharepool::HashSnapshotStore reopened{path};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(reopened.Count(), snapshots.size());
        CheckBlock(reopened.Template(ho::TemplateId(block)), block);
    }
}

BOOST_AUTO_TEST_CASE(template_lookup_tries_another_verified_source_after_runtime_disk_damage)
{
    const auto path = m_path_root / "runtime-snapshot-source-fallback";
    const auto first = ho::EncodeSnapshot(source);
    auto second_source = source;
    ++second_source.binding.height;
    const auto second = ho::EncodeSnapshot(second_source);
    {
        sharepool::HashSnapshotStore store{path};
        LOCK(cs_main);
        store.Put(first);
        store.Put(second);
    }
    {
        sharepool::HashSnapshotStore restored{path};
        LOCK(cs_main);
        const auto damaged = sharepool::HashSnapshotStoreTest::DamageFirstSource(restored, ho::TemplateId(block));
        BOOST_CHECK(restored.Has(damaged)); // Integrity is checked at the next uncached read.
        CheckBlock(restored.Template(ho::TemplateId(block)), block);
        BOOST_CHECK(!restored.Has(damaged));
        BOOST_CHECK_EQUAL(restored.Count(), 1);
        const auto& sound = damaged == ho::SnapshotHash(first) ? second : first;
        BOOST_CHECK_EQUAL(restored.Bytes(), sound.size() + GetSerializeSize(std::vector<unsigned char>{0}));
        restored.Put(first);
        restored.Put(second);
        BOOST_CHECK_EQUAL(restored.Count(), 2);
        BOOST_CHECK_EQUAL(restored.Bytes(), first.size() + second.size());
        CheckBlock(restored.Template(ho::TemplateId(block)), block);
    }
    {
        sharepool::HashSnapshotStore reopened{path};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(reopened.Count(), 2);
        CheckBlock(reopened.Template(ho::TemplateId(block)), block);
    }
}

BOOST_AUTO_TEST_CASE(quarantine_and_validated_reoffer_repair_exact_local_records)
{
    const std::array damages{Damage::TEMPLATE_CHECKSUM, Damage::TEMPLATE_TRUNCATED,
        Damage::TEMPLATE_TRAILING, Damage::TRANSACTION_IDENTITY, Damage::TRANSACTION_TRUNCATED,
        Damage::TRANSACTION_TRAILING, Damage::TRANSACTION_MISSING};
    for (size_t i{0}; i < damages.size(); ++i) {
        const auto path = m_path_root / fs::PathFromString("local-repair-" + std::to_string(i));
        const auto original_bytes = Save(path);
        Alter(path, damages[i]);
        {
            sharepool::HashSnapshotStore restored{path};
            LOCK(cs_main);
            BOOST_CHECK_EQUAL(restored.TemplateCount(), 0);
            BOOST_CHECK_GT(restored.TemplateBytes(), 0);
            BOOST_CHECK(!restored.Template(ho::TemplateId(block)));
            // Content corruption remains a local availability failure. A
            // validated reoffer atomically repairs the retained key identities.
            restored.RememberTemplate(block);
            CheckBlock(restored.Template(ho::TemplateId(block)), block);
            BOOST_CHECK_EQUAL(restored.TemplateCount(), 1);
            BOOST_CHECK_EQUAL(restored.TemplateBytes(), original_bytes);
            restored.RememberTemplate(block);
            BOOST_CHECK_EQUAL(restored.TemplateBytes(), original_bytes);
        }
        {
            sharepool::HashSnapshotStore reopened{path};
            LOCK(cs_main);
            CheckBlock(reopened.Template(ho::TemplateId(block)), block);
            BOOST_CHECK_EQUAL(reopened.TemplateCount(), 1);
            BOOST_CHECK_EQUAL(reopened.TemplateBytes(), original_bytes);
        }
    }
}

BOOST_AUTO_TEST_CASE(damaged_standalone_record_does_not_mask_authenticated_snapshot_source)
{
    for (const auto damage : {Damage::TEMPLATE_CHECKSUM, Damage::TRANSACTION_IDENTITY}) {
        const auto path = m_path_root / fs::PathFromString("snapshot-fallback-" + std::to_string(static_cast<int>(damage)));
        const auto original_bytes = Save(path, true);
        Alter(path, damage);
        sharepool::HashSnapshotStore restored{path};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(restored.TemplateCount(), 0);
        CheckBlock(restored.Template(ho::TemplateId(block)), block);
        // Fallback is a verified read, not implicit rewriting or an ACK.
        BOOST_CHECK_EQUAL(restored.TemplateCount(), 0);
        BOOST_CHECK_GE(restored.TemplateBytes(), original_bytes);
        restored.RememberTemplate(block);
        BOOST_CHECK_EQUAL(restored.TemplateCount(), 1);
        BOOST_CHECK_EQUAL(restored.TemplateBytes(), original_bytes);
    }
}

BOOST_AUTO_TEST_CASE(repaired_deduplicated_transaction_reactivates_other_sound_references)
{
    const auto path = m_path_root / "shared-transaction-repair";
    const auto original_bytes = Save(path, false, true);
    Alter(path, Damage::TRANSACTION_IDENTITY);
    sharepool::HashSnapshotStore restored{path};
    LOCK(cs_main);
    BOOST_CHECK_EQUAL(restored.TemplateCount(), 0);
    restored.RememberTemplate(block);
    CBlock second{block};
    ++second.nTime;
    CheckBlock(restored.Template(ho::TemplateId(second)), second);
    CheckBlock(restored.Template(ho::TemplateId(block)), block);
    BOOST_CHECK_EQUAL(restored.TemplateCount(), 2);
    BOOST_CHECK_EQUAL(restored.TemplateBytes(), original_bytes);
}

BOOST_AUTO_TEST_CASE(same_txid_witness_variants_remain_distinct_in_deduplicated_storage_after_restart)
{
    const auto variants = WitnessVariants();
    BOOST_CHECK(variants[0].vtx[1]->GetHash() == variants[1].vtx[1]->GetHash());
    BOOST_CHECK(variants[0].vtx[1]->GetWitnessHash() != variants[1].vtx[1]->GetWitnessHash());
    BOOST_CHECK_EQUAL(Bytes(*variants[0].vtx[1]).size(), Bytes(*variants[1].vtx[1]).size());
    std::array<CBlock, 4> jobs{variants[0], variants[0], variants[1], variants[1]};
    ++jobs[1].nTime;
    ++jobs[3].nTime;
    const auto path = m_path_root / "same-txid-witness-variants";
    size_t stored_bytes{0};
    size_t expanded_bytes{0};
    for (const auto& job : jobs) expanded_bytes += GetSerializeSize(TX_WITH_WITNESS(job));
    {
        sharepool::HashSnapshotStore store{path};
        LOCK(cs_main);
        for (const auto& job : jobs) store.RememberTemplate(job);
        stored_bytes = store.TemplateBytes();
        BOOST_CHECK_EQUAL(store.TemplateCount(), jobs.size());
        BOOST_CHECK_LT(stored_bytes, expanded_bytes);
        for (const auto& job : jobs) store.RememberTemplate(job);
        BOOST_CHECK_EQUAL(store.TemplateBytes(), stored_bytes);
    }
    {
        sharepool::HashSnapshotStore reopened{path};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(reopened.TemplateCount(), jobs.size());
        BOOST_CHECK_EQUAL(reopened.TemplateBytes(), stored_bytes);
        std::array<std::shared_ptr<const CBlock>, 4> restored;
        for (size_t i{0}; i < jobs.size(); ++i) {
            restored[i] = reopened.Template(ho::TemplateId(jobs[i]));
            CheckBlock(restored[i], jobs[i]);
            BOOST_CHECK(restored[i]->vtx[1]->vin[0].scriptWitness.stack == jobs[i].vtx[1]->vin[0].scriptWitness.stack);
        }
        BOOST_CHECK(restored[0]->vtx[1] == restored[1]->vtx[1]);
        BOOST_CHECK(restored[2]->vtx[1] == restored[3]->vtx[1]);
        BOOST_CHECK(restored[0]->vtx[1] != restored[2]->vtx[1]);
    }
}

BOOST_AUTO_TEST_CASE(wrong_witness_under_same_txid_is_quarantined_and_repaired_without_cross_contamination)
{
    const auto variants = WitnessVariants();
    const auto path = m_path_root / "same-txid-witness-repair";
    CBlock shared{variants[0]};
    ++shared.nTime;
    size_t original_bytes{0};
    {
        sharepool::HashSnapshotStore store{path};
        LOCK(cs_main);
        store.RememberTemplate(variants[0]);
        store.RememberTemplate(variants[1]);
        store.RememberTemplate(shared);
        original_bytes = store.TemplateBytes();
    }
    {
        // Same txid, same serialized size, canonical transaction encoding:
        // neither txid-only indexing nor size checks can detect this damage.
        BOOST_CHECK(variants[0].vtx[1]->GetHash() == variants[1].vtx[1]->GetHash());
        BOOST_CHECK(variants[0].vtx[1]->GetWitnessHash() != variants[1].vtx[1]->GetWitnessHash());
        BOOST_CHECK_EQUAL(Bytes(*variants[0].vtx[1]).size(), Bytes(*variants[1].vtx[1]).size());
        CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
        const auto key = std::make_pair(uint8_t{'u'}, variants[0].vtx[1]->GetWitnessHash());
        BOOST_REQUIRE(db.Write(key, Bytes(*variants[1].vtx[1]), true));
    }
    {
        sharepool::HashSnapshotStore reopened{path};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(reopened.TemplateCount(), 1);
        BOOST_CHECK(!reopened.Template(ho::TemplateId(variants[0])));
        BOOST_CHECK(!reopened.Template(ho::TemplateId(shared)));
        CheckBlock(reopened.Template(ho::TemplateId(variants[1])), variants[1]);
        reopened.RememberTemplate(variants[0]);
        BOOST_CHECK_EQUAL(reopened.TemplateCount(), 2);
        BOOST_CHECK_EQUAL(reopened.TemplateBytes(), original_bytes);
        CheckBlock(reopened.Template(ho::TemplateId(variants[0])), variants[0]);
        // Other quarantined references become available after an exact read
        // authenticates their repaired dependency and their own body hash.
        CheckBlock(reopened.Template(ho::TemplateId(shared)), shared);
        CheckBlock(reopened.Template(ho::TemplateId(variants[1])), variants[1]);
        BOOST_CHECK_EQUAL(reopened.TemplateCount(), 3);
    }
    {
        sharepool::HashSnapshotStore repaired{path};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(repaired.TemplateCount(), 3);
        BOOST_CHECK_EQUAL(repaired.TemplateBytes(), original_bytes);
        CheckBlock(repaired.Template(ho::TemplateId(variants[0])), variants[0]);
        CheckBlock(repaired.Template(ho::TemplateId(shared)), shared);
        CheckBlock(repaired.Template(ho::TemplateId(variants[1])), variants[1]);
    }
}

BOOST_AUTO_TEST_CASE(recent_inventory_bounds_live_events_and_reports_overrun)
{
    sharepool::HashSnapshotStore store{m_path_root / "recent-inventory", true, ho::TIDES_VERSION};
    LOCK(cs_main);
    const auto empty = store.RecentInventory();
    BOOST_CHECK(empty.entries.empty());
    BOOST_CHECK_EQUAL(empty.latest, 0U);
    BOOST_CHECK(!empty.epoch.IsNull());
    std::vector<unsigned char> first{6, 0, 0};
    const auto first_hash = store.Put(first);
    BOOST_CHECK_EQUAL(store.RecentSequence(), 1U);
    store.Put(first);
    BOOST_CHECK_EQUAL(store.RecentSequence(), 1U); // Sound duplicate does not churn the ring.
    for (size_t i{1}; i <= sharepool::HashSnapshotStore::MAX_RECENT_INVENTORY; ++i) {
        store.Put(std::vector<unsigned char>{6, static_cast<unsigned char>(i), static_cast<unsigned char>(i >> 8)});
    }
    const auto page = store.RecentInventory(0, 2);
    BOOST_CHECK(page.gap);
    BOOST_REQUIRE_EQUAL(page.entries.size(), 2U);
    BOOST_CHECK_EQUAL(page.entries.front().sequence, 2U);
    BOOST_CHECK_EQUAL(page.next, 3U);
    BOOST_CHECK_EQUAL(page.latest, sharepool::HashSnapshotStore::MAX_RECENT_INVENTORY + 1);
    BOOST_CHECK(page.epoch == empty.epoch);
    const auto resumed = store.RecentInventory(page.next, 2);
    BOOST_CHECK(!resumed.gap);
    BOOST_CHECK_EQUAL(resumed.entries.front().sequence, 4U);
    sharepool::HashSnapshotStoreTest::DamageSnapshot(store, first_hash);
    const auto previous = store.RecentSequence();
    store.Put(first); // Authenticated repair becomes newly available live work.
    BOOST_CHECK_EQUAL(store.RecentSequence(), previous + 1);
    const auto repaired = store.RecentInventory(previous, 1);
    BOOST_REQUIRE_EQUAL(repaired.entries.size(), 1U);
    BOOST_CHECK(repaired.entries.front().hash == first_hash);
    BOOST_CHECK_THROW(store.RecentInventory(0, 0), std::invalid_argument);
    BOOST_CHECK_THROW(store.RecentInventory(0, 1025), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(recent_inventory_restart_epoch_cannot_skip_new_low_sequences)
{
    const auto path = m_path_root / "recent-restart";
    uint256 epoch;
    {
        sharepool::HashSnapshotStore store{path, false, ho::TIDES_VERSION};
        LOCK(cs_main);
        store.Put(std::vector<unsigned char>{6, 1});
        epoch = store.RecentInventory().epoch;
        BOOST_CHECK_EQUAL(store.RecentSequence(), 1U);
    }
    sharepool::HashSnapshotStore store{path, false, ho::TIDES_VERSION};
    LOCK(cs_main);
    BOOST_CHECK_EQUAL(store.RecentSequence(), 0U);
    const auto restarted = store.RecentInventory(1);
    BOOST_CHECK(restarted.gap);
    BOOST_CHECK(restarted.epoch != epoch);
    BOOST_CHECK(restarted.entries.empty());
    store.Put(std::vector<unsigned char>{6, 2});
    store.Put(std::vector<unsigned char>{6, 3});
    const auto ambiguous_count = store.RecentInventory(1);
    BOOST_CHECK_EQUAL(ambiguous_count.latest, 2U);
    BOOST_CHECK(!ambiguous_count.gap); // Epoch, rather than sequence alone, detects this restart.
    BOOST_CHECK(ambiguous_count.epoch != epoch);
    BOOST_CHECK_EQUAL(store.RecentInventory(0).entries.size(), 2U);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(sharepool_archive_tests, StoreFixture)

BOOST_AUTO_TEST_CASE(malformed_archive_keys_never_complete_rebuild_or_discard_evidence)
{
    const auto sides = ArchiveKeySides();
    for (const uint8_t prefix : {uint8_t{'s'}, uint8_t{'m'}, uint8_t{'i'}}) {
        for (unsigned shape{0}; shape < 3; ++shape) {
            const auto path = m_path_root / fs::PathFromString("bad-archive-key-" + std::to_string(prefix) + "-" + std::to_string(shape));
            const auto malformed = MalformedArchiveKey(prefix, shape, sides[0].first);
            {
                sharepool::HashSnapshotStore store{path, false, ho::TIDES_VERSION};
                LOCK(cs_main);
                for (const auto& [hash, raw] : sides) store.Put(raw, hash);
            }
            {
                CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
                if (prefix == 'i') {
                    // Disposable source values need no interpretation during
                    // clearing, but their keys must still be exact.
                    for (const auto& [hash, raw] : sides) {
                        BOOST_REQUIRE(db.Write(std::make_pair(prefix, hash), std::vector<unsigned char>{0}));
                    }
                }
                BOOST_REQUIRE(db.Write(malformed, sides[0].second, true));
            }
            const auto malformed_error = [](const auto& error) {
                return std::string{error.what()}.find("malformed local archive key") != std::string::npos;
            };
            BOOST_CHECK_EXCEPTION((sharepool::HashSnapshotStore{path, false, ho::TIDES_VERSION, {.rebuild_index = true}}),
                                  std::runtime_error, malformed_error);
            // A faulty range end must not have committed a Ready checkpoint.
            // Ordinary startup resumes that phase and encounters the same key.
            BOOST_CHECK_EXCEPTION((sharepool::HashSnapshotStore{path, false, ho::TIDES_VERSION}),
                                  std::runtime_error, malformed_error);
            {
                CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
                BOOST_CHECK(db.Exists(malformed));
                for (const auto& [hash, raw] : sides) {
                    std::vector<unsigned char> retained;
                    BOOST_REQUIRE(db.Read(std::make_pair(uint8_t{'s'}, hash), retained));
                    BOOST_CHECK(retained == raw);
                }
                // Test-only removal of the exact injected key. Production
                // recovery refuses corruption rather than deleting evidence.
                BOOST_REQUIRE(db.Erase(malformed, true));
            }
            {
                sharepool::HashSnapshotStore resumed{path, false, ho::TIDES_VERSION};
                LOCK(cs_main);
                BOOST_CHECK(resumed.GetStartupStats().resumed_rebuild);
                BOOST_CHECK_EQUAL(resumed.Count(), 2);
                BOOST_CHECK_EQUAL(resumed.Bytes(), 10);
                BOOST_CHECK_EQUAL(resumed.ChargedBytes(), 266);
                BOOST_CHECK_EQUAL(resumed.Inventory().size(), 2);
                for (const auto& [hash, raw] : sides) BOOST_CHECK(resumed.Get(hash) == raw);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(malformed_inventory_keys_fail_instead_of_reporting_incomplete_success)
{
    const auto sides = ArchiveKeySides();
    for (unsigned shape{0}; shape < 3; ++shape) {
        const auto path = m_path_root / fs::PathFromString("bad-inventory-key-" + std::to_string(shape));
        {
            sharepool::HashSnapshotStore store{path, false, ho::TIDES_VERSION};
            LOCK(cs_main);
            for (const auto& [hash, raw] : sides) store.Put(raw, hash);
        }
        {
            CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
            BOOST_REQUIRE(db.Write(MalformedArchiveKey('m', shape, sides[0].first), sides[0].second, true));
        }
        sharepool::HashSnapshotStore store{path, false, ho::TIDES_VERSION};
        LOCK(cs_main);
        BOOST_CHECK(store.GetStartupStats().fast_path);
        BOOST_CHECK(!store.RepairRequired());
        BOOST_CHECK_EXCEPTION(store.InventoryPage(), std::runtime_error, [](const auto& error) {
            return std::string{error.what()}.find("malformed local archive key") != std::string::npos;
        });
        BOOST_CHECK(store.RepairRequired());
        if (shape) BOOST_CHECK_THROW(store.InventoryPage(sides[0].first, 1), std::runtime_error);
        for (const auto& [hash, raw] : sides) BOOST_CHECK(store.Get(hash) == raw);
    }
}

BOOST_AUTO_TEST_CASE(disk_index_exceeds_old_object_ceiling_with_bounded_inventory_and_cache)
{
    const auto path = m_path_root / "large-archive";
    constexpr uint32_t records{65540};
    {
        // Seed disk in one batch so this tests the store's complete restart
        // verification/indexing, rather than timing 65540 fsync syscalls.
        CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
        CDBBatch batch{db};
        for (uint32_t i{0}; i < records; ++i) {
            DataStream encoded;
            encoded << uint8_t{ho::TIDES_VERSION} << i;
            const std::vector<unsigned char> raw{UCharCast(encoded.data()), UCharCast(encoded.data()) + encoded.size()};
            batch.Write(std::make_pair(uint8_t{'s'}, ho::ProfileSnapshotHash(raw, ho::TIDES_VERSION)), raw);
        }
        BOOST_REQUIRE(db.WriteBatch(batch, true));
    }
    {
        sharepool::HashSnapshotStore store{path, false, ho::TIDES_VERSION};
        LOCK(cs_main);
        BOOST_CHECK(!store.GetStartupStats().fast_path);
        BOOST_CHECK_EQUAL(store.GetStartupStats().records_scanned, records);
        BOOST_CHECK_EQUAL(store.Count(), records);
        BOOST_CHECK_EQUAL(store.Bytes(), 5 * records);
        BOOST_CHECK_EQUAL(store.Inventory().size(), sharepool::HashSnapshotStore::MAX_INVENTORY_PAGE);
        std::optional<uint256> cursor;
        size_t total{0};
        bool complete{false};
        while (!complete) {
            const auto page = store.InventoryPage(cursor, 997);
            BOOST_CHECK_LE(page.hashes.size(), 997);
            for (const auto& hash : page.hashes) {
                if (cursor) BOOST_CHECK(*cursor < hash);
                BOOST_REQUIRE(store.GetShared(hash));
                ++total;
            }
            cursor = page.next;
            complete = page.complete;
        }
        BOOST_CHECK_EQUAL(total, records);
        BOOST_CHECK_LE(sharepool::HashSnapshotStoreTest::CacheCount(store), 4096);
        const std::vector<unsigned char> extra{ho::TIDES_VERSION, 255, 255, 255, 255};
        store.Put(extra);
        BOOST_CHECK_EQUAL(store.Count(), records + 1);
        BOOST_CHECK_THROW(store.InventoryPage(std::nullopt, 0), std::invalid_argument);
        BOOST_CHECK_THROW(store.InventoryPage(std::nullopt, 1025), std::invalid_argument);
    }
    {
        sharepool::HashSnapshotStore store{path, false, ho::TIDES_VERSION};
        LOCK(cs_main);
        BOOST_CHECK(store.GetStartupStats().fast_path);
        BOOST_CHECK_EQUAL(store.GetStartupStats().records_scanned, 0);
        BOOST_CHECK_EQUAL(store.GetStartupStats().bytes_scanned, 0);
        BOOST_CHECK_EQUAL(store.GetStartupStats().batches, 0);
        BOOST_CHECK_EQUAL(store.Count(), records + 1);
        BOOST_CHECK_EQUAL(store.Bytes(), 5 * (records + 1));
        BOOST_CHECK_EQUAL(sharepool::HashSnapshotStoreTest::CacheCount(store), 0);
    }
}

BOOST_AUTO_TEST_CASE(local_quota_is_finite_configurable_and_never_evicts_history)
{
    const auto path = m_path_root / "finite-quota";
    const std::vector<unsigned char> first{6, 1, 2, 3}, second{6, 4, 5, 6};
    uint256 first_hash;
    {
        sharepool::HashSnapshotStore store{path, false, ho::TIDES_VERSION, {.max_bytes = first.size() + 128}};
        LOCK(cs_main);
        first_hash = store.Put(first);
        BOOST_CHECK_THROW(store.Put(second), std::runtime_error);
        BOOST_CHECK_EQUAL(store.Count(), 1);
        BOOST_CHECK_EQUAL(store.ChargedBytes(), first.size() + 128);
        BOOST_CHECK(store.Get(first_hash) == first);
    }
    {
        sharepool::HashSnapshotStore raised{path, false, ho::TIDES_VERSION, {.max_bytes = first.size() + second.size() + 256}};
        LOCK(cs_main);
        BOOST_CHECK(raised.GetStartupStats().fast_path);
        BOOST_CHECK_EQUAL(raised.GetStartupStats().records_scanned, 0);
        raised.Put(second);
        BOOST_CHECK_EQUAL(raised.Count(), 2);
        BOOST_CHECK(raised.Get(first_hash) == first);
    }
    BOOST_CHECK_THROW((sharepool::HashSnapshotStore{path, false, ho::TIDES_VERSION, {.max_bytes = first.size() + 128}}), std::runtime_error);
    BOOST_CHECK_THROW((sharepool::HashSnapshotStore{m_path_root / "zero-quota", true, ho::TIDES_VERSION, {.max_bytes = 0}}), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(template_source_index_allowance_is_charged_before_durable_admission_and_recovers)
{
    const auto path = m_path_root / "source-index-quota";
    source.binding.version = ho::TIDES_VERSION;
    source.binding.rules = ho::RulesHash(ho::TIDES_VERSION);
    for (uint32_t i{1}; i < 32; ++i) {
        CBlock next{block};
        next.nTime += i;
        source.templates.push_back({ho::TemplateId(next), next});
    }
    std::sort(source.templates.begin(), source.templates.end(), [](const auto& a, const auto& b) { return a.id < b.id; });
    const auto raw = ho::EncodeSnapshot(source);
    const auto hash = ho::SnapshotHash(source);
    const uint64_t charge = raw.size() + 128 + 224 * source.templates.size();
    {
        sharepool::HashSnapshotStore too_small{path, false, ho::TIDES_VERSION, {.max_bytes = charge - 1}};
        LOCK(cs_main);
        BOOST_CHECK_THROW(too_small.Put(raw), std::runtime_error);
        BOOST_CHECK_EQUAL(too_small.Count(), 0);
        BOOST_CHECK_EQUAL(too_small.ChargedBytes(), 0);
        BOOST_CHECK(!too_small.Has(hash));
    }
    {
        sharepool::HashSnapshotStore store{path, false, ho::TIDES_VERSION, {.max_bytes = charge}};
        LOCK(cs_main);
        store.Put(raw);
        BOOST_CHECK_EQUAL(store.ChargedBytes(), charge);
        sharepool::HashSnapshotStoreTest::DamageSnapshot(store, hash);
        // A repair retains its charge exactly, including all source indexes.
        store.Put(raw, hash);
        BOOST_CHECK_EQUAL(store.ChargedBytes(), charge);
        for (const auto& item : source.templates) BOOST_REQUIRE(store.Template(item.id));
    }
    {
        sharepool::HashSnapshotStore reopened{path, false, ho::TIDES_VERSION, {.max_bytes = charge}};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(reopened.ChargedBytes(), charge);
        for (const auto& item : source.templates) BOOST_REQUIRE(reopened.Template(item.id));
    }
    BOOST_CHECK_THROW((sharepool::HashSnapshotStore{path, false, ho::TIDES_VERSION, {.max_bytes = charge - 1}}), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(archived_v6_templates_release_duplicate_storage_with_shared_transaction_safety)
{
    const auto path = m_path_root / "archived-template-release";
    source.binding.version = ho::TIDES_VERSION;
    source.binding.rules = ho::RulesHash(ho::TIDES_VERSION);
    CBlock second{block};
    ++second.nTime;
    {
        sharepool::HashSnapshotStore store{path, false, ho::TIDES_VERSION};
        LOCK(cs_main);
        store.RememberTemplate(block);
        store.RememberTemplate(second);
        store.Put(ho::EncodeSnapshot(source));
        BOOST_CHECK_EQUAL(store.TemplateCount(), 1);
        CheckBlock(store.Template(ho::TemplateId(second)), second);
        sharepool::HashSnapshotStoreTest::ClearSources(store);
        CheckBlock(store.Template(ho::TemplateId(block)), block);
        auto next = source;
        next.templates = {{ho::TemplateId(second), second}};
        store.Put(ho::EncodeSnapshot(next));
        BOOST_CHECK_EQUAL(store.TemplateCount(), 0);
        BOOST_CHECK_EQUAL(store.TemplateBytes(), 0);
        store.RememberTemplate(block);
        BOOST_CHECK_EQUAL(store.TemplateBytes(), 0);
    }
    {
        sharepool::HashSnapshotStore reopened{path, false, ho::TIDES_VERSION};
        LOCK(cs_main);
        CheckBlock(reopened.Template(ho::TemplateId(block)), block);
        CheckBlock(reopened.Template(ho::TemplateId(second)), second);
        BOOST_CHECK_EQUAL(reopened.TemplateBytes(), 0);
    }
}

BOOST_AUTO_TEST_CASE(interrupted_legacy_migration_resumes_committed_batches_without_double_counting)
{
    const auto path = m_path_root / "checkpoint-resume";
    std::map<uint256, std::vector<unsigned char>> records;
    for (uint32_t i{0}; i < 129; ++i) {
        DataStream stream;
        stream << uint8_t{ho::VERSION} << i;
        const std::vector<unsigned char> raw{UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
        records.emplace(ho::SnapshotHash(raw), raw);
    }
    const auto full = ho::EncodeSnapshot(source);
    records.emplace(ho::SnapshotHash(full), full);
    {
        // A previous r2 store has raw objects and disposable indexes but no
        // durable checkpoint. The first migration is interrupted after its
        // first 64-record atomic scan batch, without a clean shutdown marker.
        CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
        CDBBatch batch{db};
        for (const auto& [hash, raw] : records) batch.Write(std::make_pair(uint8_t{'s'}, hash), raw);
        BOOST_REQUIRE(db.WriteBatch(batch, true));
    }
    unsigned checks{0};
    BOOST_CHECK_EXCEPTION((sharepool::HashSnapshotStore{path, false, ho::VERSION,
        {.interrupted = [&checks] { return ++checks > 3; }}}), std::runtime_error,
        [](const auto& error) { return std::string{error.what()}.find("interrupted") != std::string::npos; });
    {
        sharepool::HashSnapshotStore resumed{path};
        LOCK(cs_main);
        BOOST_CHECK(resumed.GetStartupStats().resumed_rebuild);
        BOOST_CHECK_EQUAL(resumed.GetStartupStats().records_scanned, records.size() - 64);
        BOOST_CHECK_EQUAL(resumed.Count(), records.size());
        uint64_t bytes{0};
        for (const auto& [hash, raw] : records) {
            bytes += raw.size();
            BOOST_CHECK(resumed.Get(hash) == raw);
        }
        BOOST_CHECK_EQUAL(resumed.Bytes(), bytes);
        BOOST_CHECK_EQUAL(resumed.ChargedBytes(), bytes + 128 * records.size() + 224);
        CheckBlock(resumed.Template(ho::TemplateId(block)), block);
        // A fresh fsynced Put immediately after recovery updates the same
        // checkpoint as its payload, metadata and source references.
        resumed.Put(std::vector<unsigned char>{4, 99, 98});
    }
    {
        sharepool::HashSnapshotStore ready{path};
        LOCK(cs_main);
        BOOST_CHECK(ready.GetStartupStats().fast_path);
        BOOST_CHECK_EQUAL(ready.GetStartupStats().records_scanned, 0);
        BOOST_CHECK_EQUAL(ready.Count(), records.size() + 1);
        CheckBlock(ready.Template(ho::TemplateId(block)), block);
    }
}

BOOST_AUTO_TEST_CASE(rebuild_quota_failure_retains_a_cursor_and_resumes_after_capacity_increase)
{
    const auto path = m_path_root / "checkpoint-quota-resume";
    {
        CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
        CDBBatch batch{db};
        for (uint32_t i{0}; i < 130; ++i) {
            DataStream stream;
            stream << uint8_t{ho::VERSION} << i;
            const std::vector<unsigned char> raw{UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
            batch.Write(std::make_pair(uint8_t{'s'}, ho::SnapshotHash(raw)), raw);
        }
        BOOST_REQUIRE(db.WriteBatch(batch, true));
    }
    BOOST_CHECK_THROW((sharepool::HashSnapshotStore{path, false, ho::VERSION, {.max_bytes = 64 * 133}}), std::runtime_error);
    {
        sharepool::HashSnapshotStore resumed{path, false, ho::VERSION, {.max_bytes = 130 * 133}};
        LOCK(cs_main);
        BOOST_CHECK(resumed.GetStartupStats().resumed_rebuild);
        BOOST_CHECK_EQUAL(resumed.GetStartupStats().records_scanned, 66);
        BOOST_CHECK_EQUAL(resumed.Count(), 130);
        BOOST_CHECK_EQUAL(resumed.Bytes(), 130 * 5);
        BOOST_CHECK_EQUAL(resumed.ChargedBytes(), 130 * 133);
    }
}

BOOST_AUTO_TEST_CASE(checkpoint_damage_and_profile_mismatch_fail_explicitly_without_reinterpreting_evidence)
{
    const auto path = m_path_root / "checkpoint-integrity";
    const auto raw = ho::EncodeSnapshot(source);
    const auto hash = ho::SnapshotHash(raw);
    {
        sharepool::HashSnapshotStore store{path};
        LOCK(cs_main);
        store.Put(raw);
    }
    BOOST_CHECK_THROW((sharepool::HashSnapshotStore{path, false, ho::TIDES_VERSION}), std::runtime_error);
    BOOST_CHECK_THROW((sharepool::HashSnapshotStore{path, false, ho::TIDES_VERSION, {.rebuild_index = true}}), std::runtime_error);
    {
        CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
        BOOST_REQUIRE(db.Write(uint8_t{'C'}, std::vector<unsigned char>{0}, true));
    }
    BOOST_CHECK_THROW((sharepool::HashSnapshotStore{path}), std::runtime_error);
    {
        sharepool::HashSnapshotStore repaired{path, false, ho::VERSION, {.rebuild_index = true}};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(repaired.GetStartupStats().records_scanned, 1);
        BOOST_CHECK(repaired.Get(hash) == raw);
        CheckBlock(repaired.Template(ho::TemplateId(block)), block);
    }
}

BOOST_AUTO_TEST_CASE(source_index_corruption_requests_repair_and_interrupted_repair_resumes)
{
    const auto path = m_path_root / "source-index-checksum";
    const auto raw = ho::EncodeSnapshot(source);
    {
        sharepool::HashSnapshotStore store{path};
        LOCK(cs_main);
        store.Put(raw);
        sharepool::HashSnapshotStoreTest::DamageSources(store, ho::TemplateId(block));
        BOOST_CHECK(!store.Template(ho::TemplateId(block)));
        BOOST_CHECK(store.RepairRequired());
        BOOST_CHECK(store.Get(ho::SnapshotHash(raw)) == raw); // Authenticated unrelated reads remain usable.
    }
    BOOST_CHECK_THROW((sharepool::HashSnapshotStore{path}), std::runtime_error);
    unsigned checks{0};
    BOOST_CHECK_THROW((sharepool::HashSnapshotStore{path, false, ho::VERSION,
        {.rebuild_index = true, .interrupted = [&checks] { return ++checks > 1; }}}), std::runtime_error);
    {
        // The rebuild marker overrides the persistent repair-required marker;
        // no repeated explicit flag or reset of completed clearing is needed.
        sharepool::HashSnapshotStore resumed{path};
        LOCK(cs_main);
        BOOST_CHECK(resumed.GetStartupStats().resumed_rebuild);
        BOOST_CHECK(!resumed.RepairRequired());
        BOOST_CHECK_EQUAL(resumed.GetStartupStats().records_scanned, 1);
        BOOST_CHECK_EQUAL(resumed.Count(), 1);
        CheckBlock(resumed.Template(ho::TemplateId(block)), block);
    }
}

BOOST_AUTO_TEST_CASE(disposable_metadata_damage_and_stale_keys_rebuild_from_authenticated_preimages)
{
    const auto path = m_path_root / "metadata-recovery";
    const std::vector<unsigned char> raw{6, 1, 2, 3};
    uint256 hash;
    {
        sharepool::HashSnapshotStore store{path, false, ho::TIDES_VERSION};
        LOCK(cs_main);
        hash = store.Put(raw);
        sharepool::HashSnapshotStoreTest::DamageMetadata(store, hash);
        BOOST_CHECK(!store.Has(hash));
        BOOST_CHECK(!store.Get(hash));
        BOOST_CHECK(store.InventoryPage().hashes.empty());
        BOOST_CHECK(store.RepairRequired());
        BOOST_CHECK_THROW(store.Put(raw, hash), std::runtime_error);
    }
    BOOST_CHECK_THROW((sharepool::HashSnapshotStore{path, false, ho::TIDES_VERSION}), std::runtime_error);
    {
        sharepool::HashSnapshotStore repaired{path, false, ho::TIDES_VERSION, {.rebuild_index = true}};
        LOCK(cs_main);
        BOOST_CHECK(!repaired.RepairRequired());
        BOOST_CHECK(!repaired.GetStartupStats().fast_path);
        BOOST_CHECK_EQUAL(repaired.GetStartupStats().records_scanned, 1);
        BOOST_CHECK_EQUAL(repaired.Count(), 1);
        BOOST_CHECK(repaired.Get(hash) == raw);
    }
    {
        CDBWrapper db{DBParams{.path = path, .cache_bytes = 1024 * 1024}};
        BOOST_REQUIRE(db.Erase(std::make_pair(uint8_t{'s'}, hash), true));
    }
    {
        sharepool::HashSnapshotStore missing{path, false, ho::TIDES_VERSION};
        LOCK(cs_main);
        BOOST_CHECK(missing.GetStartupStats().fast_path);
        BOOST_CHECK(!missing.Get(hash));
        BOOST_CHECK(!missing.Has(hash));
        BOOST_CHECK(missing.RepairRequired());
    }
    {
        sharepool::HashSnapshotStore repaired{path, false, ho::TIDES_VERSION, {.rebuild_index = true}};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(repaired.Count(), 0);
        BOOST_CHECK_EQUAL(repaired.Bytes(), 0);
        BOOST_CHECK_EQUAL(repaired.ChargedBytes(), 0);
        BOOST_CHECK(repaired.Inventory().empty());
        repaired.Put(raw, hash);
        BOOST_CHECK_EQUAL(repaired.Count(), 1);
    }
}

BOOST_AUTO_TEST_CASE(reoffering_cached_bytes_repairs_the_durable_record)
{
    const auto path = m_path_root / "cached-record-repair";
    const std::vector<unsigned char> raw{6, 1, 2, 3};
    uint256 hash;
    {
        sharepool::HashSnapshotStore store{path, false, ho::TIDES_VERSION};
        LOCK(cs_main);
        hash = store.Put(raw);
        sharepool::HashSnapshotStoreTest::DamageSnapshot(store, hash);
        BOOST_CHECK(store.Get(hash) == raw); // Cache remains sound.
        BOOST_CHECK(store.Put(raw, hash) == hash);
        BOOST_CHECK_EQUAL(store.Count(), 1);
        BOOST_CHECK_EQUAL(store.Bytes(), raw.size());
        BOOST_CHECK_EQUAL(store.ChargedBytes(), raw.size() + 128);
    }
    {
        sharepool::HashSnapshotStore reopened{path, false, ho::TIDES_VERSION};
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(reopened.Count(), 1);
        BOOST_CHECK(reopened.Get(hash) == raw);
    }
}

BOOST_AUTO_TEST_CASE(streaming_archive_chunks_resume_and_authenticate_selected_profile)
{
    sharepool::HashSnapshotStore store{m_path_root / "export-source", true, ho::TIDES_VERSION};
    sharepool::HashSnapshotStore restored{m_path_root / "import-target", false, ho::TIDES_VERSION};
    LOCK(cs_main);
    for (unsigned char i{0}; i < 17; ++i) store.Put(std::vector<unsigned char>{6, i, 42});
    const auto archive_path = m_path_root / "chunk.spha";
    std::optional<uint256> cursor;
    uint64_t total{0};
    bool complete{false};
    while (!complete) {
        sharepool::HashSnapshotStore::ArchiveResult exported;
        {
            AutoFile file{fsbridge::fopen(archive_path, "wb")};
            exported = store.ExportArchive(file, cursor, 5, 12);
            BOOST_REQUIRE(file.Commit());
            BOOST_REQUIRE_EQUAL(file.fclose(), 0);
        }
        BOOST_CHECK_LE(exported.records, 4);
        {
            AutoFile file{fsbridge::fopen(archive_path, "rb")};
            const auto imported = restored.ImportArchive(file, 5, 12);
            BOOST_CHECK_EQUAL(imported.records, exported.records);
            BOOST_CHECK_EQUAL(imported.bytes, exported.bytes);
            BOOST_CHECK(imported.next == exported.next);
            BOOST_CHECK_EQUAL(imported.complete, exported.complete);
        }
        total += exported.records;
        cursor = exported.next;
        complete = exported.complete;
    }
    BOOST_CHECK_EQUAL(total, 17);
    BOOST_CHECK_EQUAL(restored.Count(), 17);
    BOOST_CHECK(restored.Inventory() == store.Inventory());
    {
        sharepool::HashSnapshotStore wrong_profile{m_path_root / "wrong-profile", true, ho::VERSION};
        AutoFile file{fsbridge::fopen(archive_path, "rb")};
        BOOST_CHECK_THROW(wrong_profile.ImportArchive(file), std::runtime_error);
        BOOST_CHECK_EQUAL(wrong_profile.Count(), 0);
    }
}

BOOST_AUTO_TEST_CASE(archive_streams_operate_without_a_caller_chain_mutex)
{
    sharepool::HashSnapshotStore store{m_path_root / "unlocked-export", true, ho::TIDES_VERSION};
    sharepool::HashSnapshotStore restored{m_path_root / "unlocked-import", true, ho::TIDES_VERSION};
    {
        LOCK(cs_main);
        store.Put(std::vector<unsigned char>{6, 1, 2, 3});
    }
    const auto path = m_path_root / "unlocked.spha";
    {
        AutoFile file{fsbridge::fopen(path, "wb")};
        const auto exported = store.ExportArchive(file);
        BOOST_CHECK_EQUAL(exported.records, 1);
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    }
    {
        AutoFile file{fsbridge::fopen(path, "rb")};
        const auto imported = restored.ImportArchive(file);
        BOOST_CHECK_EQUAL(imported.records, 1);
    }
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(restored.Count(), 1);
        BOOST_CHECK(restored.Inventory() == store.Inventory());
    }
}

BOOST_AUTO_TEST_CASE(streaming_archive_rejects_corruption_truncation_trailing_data_and_resource_excess)
{
    const auto archive_path = m_path_root / "damaged.spha";
    sharepool::HashSnapshotStore source_store{m_path_root / "damage-export", true, ho::TIDES_VERSION};
    LOCK(cs_main);
    source_store.Put(std::vector<unsigned char>{6, 1, 2, 3});
    source_store.Put(std::vector<unsigned char>{6, 4, 5, 6});
    const auto save = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        AutoFile file{fsbridge::fopen(archive_path, "wb")};
        source_store.ExportArchive(file);
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    };
    for (int mutation{0}; mutation < 5; ++mutation) {
        save();
        {
            AutoFile file{fsbridge::fopen(archive_path, "r+b")};
            if (mutation == 0) {
                file.seek(12 + 4 + 1 + 32 + 4 + 32, SEEK_SET); // First payload byte.
                file << uint8_t{255};
            } else if (mutation == 1) {
                file.seek(-1, SEEK_END);
                BOOST_REQUIRE(file.Truncate(file.tell()));
            } else if (mutation == 2) {
                file.seek(0, SEEK_END);
                file << uint8_t{1};
            }
            BOOST_REQUIRE_EQUAL(file.fclose(), 0);
        }
        sharepool::HashSnapshotStore target{m_path_root / fs::PathFromString("damaged-target-" + std::to_string(mutation)), true, ho::TIDES_VERSION};
        AutoFile file{fsbridge::fopen(archive_path, "rb")};
        BOOST_CHECK_THROW(target.ImportArchive(file, mutation == 3 ? 1 : 1024, mutation == 4 ? 3 : 1024), std::exception);
        if (mutation == 0 || mutation == 4) BOOST_CHECK_EQUAL(target.Count(), 0);
        // Failed imports retain only individually hash-verified records.
        for (const auto& hash : target.Inventory()) BOOST_CHECK(target.Get(hash) == source_store.Get(hash));
    }
}

BOOST_AUTO_TEST_SUITE_END()
