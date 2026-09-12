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

#include <array>

#include <boost/test/unit_test.hpp>

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

std::vector<unsigned char> Bytes(const CTransaction& tx)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(tx);
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

BOOST_AUTO_TEST_SUITE_END()
