// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/merkle.h>
#include <consensus/sharepool_hash.h>
#include <key.h>
#include <kernel/chainparams.h>
#include <pow.h>
#include <pubkey.h>
#include <script/script.h>
#include <sharepool/tides_history.h>
#include <test/util/setup_common.h>
#include <versionbits.h>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <map>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {
namespace ho = sharepool::hashonly;
using boost::multiprecision::cpp_int;

cpp_int Integer(const uint256& value)
{
    return cpp_int{"0x" + value.GetHex()};
}

std::vector<unsigned char> Script(unsigned char id)
{
    std::vector<unsigned char> result{OP_0, 20};
    result.resize(22, id);
    return result;
}

CTxOut Output(CAmount value, unsigned char id)
{
    const auto script = Script(id);
    return {value, CScript{script.begin(), script.end()}};
}

struct TidesFixture : BasicTestingSetup {
    static constexpr CAmount REWARD{100003};
    Consensus::Params consensus{CChainParams::RegTest({})->GetConsensus()};
    std::array<uint256, 5> hashes;
    std::array<CBlockIndex, 5> indexes;
    CKey key;
    std::map<uint256, std::shared_ptr<const ho::Snapshot>> snapshots;

    TidesFixture()
    {
        consensus.hashGenesisBlock = uint256{uint8_t{1}};
        consensus.SharePoolHeight = 1;
        consensus.SharePoolHashOnly = true;
        consensus.SharePoolAdmittedLedger = false;
        consensus.SharePoolTides = true;
        consensus.Blake2bHeight = 1;
        // Public unit-test key. These fixtures do not model native UTXO or PoW
        // validation of the containing blocks; the callback supplies that layer.
        std::array<unsigned char, 32> secret{};
        secret.back() = 1;
        key.Set(secret.begin(), secret.end(), true);
        for (size_t i{0}; i < indexes.size(); ++i) {
            hashes[i] = uint256{static_cast<uint8_t>(i + 1)};
            indexes[i].phashBlock = &hashes[i];
            indexes[i].nHeight = i;
            indexes[i].nTime = 1000 + i * 600;
            indexes[i].nBits = sharepool::SHARE_BITS;
            indexes[i].m_header_v2 = i > 0;
            if (i) indexes[i].pprev = &indexes[i - 1];
            indexes[i].BuildSkip();
        }
    }

    ho::Snapshot Empty(uint32_t height = 1, unsigned char owner = 0x61, uint8_t pool = 3)
    {
        ho::Snapshot result;
        auto& binding = result.binding;
        binding.version = ho::TIDES_VERSION;
        binding.genesis = consensus.hashGenesisBlock;
        binding.rules = ho::RulesHash(ho::TIDES_VERSION);
        binding.height = height;
        binding.native_parent = hashes.at(height - 1);
        binding.pool = uint256{pool};
        binding.payout_script = Script(owner);
        const XOnlyPubKey pubkey{key.GetPubKey()};
        std::copy(pubkey.begin(), pubkey.end(), binding.owner.begin());
        State(result);
        return result;
    }

    ho::Lookup Lookup()
    {
        return [this](const uint256& hash) -> std::shared_ptr<const ho::Snapshot> {
            const auto found = snapshots.find(hash);
            return found == snapshots.end() ? nullptr : found->second;
        };
    }

    void State(ho::Snapshot& snapshot)
    {
        const auto height = snapshot.binding.height;
        const auto* parent = height == 1 ? nullptr : snapshots.at(indexes.at(height - 1).m_mm_rhs).get();
        ho::ApplyTidesState(snapshot, parent);
        const auto result = ho::CalculateTidesPayouts(snapshot, &indexes.at(height - 1),
            indexes.at(height - 1).nBits, consensus, Lookup(), REWARD, snapshot.payouts);
        if (!result.IsValid()) throw std::runtime_error(result.reason);
    }

    CBlock Block(ho::Snapshot& snapshot)
    {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript{} << int64_t{snapshot.binding.height} << OP_0;
        coinbase.vout = snapshot.payouts;
        CBlock block;
        block.m_header_v2 = true;
        block.nVersion = VERSIONBITS_TOP_BITS;
        block.m_height = snapshot.binding.height;
        block.hashPrevBlock = snapshot.binding.native_parent;
        block.nTime = indexes.at(snapshot.binding.height - 1).nTime + 1;
        block.nBits = GetNextWorkRequired(&indexes.at(snapshot.binding.height - 1), &block, consensus);
        block.m_txcount = 1;
        block.vtx = {MakeTransactionRef(std::move(coinbase))};
        block.hashMerkleRoot = BlockMerkleRoot(block);
        snapshot.job_commitment = ho::JobHash(block);
        if (!key.SignSchnorr(ho::OwnerHash(snapshot), snapshot.authorization, nullptr, {})) {
            throw std::runtime_error("fixture signing failed");
        }
        block.m_mm_rhs = ho::SnapshotHash(snapshot);
        snapshots[block.m_mm_rhs] = std::make_shared<const ho::Snapshot>(snapshot);
        return block;
    }

    void Add(ho::Snapshot& snapshot, const CBlock& origin, const ho::Snapshot& opening, uint32_t nonce = 1)
    {
        const auto id = ho::TemplateId(origin);
        if (std::none_of(snapshot.templates.begin(), snapshot.templates.end(), [&](const auto& entry) { return entry.id == id; })) {
            snapshot.templates.push_back({id, origin});
        }
        sharepool::Share share;
        share.header = origin.GetBlockHeader();
        share.header.nNonce = nonce;
        share.origin = opening.binding;
        share.authorization = opening.authorization;
        snapshot.shares.push_back(std::move(share));
        std::sort(snapshot.templates.begin(), snapshot.templates.end(), [](const auto& a, const auto& b) { return a.id < b.id; });
        std::sort(snapshot.shares.begin(), snapshot.shares.end(), [](const auto& a, const auto& b) {
            return UintToArith256(a.header.GetHash()) < UintToArith256(b.header.GetHash());
        });
    }

    ho::Result Check(const CBlock& block, std::optional<CAmount> reward = REWARD)
    {
        const auto native = [](const CBlock& origin, const CBlockIndex* previous) {
            if (!previous || origin.hashPrevBlock != previous->GetBlockHash() || BlockMerkleRoot(origin) != origin.hashMerkleRoot) {
                return ho::Result::Invalid("fixture-body");
            }
            return ho::Result::Valid(REWARD);
        };
        return ho::CheckSnapshot(block, &indexes.at(block.m_height - 1), consensus, Lookup(), native, reward);
    }

    void Anchor(const CBlock& block)
    {
        LOCK(cs_main);
        auto& index = indexes.at(block.m_height);
        hashes.at(block.m_height) = block.GetHash();
        index.m_mm_rhs = block.m_mm_rhs;
        index.nTime = block.nTime;
        index.nBits = block.nBits;
        // Conditional branch accounting is usable before ConnectBlock. Actual
        // native ancestor validity remains mandatory before chain activation.
        index.nStatus = BLOCK_VALID_TRANSACTIONS;
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(sharepool_tides_consensus_tests, TidesFixture)

BOOST_AUTO_TEST_CASE(exact_assigned_work_and_probability_across_native_targets)
{
    const cpp_int space = cpp_int{1} << 256;
    for (const auto bits : {0x207fffffU, 0x1d00ffffU, 0x1b0404cbU, 0x01010000U}) {
        const cpp_int native = Integer(ArithToUint256(arith_uint256{}.SetCompact(bits)));
        const cpp_int work = Integer(ho::TidesShareWork(bits));
        const cpp_int target = Integer(ho::ShareTarget(bits, ho::TIDES_VERSION));
        BOOST_CHECK(work > 0);
        BOOST_CHECK((work & (work - 1)) == 0);
        BOOST_CHECK_EQUAL(cpp_int(work * (target + 1)).str(), space.str());
        cpp_int desired = space / (native + 1) / 1024;
        if (desired < 1) desired = 1;
        BOOST_CHECK(work <= desired);
        BOOST_CHECK(2 * work > desired);
        BOOST_CHECK(ho::ShareTarget(bits, ho::VERSION) == ho::ShareTarget(bits, ho::LEDGER_VERSION));
    }
    BOOST_CHECK_EQUAL(Integer(ho::TidesShareWork(sharepool::SHARE_BITS)).str(), "1");
    BOOST_CHECK_EQUAL(Integer(ho::ShareTarget(sharepool::SHARE_BITS, ho::TIDES_VERSION)).str(), cpp_int(space - 1).str());
    BOOST_CHECK(ho::ShareTarget(sharepool::SHARE_BITS, ho::VERSION) != ho::ShareTarget(sharepool::SHARE_BITS, ho::TIDES_VERSION));
    BOOST_CHECK_EQUAL(Integer(ho::TidesShareWork(0x01010000)).str(), (cpp_int{1} << 245).str());
    for (const auto bits : {0U, 0x1d80ffffU, 0x23000001U, 0x03000001U}) {
        BOOST_CHECK_THROW(ho::TidesShareWork(bits), std::invalid_argument);
        BOOST_CHECK_THROW(ho::ShareTarget(bits, ho::TIDES_VERSION), std::invalid_argument);
    }
    BOOST_CHECK_THROW(ho::ShareTarget(sharepool::SHARE_BITS, 8), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(legacy_hash_domains_and_new_profile_remain_distinct)
{
    // Golden values generated independently with hashlib and little-endian
    // struct packing. In particular malformed v6-looking bytes keep the old
    // raw-hash behavior under both legacy profiles.
    BOOST_CHECK_EQUAL(ho::RulesHash(4).GetHex(), "2d8343cd857f5ea23b189a5db0c52ddc7923a5b96bed09e3624391da04d8e9c0");
    BOOST_CHECK_EQUAL(ho::RulesHash(5).GetHex(), "44b6ecb8d0688dbe1be89dbc1008a6414935263409f03163711bff5555e51770");
    BOOST_CHECK_EQUAL(ho::RulesHash(6).GetHex(), "9050ab43fa5feddb7f0659abc4ca43f596d4465f93535f3b9ab37449397e6edd");
    const std::vector<unsigned char> malformed{6, 0xff};
    BOOST_CHECK_EQUAL(ho::SnapshotHash(malformed).GetHex(), "0ea745471620362b303b1b64cff683f020e8cb7de58de1017e677190d4949234");
    BOOST_CHECK(ho::ProfileSnapshotHash(malformed, 4) == ho::SnapshotHash(malformed));
    BOOST_CHECK(ho::ProfileSnapshotHash(malformed, 5) == ho::SnapshotHash(malformed));
    BOOST_CHECK_EQUAL(ho::ProfileSnapshotHash(malformed, 6).GetHex(), "e149ea7b762065059c1f7d6d74a30d3695c07b3dfd6e1368c47bd900dd651123");
    BOOST_CHECK_EQUAL(ho::SnapshotHash(std::vector<unsigned char>{5, 0}).GetHex(), "66d6850be22f3996da4f56c769e216bd81725626671b2d51b77cc59cd0da4a01");
    BOOST_CHECK_THROW(ho::ProfileSnapshotHash(malformed, 8), std::invalid_argument);
    BOOST_CHECK_THROW(ho::RulesHash(8), std::invalid_argument);

    auto snapshot = Empty();
    const auto block = Block(snapshot);
    const auto bytes = ho::EncodeSnapshot(snapshot);
    BOOST_CHECK(ho::EncodeSnapshot(ho::DecodeSnapshot(bytes)) == bytes);
    BOOST_CHECK(block.m_mm_rhs == ho::ProfileSnapshotHash(bytes, 6));
    BOOST_CHECK(block.m_mm_rhs != ho::SnapshotHash(bytes));
    BOOST_CHECK(ho::ProfileSnapshotHash(snapshot, 4) == ho::SnapshotHash(bytes));
    BOOST_CHECK(ho::ProfileSnapshotHash(snapshot, 5) == ho::SnapshotHash(bytes));
    BOOST_CHECK_THROW(ho::CalculatePayouts(snapshot, REWARD), std::invalid_argument);
    auto legacy = consensus;
    legacy.SharePoolTides = false;
    BOOST_CHECK_EQUAL(ho::ProfileVersion(legacy), 4U);
    legacy.SharePoolAdmittedLedger = true;
    BOOST_CHECK_EQUAL(ho::ProfileVersion(legacy), 5U);
    BOOST_CHECK_EQUAL(ho::ProfileVersion(consensus), 6U);
}

BOOST_AUTO_TEST_CASE(rational_native_window_clips_boundary_without_integer_rounding)
{
    auto alice = Empty(1, 0x11);
    const auto alice_job = Block(alice);
    auto first = Empty();
    Add(first, alice_job, alice);
    State(first);
    const auto first_block = Block(first);
    BOOST_REQUIRE(Check(first_block).IsValid());
    Anchor(first_block);
    auto snapshot = Empty(2);
    // Accounting-only current inputs: at the regtest target each proof has
    // one expected hash of work. Sixteen proofs admitted at height2 are newer
    // than Alice's independently admitted height1 proof. The exact window is
    // slightly more than16, so the older HEIGHT cohort receives a fraction.
    // Neither rounding network work down to 2 nor rounding the window up to 17
    // gives these payouts. The full verifier authenticates these inputs later.
    for (uint32_t i{0}; i < 16; ++i) {
        sharepool::Share share;
        share.header.nBits = sharepool::SHARE_BITS;
        share.header.nNonce = i;
        share.origin.pool = snapshot.binding.pool;
        share.origin.payout_script = Script(0x22);
        snapshot.shares.push_back(std::move(share));
    }
    std::sort(snapshot.shares.begin(), snapshot.shares.end(), [](const auto& a, const auto& b) {
        return UintToArith256(a.header.GetHash()) < UintToArith256(b.header.GetHash());
    });
    std::vector<CTxOut> payouts;
    auto result = ho::CalculateTidesPayouts(snapshot, &indexes[1], sharepool::SHARE_BITS, consensus, Lookup(), MAX_MONEY, payouts);
    BOOST_REQUIRE_MESSAGE(result.IsValid(), result.reason);
    const cpp_int denominator = Integer(ArithToUint256(arith_uint256{}.SetCompact(sharepool::SHARE_BITS))) + 1;
    const cpp_int requested = cpp_int{8} << 256;
    const cpp_int boundary = requested - 16 * denominator;
    const auto oldest = (cpp_int{MAX_MONEY} * boundary / requested).convert_to<CAmount>();
    const auto newest = (cpp_int{MAX_MONEY} * 16 * denominator / requested).convert_to<CAmount>();
    BOOST_CHECK(oldest > 0);
    BOOST_CHECK(oldest < MAX_MONEY / 17);
    BOOST_CHECK(payouts == (std::vector<CTxOut>{Output(oldest, 0x11), Output(newest, 0x22)}));
    BOOST_CHECK_EQUAL(oldest + newest, MAX_MONEY - 1);

    // Reserve all eligible scripts independently of whether a tiny reward
    // floors either actual entitlement to zero.
    result = ho::CalculateTidesPayouts(snapshot, &indexes[1], sharepool::SHARE_BITS, consensus, Lookup(), 1, payouts, true);
    BOOST_REQUIRE(result.IsValid());
    BOOST_CHECK(payouts == (std::vector<CTxOut>{Output(0, 0x11), Output(0, 0x22)}));
    result = ho::CalculateTidesPayouts(snapshot, &indexes[1], sharepool::SHARE_BITS, consensus, Lookup(), 1, payouts);
    BOOST_REQUIRE(result.IsValid());
    BOOST_CHECK(payouts.empty());
}

BOOST_AUTO_TEST_CASE(boundary_cohort_pays_every_recipient_independently_of_proof_order)
{
    auto snapshot = Empty();
    // Direct accounting inputs isolate recipient/order invariance. Native
    // canonical serialization still requires numeric proof-ID ordering.
    for (uint32_t i{0}; i < 100; ++i) {
        sharepool::Share proof;
        proof.header.nBits = sharepool::SHARE_BITS;
        proof.header.nNonce = i;
        proof.origin.pool = snapshot.binding.pool;
        proof.origin.payout_script = Script(i + 1);
        snapshot.shares.push_back(std::move(proof));
    }
    const ho::Lookup no_history = [](const uint256&) -> std::shared_ptr<const ho::Snapshot> {
        throw std::runtime_error("whole current cohort already fills window");
    };
    std::vector<CTxOut> payouts;
    auto result = ho::CalculateTidesPayouts(snapshot, &indexes[0], sharepool::SHARE_BITS, consensus, no_history, REWARD, payouts);
    BOOST_REQUIRE_MESSAGE(result.IsValid(), result.reason);
    BOOST_REQUIRE_EQUAL(payouts.size(), 100);
    for (uint32_t i{0}; i < 100; ++i) BOOST_CHECK(payouts[i] == Output(REWARD / 100, i + 1));
    const auto expected = payouts;
    std::reverse(snapshot.shares.begin(), snapshot.shares.end());
    result = ho::CalculateTidesPayouts(snapshot, &indexes[0], sharepool::SHARE_BITS, consensus, no_history, REWARD, payouts);
    BOOST_REQUIRE(result.IsValid());
    BOOST_CHECK(payouts == expected);
    // Changing nonce/proof IDs does not let a recipient move ahead of the
    // other members of its same native-height admission cohort.
    for (auto& proof : snapshot.shares) proof.header.nNonce += 1000;
    result = ho::CalculateTidesPayouts(snapshot, &indexes[0], sharepool::SHARE_BITS, consensus, no_history, REWARD, payouts);
    BOOST_REQUIRE(result.IsValid());
    BOOST_CHECK(payouts == expected);
}

BOOST_AUTO_TEST_CASE(fractional_cohort_uses_more_than_512_bits_without_losing_newer_work)
{
    auto historical = Empty();
    // Arithmetic boundary fixtures, not a claim that regtest naturally moves
    // between these difficulties. Exact historical bindings/signatures are
    // supplied; full native ancestor validity is covered by separate tests.
    constexpr uint32_t COHORT_SIZE{8192};
    for (uint32_t i{0}; i < COHORT_SIZE; ++i) {
        sharepool::Share proof;
        proof.header.nBits = 0x01010000; // Assigned work2^245 per proof.
        proof.header.nNonce = i + 1;
        proof.origin.pool = historical.binding.pool;
        proof.origin.payout_script = Script(i & 1 ? 0x22 : 0x11);
        historical.shares.push_back(std::move(proof));
    }
    std::sort(historical.shares.begin(), historical.shares.end(), [](const auto& a, const auto& b) {
        return UintToArith256(a.header.GetHash()) < UintToArith256(b.header.GetHash());
    });
    const auto historical_block = Block(historical);
    Anchor(historical_block);
    auto current = Empty(2);
    sharepool::Share newer;
    newer.header.nBits = sharepool::SHARE_BITS;
    newer.header.nNonce = 300;
    newer.origin.pool = current.binding.pool;
    newer.origin.payout_script = Script(0x11);
    current.shares.push_back(std::move(newer));
    std::vector<CTxOut> payouts;
    const auto result = ho::CalculateTidesPayouts(current, &indexes[1], sharepool::SHARE_BITS,
        consensus, Lookup(), MAX_MONEY, payouts);
    BOOST_REQUIRE_MESSAGE(result.IsValid(), result.reason);
    const cpp_int denominator = Integer(ArithToUint256(arith_uint256{}.SetCompact(sharepool::SHARE_BITS))) + 1;
    const cpp_int window = cpp_int{8} << 256;
    const cpp_int work = cpp_int{1} << 245;
    const cpp_int total = COHORT_SIZE * work;
    const cpp_int each = (COHORT_SIZE / 2) * work;
    BOOST_CHECK(total * denominator >= (cpp_int{1} << 512));
    const cpp_int alice_numerator = cpp_int{MAX_MONEY} * (denominator * total + (window - denominator) * each);
    const cpp_int bob_numerator = cpp_int{MAX_MONEY} * (window - denominator) * each;
    BOOST_CHECK(alice_numerator >= (cpp_int{1} << 512));
    BOOST_CHECK(bob_numerator >= (cpp_int{1} << 512));
    const auto alice = (alice_numerator / (window * total)).convert_to<CAmount>();
    const auto bob = (bob_numerator / (window * total)).convert_to<CAmount>();
    BOOST_CHECK(alice > bob); // Alice's newer full work must survive scaling.
    BOOST_CHECK(payouts == (std::vector<CTxOut>{Output(alice, 0x11), Output(bob, 0x22)}));
    BOOST_CHECK_EQUAL(alice + bob, MAX_MONEY - 1);
}

BOOST_AUTO_TEST_CASE(actual_parent_plus_current_delta_pays_and_rewards_do_not_reset_history)
{
    auto alice = Empty(1, 0x11);
    const auto alice_job = Block(alice);
    auto first = Empty();
    Add(first, alice_job, alice);
    State(first);
    const auto first_block = Block(first);
    const auto first_check = Check(first_block);
    BOOST_REQUIRE_MESSAGE(first_check.IsValid(), first_check.reason);
    BOOST_CHECK(first.payouts == std::vector<CTxOut>{Output(REWARD, 0x11)});
    Anchor(first_block);

    auto bob = Empty(2, 0x22);
    const auto bob_job = Block(bob);
    auto second = Empty(2);
    Add(second, bob_job, bob);
    State(second);
    const auto second_block = Block(second);
    const auto accepted = Check(second_block);
    BOOST_REQUIRE_MESSAGE(accepted.IsValid(), accepted.reason);
    const std::vector<CTxOut> fair{Output(REWARD / 2, 0x11), Output(REWARD / 2, 0x22)};
    BOOST_CHECK(second.payouts == fair);
    BOOST_CHECK(second.history_head != first.history_head);

    // Matching snapshot/coinbase totals and a fresh exact-job signature are
    // insufficient: redistributing one satoshi violates the historical ledger.
    auto wrong = second;
    --wrong.payouts[0].nValue;
    ++wrong.payouts[1].nValue;
    const auto wrong_block = Block(wrong);
    const auto rejected = Check(wrong_block);
    BOOST_CHECK(rejected.status == ho::Status::Invalid);
    BOOST_CHECK_EQUAL(rejected.reason, "bad-sharepool-hash-tides-payouts");
    BOOST_CHECK(Check(second_block, std::nullopt).IsMissing());
    auto reset = second;
    reset.history_head = first.history_head;
    const auto reset_block = Block(reset);
    BOOST_CHECK_EQUAL(Check(reset_block).reason, "bad-sharepool-hash-tides-history");

    Anchor(second_block);
    auto third = Empty(3);
    const auto third_block = Block(third);
    const auto repeated = Check(third_block);
    BOOST_REQUIRE_MESSAGE(repeated.IsValid(), repeated.reason);
    BOOST_CHECK(third.payouts == fair);
    BOOST_CHECK(third.shares.empty());
    BOOST_CHECK(third.pending.empty());
    BOOST_CHECK(third.settled.empty());

    // Conditional history must remain usable for a competing branch whose
    // parent has not run ConnectBlock; a BLOCK_VALID_SCRIPTS gate here would
    // prevent the child becoming eligible to activate a longer branch.
    {
        LOCK(cs_main);
        BOOST_CHECK(!indexes[2].IsValid(BLOCK_VALID_SCRIPTS));
    }
    std::vector<CTxOut> branch_payouts;
    const auto branch = ho::CalculateTidesPayouts(third, &indexes[2], sharepool::SHARE_BITS,
        consensus, Lookup(), REWARD, branch_payouts);
    BOOST_REQUIRE_MESSAGE(branch.IsValid(), branch.reason);
    BOOST_CHECK(branch_payouts == fair);
}

BOOST_AUTO_TEST_CASE(same_recipient_can_join_multiple_pools_without_moving_old_work)
{
    auto alice_a = Empty(1, 0x31, 3);
    auto bob_a = Empty(1, 0x32, 3);
    auto alice_b = Empty(1, 0x31, 4);
    const auto job_a = Block(alice_a);
    const auto job_bob = Block(bob_a);
    const auto job_b = Block(alice_b);
    auto first = Empty();
    Add(first, job_a, alice_a);
    Add(first, job_bob, bob_a);
    Add(first, job_b, alice_b);
    State(first);
    const auto first_block = Block(first);
    const auto first_check = Check(first_block);
    BOOST_REQUIRE_MESSAGE(first_check.IsValid(), first_check.reason);
    const std::vector<CTxOut> pool_a{Output(REWARD / 2, 0x31), Output(REWARD / 2, 0x32)};
    BOOST_CHECK(first.payouts == pool_a);
    Anchor(first_block);

    auto pool_b = Empty(2, 0x71, 4);
    const auto b_block = Block(pool_b);
    const auto b_check = Check(b_block);
    BOOST_REQUIRE_MESSAGE(b_check.IsValid(), b_check.reason);
    BOOST_CHECK(pool_b.payouts == std::vector<CTxOut>{Output(REWARD, 0x31)});
    auto pool_a_again = Empty(2, 0x71, 3);
    BOOST_CHECK(pool_a_again.payouts == pool_a);
    auto new_pool = Empty(2, 0x71, 5);
    BOOST_CHECK(new_pool.payouts == std::vector<CTxOut>{Output(REWARD, 0x71)});
}

BOOST_AUTO_TEST_CASE(native_payout_queries_apply_configured_capacity_and_recover_after_increase)
{
    namespace tides = sharepool::tides;
    struct Restore {
        tides::HistoryCacheBudget old{tides::ConfiguredHistoryCacheBudget()};
        ~Restore() { tides::ConfigureHistoryCache(old); }
    } restore;
    auto alice = Empty(1, 0x81);
    auto bob = Empty(1, 0x82);
    const auto alice_job = Block(alice);
    const auto bob_job = Block(bob);
    auto first = Empty();
    Add(first, alice_job, alice);
    Add(first, bob_job, bob);
    State(first);
    const auto first_block = Block(first);
    const auto checked = Check(first_block);
    BOOST_REQUIRE_MESSAGE(checked.IsValid(), checked.reason);
    Anchor(first_block);

    auto child = first;
    child.binding.height = 2;
    child.binding.native_parent = first_block.GetHash();
    child.shares.clear();
    child.templates.clear();
    ho::ApplyTidesState(child, &first);
    auto tiny = tides::ConfiguredHistoryCacheBudget();
    tiny.query_bytes = 1; // Internal test seam; startup uses whole positive MiB.
    tides::ConfigureHistoryCache(tiny);
    const std::vector<CTxOut> sentinel{Output(1, 0x91)};
    std::vector<CTxOut> payouts = sentinel;
    const auto limited = ho::CalculateTidesPayouts(child, &indexes[1], sharepool::SHARE_BITS,
        consensus, Lookup(), REWARD, payouts);
    BOOST_CHECK(limited.IsMissing());
    BOOST_CHECK_EQUAL(limited.reason, "bad-sharepool-hash-tides-history-query-budget");
    BOOST_CHECK(payouts == sentinel);
    tides::ConfigureHistoryCache(tides::HistoryCacheBudgetFromMiB("1", "1"));
    const auto resumed = ho::CalculateTidesPayouts(child, &indexes[1], sharepool::SHARE_BITS,
        consensus, Lookup(), REWARD, payouts);
    BOOST_REQUIRE_MESSAGE(resumed.IsValid(), resumed.reason);
    BOOST_CHECK(payouts == (std::vector<CTxOut>{Output(REWARD / 2, 0x81), Output(REWARD / 2, 0x82)}));
}

BOOST_AUTO_TEST_SUITE_END()
