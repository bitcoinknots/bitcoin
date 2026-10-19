// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_AUTO_TEST_SUITE(coinbase_maturity_tests)

BOOST_AUTO_TEST_CASE(until_rdts_schedule_boundaries)
{
    const auto main{CChainParams::Main()};
    const auto& p{main->GetConsensus()};
    BOOST_CHECK_EQUAL(p.CoinbaseMaturityLongStartHeight, 973440);
    BOOST_CHECK_EQUAL(p.CoinbaseMaturityLongEnforceHeight, 973440);
    BOOST_CHECK_EQUAL(p.CoinbaseMaturityLongReleaseHeight, 979920);
    BOOST_CHECK(!p.CoinbaseMaturityLongActiveAt(973439, 0));
    for (const int height : {973440, 979919, 979920, 979921, 2000000, std::numeric_limits<int>::max()}) {
        BOOST_CHECK(p.CoinbaseMaturityLongActiveAt(height, 0));
        BOOST_CHECK_EQUAL(p.CoinbaseMaturityAt(973439, height, 0), 100);
        BOOST_CHECK_EQUAL(p.CoinbaseMaturityAt(973440, height, 0), 6480);
        BOOST_CHECK_EQUAL(p.CoinbaseMaturityAt(973441, height, 0), 6480);
    }
    for (const int height : {973440, 979919, 979920, 979921, 2000000}) {
        for (const int64_t mtp : {p.RdtsExpiryTime - 1, p.RdtsExpiryTime, p.RdtsExpiryTime + 1}) {
            BOOST_CHECK_EQUAL(p.CoinbaseMaturityLongAt(height, mtp), mtp < p.RdtsExpiryTime ? 6480 : 100);
            BOOST_CHECK_EQUAL(p.CoinbaseMaturityAt(973439, height, mtp), 100);
        }
    }
    const auto testnet4{CChainParams::TestNet4()};
    const auto& t{testnet4->GetConsensus()};
    BOOST_CHECK_EQUAL(t.CoinbaseMaturityLongAt(158110, 0), 6705);
    BOOST_CHECK_EQUAL(t.CoinbaseMaturityLongAt(158111, 0), 100);
    BOOST_CHECK_EQUAL(t.CoinbaseMaturityLongAt(2000000, 0), 100);
    for (const auto* chain : {main.get(), testnet4.get()}) {
        const auto& c{chain->GetConsensus()};
        BOOST_REQUIRE_EQUAL(c.chainstate_revalidation_deployments.size(), 1);
        const auto& d{c.chainstate_revalidation_deployments.front()};
        BOOST_CHECK_EQUAL(d.name, "long_coinbase_maturity");
        BOOST_CHECK_EQUAL(d.start_height, c.CoinbaseMaturityLongEnforceHeight);
        BOOST_CHECK_EQUAL(d.stop_height, chain == main.get() ? std::numeric_limits<int>::max() : 158110);
        BOOST_CHECK_EQUAL(d.stop_time, chain == main.get() ? c.RdtsExpiryTime : std::numeric_limits<int64_t>::max());
    }
    const auto testnet3{CChainParams::TestNet()};
    const auto signet{CChainParams::SigNet({})};
    const auto regtest{CChainParams::RegTest({})};
    for (const auto* chain : {testnet3.get(), signet.get(), regtest.get()}) {
        BOOST_CHECK_EQUAL(chain->GetConsensus().CoinbaseMaturityAt(1000, 1000000, 0), 100);
        BOOST_CHECK(chain->GetConsensus().chainstate_revalidation_deployments.empty());
    }
}

BOOST_AUTO_TEST_CASE(regtest_schedule)
{
    CChainParams::RegTestOptions options;
    options.coinbase_maturity_long_start_height = 10;
    options.coinbase_maturity_long_enforce_height = 20;
    options.coinbase_maturity_long_release_height = 150;
    const auto regtest{CChainParams::RegTest(options)};
    const auto& p{regtest->GetConsensus()};
    BOOST_CHECK_EQUAL(p.CoinbaseMaturityLongAt(19, 0), 100);
    BOOST_CHECK_EQUAL(p.CoinbaseMaturityLongAt(20, 0), 140);
    BOOST_CHECK_EQUAL(p.CoinbaseMaturityLongAt(149, 0), 140);
    BOOST_CHECK_EQUAL(p.CoinbaseMaturityLongAt(150, 0), 140);
    BOOST_CHECK_EQUAL(p.chainstate_revalidation_deployments.front().stop_height, std::numeric_limits<int>::max());
    options.coinbase_maturity_long_expiry_time = 1800000000;
    const auto expiring{CChainParams::RegTest(options)};
    BOOST_CHECK_EQUAL(expiring->GetConsensus().CoinbaseMaturityLongAt(150, 1799999999), 140);
    BOOST_CHECK_EQUAL(expiring->GetConsensus().CoinbaseMaturityLongAt(150, 1800000000), 100);
    BOOST_CHECK_EQUAL(expiring->GetConsensus().chainstate_revalidation_deployments.front().stop_time, 1800000000);
    options.coinbase_maturity_long_maturity = 6480;
    const auto synthetic{CChainParams::RegTest(options)};
    BOOST_CHECK_EQUAL(synthetic->GetConsensus().CoinbaseMaturityLongAt(20, 0), 6480);
}

BOOST_FIXTURE_TEST_CASE(until_rdts_input_depth_boundaries, BasicTestingSetup)
{
    const auto chain{CChainParams::Main()};
    const auto& p{chain->GetConsensus()};
    for (const int coin_height : {973439, 973440, 973441, 979919, 979920, 2000000}) {
        CCoinsView base;
        CCoinsViewCache coins{&base};
        const COutPoint prevout{Txid::FromUint256(uint256::ONE), 0};
        coins.AddCoin(prevout, Coin{CTxOut{10000, CScript{} << OP_TRUE}, coin_height, true}, false);
        CMutableTransaction tx;
        tx.vin.emplace_back(prevout);
        tx.vout.emplace_back(9000, CScript{} << OP_TRUE);
        for (const int64_t mtp : {p.RdtsExpiryTime - 1, p.RdtsExpiryTime, p.RdtsExpiryTime + 1}) {
            for (const int depth : {99, 100, 6479, 6480, 6481}) {
                const int height{coin_height + depth};
                const bool expected{depth >= (coin_height < 973440 || mtp >= p.RdtsExpiryTime ? 100 : 6480)};
                TxValidationState state;
                CAmount fee{0};
                BOOST_CHECK_EQUAL(Consensus::CheckTxInputs(CTransaction{tx}, state, coins, height, fee, CheckTxInputsRules::None,
                                                         p.CoinbaseMaturityLongAt(height, mtp), p.CoinbaseMaturityLongStartHeight), expected);
                if (expected) BOOST_CHECK_EQUAL(fee, 1000);
                else BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-premature-spend-of-coinbase");
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(testnet4_release_unchanged, BasicTestingSetup)
{
    const auto chain{CChainParams::TestNet4()};
    const auto& p{chain->GetConsensus()};
    CCoinsView base;
    CCoinsViewCache coins{&base};
    const COutPoint prevout{Txid::FromUint256(uint256::ONE), 0};
    coins.AddCoin(prevout, Coin{CTxOut{10000, CScript{} << OP_TRUE}, 151632, true}, false);
    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(9000, CScript{} << OP_TRUE);
    TxValidationState state;
    CAmount fee{0};
    // At depth 6479, #419 releases this testnet4 reward in block 158111.
    BOOST_CHECK(Consensus::CheckTxInputs(CTransaction{tx}, state, coins, 158111, fee, CheckTxInputsRules::None,
                                        p.CoinbaseMaturityLongAt(158111, 0), p.CoinbaseMaturityLongStartHeight));
    BOOST_CHECK_EQUAL(fee, 1000);
    BOOST_CHECK_EQUAL(p.chainstate_revalidation_deployments.front().stop_height, 158110);
}

BOOST_AUTO_TEST_SUITE_END()
