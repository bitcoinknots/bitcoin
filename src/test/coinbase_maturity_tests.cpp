// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(coinbase_maturity_tests, BasicTestingSetup)

// Only outputs created inside the window are covered, and coverage is fixed
// when the output is created.
BOOST_AUTO_TEST_CASE(maturity_covers_the_window_only)
{
    constexpr int START{1000};
    constexpr int END{2000};
    Consensus::Params params;
    params.CoinbaseMaturityLongStartHeight = START;
    params.CoinbaseMaturityLongEndHeight = END;

    const CoinbaseMaturity maturity{params.CoinbaseMaturityInForce()};
    BOOST_CHECK_EQUAL(maturity.Required(START - 1), COINBASE_MATURITY);
    BOOST_CHECK_EQUAL(maturity.Required(START), COINBASE_MATURITY_LONG);
    BOOST_CHECK_EQUAL(maturity.Required(END - 1), COINBASE_MATURITY_LONG);
    BOOST_CHECK_EQUAL(maturity.Required(END), COINBASE_MATURITY);
    BOOST_CHECK_EQUAL(maturity.Required(0), COINBASE_MATURITY);
    BOOST_CHECK_EQUAL(maturity.Required(std::numeric_limits<int>::max()), COINBASE_MATURITY);
}

// A schedule can never ask for less than the ordinary rule.
BOOST_AUTO_TEST_CASE(never_weaker_than_the_ordinary_rule)
{
    Consensus::Params params;
    params.CoinbaseMaturityLongStartHeight = 0;
    params.CoinbaseMaturityLongEndHeight = std::numeric_limits<int>::max();
    for (const int depth : {0, 1, COINBASE_MATURITY - 1, COINBASE_MATURITY, COINBASE_MATURITY_LONG}) {
        params.CoinbaseMaturityLong = depth;
        BOOST_CHECK(params.CoinbaseMaturityInForce().Required(0) >= COINBASE_MATURITY);
    }
}

// Unscheduled is the default, and a default-constructed value is the ordinary
// rule, which is what the chain-free callers pass.
BOOST_AUTO_TEST_CASE(unscheduled_is_inert)
{
    const Consensus::Params defaults{};
    for (const int height : {0, 1, 970650, std::numeric_limits<int>::max()}) {
        BOOST_CHECK_EQUAL(defaults.CoinbaseMaturityInForce().Required(height), COINBASE_MATURITY);
        BOOST_CHECK_EQUAL(CoinbaseMaturity{}.Required(height), COINBASE_MATURITY);
    }

    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        // Hold the params alive: GetConsensus() returns a reference into them.
        const auto params{CreateChainParams(*m_node.args, chain)};
        const Consensus::Params& consensus{params->GetConsensus()};
        BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLongStartHeight, std::numeric_limits<int>::max());
        BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityInForce().Required(970650), COINBASE_MATURITY);
    }
}

BOOST_AUTO_TEST_SUITE_END()
