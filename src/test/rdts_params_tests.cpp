// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/params.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(rdts_params_tests, BasicTestingSetup)

// RDTS applies to exactly the blocks from the BLAKE2b fork height whose
// parent's median-time-past is below the expiry: pin both boundaries.
BOOST_AUTO_TEST_CASE(rdts_active_at_boundaries)
{
    constexpr int H{1000};
    constexpr int64_t T{2'000'000'000};
    Consensus::Params params;
    params.Blake2bHeight = H;
    params.RdtsExpiryTime = T;

    for (const int height : {H - 1, H, H + 1}) {
        for (const int64_t mtp : {T - 1, T, T + 1}) {
            BOOST_CHECK_EQUAL(params.RdtsActiveAt(height, mtp), height >= H && mtp < T);
        }
    }
    BOOST_CHECK(params.RdtsActiveAt(std::numeric_limits<int>::max(), T - 1));
    BOOST_CHECK(!params.RdtsActiveAt(H, std::numeric_limits<int64_t>::max()));
    BOOST_CHECK(params.RdtsActiveAt(H, std::numeric_limits<int64_t>::min()));

    // Unscheduled fork height: never active, whatever the expiry.
    params.Blake2bHeight = std::numeric_limits<int>::max();
    BOOST_CHECK(!params.RdtsActiveAt(std::numeric_limits<int>::max() - 1, T - 1));
    BOOST_CHECK(params.RdtsActiveAt(std::numeric_limits<int>::max(), T - 1));

    // Unscheduled expiry (the default): never active, whatever the height.
    params.Blake2bHeight = H;
    params.RdtsExpiryTime = std::numeric_limits<int64_t>::min();
    BOOST_CHECK(!params.RdtsActiveAt(H, std::numeric_limits<int64_t>::min()));
    BOOST_CHECK(!params.RdtsActiveAt(H, 0));
    BOOST_CHECK(!params.RdtsActiveAt(std::numeric_limits<int>::max(), 0));
}

// Mainnet RDTS continues: no expiry, at any parent median-time-past.
BOOST_AUTO_TEST_CASE(rdts_mainnet_schedule)
{
    const auto mainnet{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    const Consensus::Params& c{mainnet->GetConsensus()};
    BOOST_CHECK_EQUAL(c.RdtsExpiryTime, std::numeric_limits<int64_t>::max());
    if (c.Blake2bHeight != std::numeric_limits<int>::max()) {
        for (const int64_t mtp : {int64_t{0}, int64_t{1819756799}, int64_t{1819756800}, int64_t{4102444800}, std::numeric_limits<int64_t>::max() - 1}) {
            BOOST_CHECK(c.RdtsActiveAt(c.Blake2bHeight, mtp));
            BOOST_CHECK(c.RdtsActiveAt(c.Blake2bHeight + 1000000, mtp));
        }
        BOOST_CHECK(!c.RdtsActiveAt(c.Blake2bHeight - 1, 0));
    }
}

BOOST_AUTO_TEST_SUITE_END()
