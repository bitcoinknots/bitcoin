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

// The expiry is a fixed date while the fork is a height. Whoever schedules
// the mainnet fork height must revisit the expiry: a fork later than this
// tripwire would leave RDTS with far less than the intended year, or (past
// the expiry date) never enforced at all.
BOOST_AUTO_TEST_CASE(rdts_mainnet_schedule)
{
    const auto mainnet{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    const Consensus::Params& c{mainnet->GetConsensus()};
    BOOST_CHECK_EQUAL(c.RdtsExpiryTime, 1819756800); // September 1st, 2027 00:00 UTC
    // 965664 was the last height the retired versionbits schedule could have
    // activated at, 52416 its active duration: the expiry above was chosen to
    // match that window, so a fork height past it needs a new expiry.
    BOOST_CHECK(c.Blake2bHeight == std::numeric_limits<int>::max() || c.Blake2bHeight < 965664 + 52416);
}

BOOST_AUTO_TEST_SUITE_END()
