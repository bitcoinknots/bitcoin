// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <deploymentstatus.h>
#include <versionbits.h>

#include <limits>
#include <string>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(chainparams_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(purity_activation_height_mainnet)
{
    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
    const auto chainParams = CreateChainParams(args, ChainType::MAIN);
    BOOST_CHECK_EQUAL(chainParams->GetConsensus().nPurityActivationHeight, Consensus::MAINNET_PURITY_ACTIVATION_HEIGHT);
    BOOST_CHECK_EQUAL(chainParams->GetConsensus().nAsertAnchorHeight, Consensus::MAINNET_ASERT_ANCHOR_HEIGHT);
}

BOOST_AUTO_TEST_CASE(purity_activation_block_hash_pinned)
{
    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
    const auto chainParams = CreateChainParams(args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    const uint256 expected{"0000000000000000003ea74f4dafdda7ed4e02c4c1ccb9768e0ca4f9e1a35159"};
    BOOST_CHECK_EQUAL(consensus.hashPurityActivationBlock, expected);

    // The pin is a consensus rule evaluated from Consensus::Params alone; it
    // does not consult the (disableable) -checkpoints machinery.
    const int activation = consensus.nPurityActivationHeight;
    BOOST_CHECK(Consensus::PurityActivationBlockPermitted(activation, expected, consensus));

    // A real conflicting mainnet block at the same height must be rejected.
    const uint256 conflicting{"0000000000000000000121f7aa4329b9d040bde9eac2d49b5219e57742ccbc9d"};
    BOOST_CHECK(!Consensus::PurityActivationBlockPermitted(activation, conflicting, consensus));
    BOOST_CHECK(!Consensus::PurityActivationBlockPermitted(activation, uint256{}, consensus));

    // Other heights are unconstrained by the pin.
    BOOST_CHECK(Consensus::PurityActivationBlockPermitted(activation - 1, conflicting, consensus));
    BOOST_CHECK(Consensus::PurityActivationBlockPermitted(activation + 1, conflicting, consensus));
}

BOOST_AUTO_TEST_CASE(purity_activation_block_hash_unset_off_mainnet)
{
    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
    const auto chainParams = CreateChainParams(args, ChainType::REGTEST);
    const auto& consensus = chainParams->GetConsensus();
    BOOST_CHECK(consensus.hashPurityActivationBlock.IsNull());
    // Unset pin never constrains any block.
    BOOST_CHECK(Consensus::PurityActivationBlockPermitted(0, uint256{}, consensus));
    BOOST_CHECK(Consensus::PurityActivationBlockPermitted(Consensus::MAINNET_PURITY_ACTIVATION_HEIGHT, uint256{}, consensus));
}

BOOST_AUTO_TEST_CASE(purity_activation_height_ignored_off_mainnet)
{
    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
    const auto chainParams = CreateChainParams(args, ChainType::REGTEST);
    BOOST_CHECK_EQUAL(chainParams->GetConsensus().nPurityActivationHeight, std::numeric_limits<int>::max());
}

BOOST_AUTO_TEST_CASE(purity_activation_height_enables_rdts)
{
    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
    const auto chainParams = CreateChainParams(args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();
    VersionBitsCache versionbitscache;

    // Height 0 is below activation; BIP9 path is not ACTIVE for genesis.
    BOOST_CHECK(!DeploymentActiveAfter(nullptr, consensus, Consensus::DEPLOYMENT_REDUCED_DATA, versionbitscache));

    CBlockIndex tip;
    tip.nHeight = Consensus::MAINNET_PURITY_ACTIVATION_HEIGHT - 1; // next block is the Purity activation height
    tip.pprev = nullptr;
    // Permanent RDTS activates via Purity height before BIP9 is consulted.
    BOOST_CHECK(DeploymentActiveAfter(&tip, consensus, Consensus::DEPLOYMENT_REDUCED_DATA, versionbitscache));
}

BOOST_AUTO_TEST_SUITE_END()
