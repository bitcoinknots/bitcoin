// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <deploymentstatus.h>
#include <util/fs.h>
#include <versionbits.h>

#include <limits>
#include <stdexcept>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(chainparams_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(purity_activation_height_default)
{
    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
    const auto chainParams = CreateChainParams(args, ChainType::MAIN);
    BOOST_CHECK_EQUAL(chainParams->GetConsensus().nPurityActivationHeight, std::numeric_limits<int>::max());
}

BOOST_AUTO_TEST_CASE(purity_activation_height_from_arg)
{
    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
    args.ForceSetArg("-purityactivationheight", "961636");
    const auto chainParams = CreateChainParams(args, ChainType::MAIN);
    BOOST_CHECK_EQUAL(chainParams->GetConsensus().nPurityActivationHeight, 961636);
}

BOOST_AUTO_TEST_CASE(purity_activation_height_invalid)
{
    {
        ArgsManager args;
        args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
        args.ForceSetArg("-purityactivationheight", "-1");
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::MAIN), std::runtime_error);
    }
    {
        ArgsManager args;
        args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
        args.ForceSetArg("-purityactivationheight", "2147483647"); // INT_MAX
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::MAIN), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(purity_activation_height_ignored_off_mainnet)
{
    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
    args.ForceSetArg("-purityactivationheight", "961636");
    const auto chainParams = CreateChainParams(args, ChainType::REGTEST);
    BOOST_CHECK_EQUAL(chainParams->GetConsensus().nPurityActivationHeight, std::numeric_limits<int>::max());
}

BOOST_AUTO_TEST_CASE(purity_activation_height_enables_rdts)
{
    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
    args.ForceSetArg("-purityactivationheight", "100");
    const auto chainParams = CreateChainParams(args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();
    VersionBitsCache versionbitscache;

    // Height 0 is below activation; BIP9 path is not ACTIVE for genesis.
    BOOST_CHECK(!DeploymentActiveAfter(nullptr, consensus, Consensus::DEPLOYMENT_REDUCED_DATA, versionbitscache));

    CBlockIndex tip;
    tip.nHeight = 99; // next block is 100
    tip.pprev = nullptr;
    // Permanent RDTS activates via Purity height before BIP9 is consulted.
    BOOST_CHECK(DeploymentActiveAfter(&tip, consensus, Consensus::DEPLOYMENT_REDUCED_DATA, versionbitscache));
}

BOOST_AUTO_TEST_CASE(purity_activation_height_lock_persists)
{
    const fs::path datadir = m_args.GetDataDirBase() / "purity_lock_persist";
    fs::create_directories(datadir);

    {
        ArgsManager args;
        args.ForceSetArg("-datadir", fs::PathToString(datadir));
        args.ForceSetArg("-purityactivationheight", "961636");
        ApplyPurityActivationHeightLock(args);
        const auto chainParams = CreateChainParams(args, ChainType::MAIN);
        BOOST_CHECK_EQUAL(chainParams->GetConsensus().nPurityActivationHeight, 961636);
        BOOST_CHECK(fs::exists(datadir / "purity_activation_height"));
    }

    // Relock with a different CLI value: locked height wins.
    {
        ArgsManager args;
        args.ForceSetArg("-datadir", fs::PathToString(datadir));
        args.ForceSetArg("-purityactivationheight", "999999");
        ApplyPurityActivationHeightLock(args);
        BOOST_CHECK_EQUAL(args.GetArg("-purityactivationheight", ""), "961636");
        const auto chainParams = CreateChainParams(args, ChainType::MAIN);
        BOOST_CHECK_EQUAL(chainParams->GetConsensus().nPurityActivationHeight, 961636);
    }

    // Restart without the CLI arg: still uses the locked height.
    {
        ArgsManager args;
        args.ForceSetArg("-datadir", fs::PathToString(datadir));
        ApplyPurityActivationHeightLock(args);
        const auto chainParams = CreateChainParams(args, ChainType::MAIN);
        BOOST_CHECK_EQUAL(chainParams->GetConsensus().nPurityActivationHeight, 961636);
    }
}

BOOST_AUTO_TEST_SUITE_END()
