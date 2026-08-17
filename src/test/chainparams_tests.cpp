// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <deploymentstatus.h>
#include <util/fs.h>
#include <util/readwritefile.h>
#include <util/string.h>
#include <versionbits.h>

#include <limits>
#include <stdexcept>
#include <string>

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

BOOST_AUTO_TEST_CASE(purity_activation_height_minimum_is_after_anchor)
{
    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(m_args.GetDataDirBase()));
    args.ForceSetArg("-purityactivationheight", util::ToString(Consensus::MAINNET_ASERT_ANCHOR_HEIGHT + 1));
    const auto chainParams = CreateChainParams(args, ChainType::MAIN);
    BOOST_CHECK_EQUAL(chainParams->GetConsensus().nPurityActivationHeight, Consensus::MAINNET_ASERT_ANCHOR_HEIGHT + 1);
    BOOST_CHECK_EQUAL(chainParams->GetConsensus().nAsertAnchorHeight, Consensus::MAINNET_ASERT_ANCHOR_HEIGHT);
}

BOOST_AUTO_TEST_CASE(purity_activation_height_invalid)
{
    const auto reject = [](const std::string& value) {
        ArgsManager args;
        args.ForceSetArg("-purityactivationheight", value);
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::MAIN), std::runtime_error);
    };
    reject("-1");
    reject("0");
    reject("100");
    reject(util::ToString(Consensus::MAINNET_ASERT_ANCHOR_HEIGHT));
    reject("2147483647"); // INT_MAX
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
    const int activation_height = Consensus::MAINNET_ASERT_ANCHOR_HEIGHT + 1;
    args.ForceSetArg("-purityactivationheight", util::ToString(activation_height));
    const auto chainParams = CreateChainParams(args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();
    VersionBitsCache versionbitscache;

    // Height 0 is below activation; BIP9 path is not ACTIVE for genesis.
    BOOST_CHECK(!DeploymentActiveAfter(nullptr, consensus, Consensus::DEPLOYMENT_REDUCED_DATA, versionbitscache));

    CBlockIndex tip;
    tip.nHeight = activation_height - 1; // next block is the Purity activation height
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

BOOST_AUTO_TEST_CASE(purity_activation_height_lock_rejects_stale_below_anchor)
{
    const fs::path datadir = m_args.GetDataDirBase() / "purity_lock_too_low";
    fs::create_directories(datadir);
    const fs::path lock_path = datadir / "purity_activation_height";
    BOOST_CHECK(WriteBinaryFile(lock_path, "100\n"));

    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(datadir));
    BOOST_CHECK_THROW(ApplyPurityActivationHeightLock(args), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(purity_activation_height_lock_rejects_too_low_cli)
{
    const fs::path datadir = m_args.GetDataDirBase() / "purity_lock_cli_too_low";
    fs::create_directories(datadir);

    ArgsManager args;
    args.ForceSetArg("-datadir", fs::PathToString(datadir));
    args.ForceSetArg("-purityactivationheight", "100");
    BOOST_CHECK_THROW(ApplyPurityActivationHeightLock(args), std::runtime_error);
    BOOST_CHECK(!fs::exists(datadir / "purity_activation_height"));
}

BOOST_AUTO_TEST_CASE(purity_activation_height_lock_ignores_invalid_cli)
{
    const fs::path datadir = m_args.GetDataDirBase() / "purity_lock_ignore_invalid_cli";
    fs::create_directories(datadir);

    {
        ArgsManager args;
        args.ForceSetArg("-datadir", fs::PathToString(datadir));
        args.ForceSetArg("-purityactivationheight", "961636");
        ApplyPurityActivationHeightLock(args);
    }

    {
        ArgsManager args;
        args.ForceSetArg("-datadir", fs::PathToString(datadir));
        args.ForceSetArg("-purityactivationheight", "100");
        ApplyPurityActivationHeightLock(args);
        BOOST_CHECK_EQUAL(args.GetArg("-purityactivationheight", ""), "961636");
        const auto chainParams = CreateChainParams(args, ChainType::MAIN);
        BOOST_CHECK_EQUAL(chainParams->GetConsensus().nPurityActivationHeight, 961636);
    }
}

BOOST_AUTO_TEST_SUITE_END()
