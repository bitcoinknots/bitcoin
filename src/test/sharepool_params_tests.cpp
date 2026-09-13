// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <chainparamsbase.h>
#include <common/args.h>
#include <consensus/params.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <stdexcept>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(sharepool_params_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(public_network_factory_rejects_test_override)
{
    ArgsManager args;
    SetupChainParamsBaseOptions(args);
    args.ForceSetArg("-sharepoolheight", "2");
    args.ForceSetArg("-testactivationheight", "blake2b@1");
    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET}) {
        BOOST_CHECK_THROW(CreateChainParams(args, chain), std::runtime_error);
    }
    BOOST_CHECK_EQUAL(CreateChainParams(args, ChainType::REGTEST)->GetConsensus().SharePoolHeight, 2);
}

BOOST_AUTO_TEST_CASE(command_line_parser_rejects_ambiguous_or_invalid_schedule)
{
    const std::vector<std::vector<std::string>> cases{
        {"-sharepoolheight=0", "-testactivationheight=blake2b@1"},
        {"-sharepoolheight=-1", "-testactivationheight=blake2b@1"},
        {"-sharepoolheight=2147483647", "-testactivationheight=blake2b@1"},
        {"-sharepoolheight=2"},
        {"-sharepoolheight=2", "-testactivationheight=blake2b@3"},
        {"-sharepoolheight=2", "-sharepoolheight=3", "-testactivationheight=blake2b@1"},
        {"-sharepoolheight=invalid", "-testactivationheight=blake2b@1"},
        {"-sharepoolheight", "-testactivationheight=blake2b@1"},
    };
    for (const auto& options : cases) {
        ArgsManager args;
        SetupChainParamsBaseOptions(args);
        std::vector<const char*> argv{"sharepool-params-test"};
        for (const auto& arg : options) argv.push_back(arg.c_str());
        std::string error;
        BOOST_REQUIRE(args.ParseParameters(argv.size(), argv.data(), error));
        BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    }
    ArgsManager args;
    SetupChainParamsBaseOptions(args);
    const char* argv[]{"sharepool-params-test", "-nosharepoolheight"};
    std::string error;
    BOOST_CHECK(!args.ParseParameters(2, argv, error));
}

BOOST_AUTO_TEST_CASE(hash_only_requires_explicit_regtest_native_schedule)
{
    ArgsManager args;
    SetupChainParamsBaseOptions(args);
    BOOST_CHECK(!CreateChainParams(args, ChainType::REGTEST)->GetConsensus().SharePoolHashOnly);
    args.ForceSetArg("-sharepoolhashonly", "1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    args.ForceSetArg("-sharepoolheight", "2");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    args.ForceSetArg("-testactivationheight", "blake2b@1");
    const auto hash_only = CreateChainParams(args, ChainType::REGTEST);
    BOOST_CHECK(hash_only->GetConsensus().SharePoolHashOnly);
    BOOST_CHECK_EQUAL(hash_only->GetConsensus().SharePoolHeight, 2);
    args.ForceSetArg("-sharepoolhashonly", "0");
    BOOST_CHECK(!CreateChainParams(args, ChainType::REGTEST)->GetConsensus().SharePoolHashOnly);
}

BOOST_AUTO_TEST_CASE(public_network_factory_rejects_hash_only_option)
{
    for (const std::string value : {"0", "1"}) {
        ArgsManager args;
        SetupChainParamsBaseOptions(args);
        args.ForceSetArg("-sharepoolhashonly", value);
        for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET}) {
            BOOST_CHECK_THROW(CreateChainParams(args, chain), std::runtime_error);
        }
    }
}

BOOST_AUTO_TEST_CASE(confirmed_ledger_is_explicit_and_regtest_only)
{
    ArgsManager args;
    SetupChainParamsBaseOptions(args);
    BOOST_CHECK(!CreateChainParams(args, ChainType::REGTEST)->GetConsensus().SharePoolAdmittedLedger);
    args.ForceSetArg("-sharepooladmittedledger", "1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    args.ForceSetArg("-sharepoolheight", "2");
    args.ForceSetArg("-testactivationheight", "blake2b@1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    args.ForceSetArg("-sharepoolhashonly", "1");
    BOOST_CHECK(CreateChainParams(args, ChainType::REGTEST)->GetConsensus().SharePoolAdmittedLedger);
    for (const std::string value : {"0", "1"}) {
        args.ForceSetArg("-sharepooladmittedledger", value);
        for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET}) {
            BOOST_CHECK_THROW(CreateChainParams(args, chain), std::runtime_error);
        }
    }
}

BOOST_AUTO_TEST_CASE(tides_is_explicit_and_separate_from_confirmed_ledger)
{
    ArgsManager args;
    SetupChainParamsBaseOptions(args);
    BOOST_CHECK(!CreateChainParams(args, ChainType::REGTEST)->GetConsensus().SharePoolTides);
    args.ForceSetArg("-sharepooltides", "1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    args.ForceSetArg("-sharepoolhashonly", "1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    args.ForceSetArg("-sharepoolheight", "2");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    args.ForceSetArg("-testactivationheight", "blake2b@1");
    const auto tides = CreateChainParams(args, ChainType::REGTEST);
    BOOST_CHECK(tides->GetConsensus().SharePoolTides);
    BOOST_CHECK(tides->GetConsensus().SharePoolHashOnly);
    BOOST_CHECK(!tides->GetConsensus().SharePoolAdmittedLedger);
    BOOST_CHECK_EQUAL(tides->GetConsensus().SharePoolHeight, 2);
    args.ForceSetArg("-sharepooladmittedledger", "1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    args.ForceSetArg("-sharepooltides", "0");
    const auto ledger = CreateChainParams(args, ChainType::REGTEST);
    BOOST_CHECK(ledger->GetConsensus().SharePoolAdmittedLedger);
    BOOST_CHECK(!ledger->GetConsensus().SharePoolTides);
    args.ForceSetArg("-sharepooladmittedledger", "0");
    const auto hash_only = CreateChainParams(args, ChainType::REGTEST);
    BOOST_CHECK(hash_only->GetConsensus().SharePoolHashOnly);
    BOOST_CHECK(!hash_only->GetConsensus().SharePoolTides);
    BOOST_CHECK(!hash_only->GetConsensus().SharePoolAdmittedLedger);
}

BOOST_AUTO_TEST_CASE(public_network_factory_rejects_tides_option_even_disabled)
{
    for (const std::string value : {"0", "1"}) {
        ArgsManager args;
        SetupChainParamsBaseOptions(args);
        args.ForceSetArg("-sharepooltides", value);
        for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET}) {
            BOOST_CHECK_THROW(CreateChainParams(args, chain), std::runtime_error);
        }
    }
}

BOOST_AUTO_TEST_CASE(kernel_tides_profile_enforces_schedule_and_profile_exclusion)
{
    CChainParams::RegTestOptions options;
    options.sharepool_tides = true;
    BOOST_CHECK_THROW(CChainParams::RegTest(options), std::runtime_error);
    options.sharepool_hash_only = true;
    BOOST_CHECK_THROW(CChainParams::RegTest(options), std::runtime_error);
    options.sharepool_height = 2;
    BOOST_CHECK_THROW(CChainParams::RegTest(options), std::runtime_error);
    options.activation_heights[Consensus::BuriedDeployment::DEPLOYMENT_BLAKE2B] = 1;
    BOOST_CHECK(CChainParams::RegTest(options)->GetConsensus().SharePoolTides);
    options.sharepool_admitted_ledger = true;
    BOOST_CHECK_THROW(CChainParams::RegTest(options), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(tides_command_line_flag_is_registered_and_public_defaults_stay_disabled)
{
    ArgsManager args;
    SetupChainParamsBaseOptions(args);
    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        BOOST_CHECK(!CreateChainParams(args, chain)->GetConsensus().SharePoolTides);
    }
    const char* argv[]{"sharepool-params-test", "-sharepooltides=1", "-sharepoolhashonly=1",
                       "-sharepoolheight=2", "-testactivationheight=blake2b@1"};
    std::string error;
    BOOST_REQUIRE(args.ParseParameters(5, argv, error));
    BOOST_CHECK(CreateChainParams(args, ChainType::REGTEST)->GetConsensus().SharePoolTides);
}

BOOST_AUTO_TEST_CASE(compact_tides_is_explicit_and_public_activation_is_rejected)
{
    ArgsManager args;
    SetupChainParamsBaseOptions(args);
    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        BOOST_CHECK(!CreateChainParams(args, chain)->GetConsensus().SharePoolCompactTides);
    }
    args.ForceSetArg("-sharepoolcompacttides", "1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    args.ForceSetArg("-sharepooltides", "1");
    args.ForceSetArg("-sharepoolhashonly", "1");
    args.ForceSetArg("-sharepoolheight", "2");
    args.ForceSetArg("-testactivationheight", "blake2b@1");
    const auto compact = CreateChainParams(args, ChainType::REGTEST);
    BOOST_CHECK(compact->GetConsensus().SharePoolCompactTides);
    BOOST_CHECK(compact->GetConsensus().SharePoolTides);
    BOOST_CHECK(!compact->GetConsensus().SharePoolAdmittedLedger);
    args.ForceSetArg("-sharepooladmittedledger", "1");
    BOOST_CHECK_THROW(CreateChainParams(args, ChainType::REGTEST), std::runtime_error);
    for (const std::string value : {"0", "1"}) {
        args.ForceSetArg("-sharepoolcompacttides", value);
        for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET}) {
            BOOST_CHECK_THROW(CreateChainParams(args, chain), std::runtime_error);
        }
    }
    CChainParams::RegTestOptions options;
    options.sharepool_compact_tides = true;
    BOOST_CHECK_THROW(CChainParams::RegTest(options), std::runtime_error);
    options.sharepool_tides = true;
    options.sharepool_hash_only = true;
    options.sharepool_height = 2;
    options.activation_heights[Consensus::BuriedDeployment::DEPLOYMENT_BLAKE2B] = 1;
    BOOST_CHECK(CChainParams::RegTest(options)->GetConsensus().SharePoolCompactTides);
}

BOOST_AUTO_TEST_SUITE_END()
