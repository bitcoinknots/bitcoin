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

BOOST_AUTO_TEST_SUITE_END()
