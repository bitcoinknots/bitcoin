// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stratum/stratum_messages.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

BOOST_AUTO_TEST_SUITE(stratum_messages_tests)

BOOST_AUTO_TEST_CASE(parse_submit_format)
{
    UniValue params(UniValue::VARR);
    params.push_back("worker");
    params.push_back("1");
    params.push_back("abcd1234");
    params.push_back("67abcdef");
    params.push_back("00112233");

    const auto req = stratum::ParseSubmitParams(params);
    BOOST_REQUIRE(req.has_value());
    BOOST_CHECK_EQUAL(req->worker_name, "worker");
    BOOST_CHECK_EQUAL(req->job_id, "1");
}

BOOST_AUTO_TEST_CASE(parse_submit_invalid)
{
    UniValue params(UniValue::VARR);
    params.push_back("worker");
    const auto req = stratum::ParseSubmitParams(params);
    BOOST_CHECK(!req.has_value());
}

BOOST_AUTO_TEST_SUITE_END()
