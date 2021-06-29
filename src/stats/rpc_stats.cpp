// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/util.h>
#include <stats/stats.h>
#include <util/system.h>
#include <util/strencodings.h>

#include <stdint.h>

#include <univalue.h>

UniValue getmempoolstats(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"getmempoolstats",
                "\nReturns the collected mempool statistics (non-linear non-interpolated samples).\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM_TIME, "time_from", "Timestamp, first sample"},
                        {RPCResult::Type::NUM_TIME, "time_to", "Timestamp, last sample"},
                        {RPCResult::Type::ARR, "samples", "",
                        {
                            {RPCResult::Type::ARR_FIXED, "", "",
                            {
                                {RPCResult::Type::NUM, "", "Sample time in seconds (relative to other sample times only)"},
                                {RPCResult::Type::NUM, "", "Number of transactions in the memory pool"},
                                {RPCResult::Type::NUM, "", "Memory usage by memory pool"},
                                {RPCResult::Type::NUM, "", "Minimum fee per kB"},
                            }},
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("getmempoolstats", "")
            + HelpExampleRpc("getmempoolstats", "")
                },
            }.ToString());
    }

    // get stats from the core stats model
    uint64_t timeFrom = 0;
    uint64_t timeTo = 0;
    mempoolSamples_t samples = CStats::DefaultStats()->mempoolGetValuesInRange(timeFrom, timeTo);

    // use "flat" json encoding for performance reasons
    UniValue samplesObj(UniValue::VARR);
    for (struct CStatsMempoolSample& sample : samples) {
        UniValue singleSample(UniValue::VARR);
        singleSample.push_back(UniValue((uint64_t)sample.m_time_delta));
        singleSample.push_back(UniValue(sample.m_tx_count));
        singleSample.push_back(UniValue(sample.m_dyn_mem_usage));
        singleSample.push_back(UniValue(sample.m_min_fee_per_k));
        samplesObj.push_back(singleSample);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("time_from", timeFrom);
    result.pushKV("time_to", timeTo);
    result.pushKV("samples", samplesObj);

    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                        actor (function)           argNames
    //  --------------------- ------------------------    -----------------------  ----------
    { "stats",              "getmempoolstats",          &getmempoolstats,          {} },
};

void RegisterStatsRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
