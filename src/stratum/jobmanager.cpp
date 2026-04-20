// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stratum/jobmanager.h>

#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>

#include <sstream>

namespace stratum {

namespace {
constexpr int EXTRANONCE2_SIZE{4};
} // namespace

JobManager::JobManager(std::string payout_address, uint32_t share_difficulty)
    : m_payout_address(std::move(payout_address)), m_share_difficulty(share_difficulty)
{
}

UniValue JobManager::HandleSubscribe(const UniValue& id) const
{
    UniValue subscriptions(UniValue::VARR);
    UniValue notify_sub(UniValue::VARR);
    notify_sub.push_back("mining.notify");
    notify_sub.push_back("knots-subscription");
    subscriptions.push_back(std::move(notify_sub));

    UniValue result(UniValue::VARR);
    result.push_back(std::move(subscriptions));
    result.push_back("00000000"); // extranonce1
    result.push_back(EXTRANONCE2_SIZE);

    UniValue response(UniValue::VOBJ);
    response.pushKV("id", id);
    response.pushKV("result", std::move(result));
    response.pushKV("error", UniValue{UniValue::VNULL});
    return response;
}

UniValue JobManager::HandleAuthorize() const
{
    UniValue response(UniValue::VOBJ);
    response.pushKV("result", true);
    response.pushKV("error", UniValue{UniValue::VNULL});
    return response;
}

UniValue JobManager::HandleSubmit(const UniValue& params) const
{
    UniValue response(UniValue::VOBJ);
    if (!params.isArray() || params.size() < 5) {
        UniValue err(UniValue::VARR);
        err.push_back(20);
        err.push_back("Invalid submit parameters");
        err.push_back(UniValue{UniValue::VNULL});
        response.pushKV("result", false);
        response.pushKV("error", std::move(err));
        return response;
    }

    // Skeleton implementation: accepts submissions matching current job id.
    const std::string submitted_job_id = params[1].get_str();
    bool accepted{false};
    {
        LOCK(m_mutex);
        accepted = submitted_job_id == m_current_job.id;
    }

    response.pushKV("result", accepted);
    if (!accepted) {
        UniValue err(UniValue::VARR);
        err.push_back(21);
        err.push_back("Job not found");
        err.push_back(UniValue{UniValue::VNULL});
        response.pushKV("error", std::move(err));
    } else {
        response.pushKV("error", UniValue{UniValue::VNULL});
    }
    return response;
}

Job JobManager::RefreshJob()
{
    LOCK(m_mutex);
    m_current_job = BuildSkeletonJob();
    m_current_job.id = util::ToString(m_next_job_id++);
    return m_current_job;
}

std::optional<Job> JobManager::CurrentJob() const
{
    LOCK(m_mutex);
    if (m_current_job.id.empty()) {
        return std::nullopt;
    }
    return m_current_job;
}

UniValue JobManager::BuildNotify(const Job& job) const
{
    UniValue params(UniValue::VARR);
    params.push_back(job.id);
    params.push_back(job.prevhash);
    params.push_back(job.coinbase1);
    params.push_back(job.coinbase2);
    params.push_back(job.merkle_branches);
    params.push_back(job.version);
    params.push_back(job.nbits);
    params.push_back(job.ntime);
    params.push_back(job.clean_jobs);

    UniValue payload(UniValue::VOBJ);
    payload.pushKV("id", UniValue{UniValue::VNULL});
    payload.pushKV("method", "mining.notify");
    payload.pushKV("params", std::move(params));
    return payload;
}

Job JobManager::BuildSkeletonJob() const
{
    Job job;
    job.prevhash = "0000000000000000000000000000000000000000000000000000000000000000";
    job.coinbase1 = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
    job.coinbase2 = strprintf("%s00000000", HexStr(m_payout_address));
    job.version = "20000000";
    job.nbits = "1d00ffff";

    std::stringstream ntime;
    ntime << std::hex << GetTime();
    job.ntime = ntime.str();

    UniValue branches(UniValue::VARR);
    job.merkle_branches = std::move(branches);
    job.clean_jobs = true;
    (void)m_share_difficulty;

    return job;
}

} // namespace stratum
