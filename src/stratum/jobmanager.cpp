// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stratum/jobmanager.h>

#include <tinyformat.h>
#include <util/strencodings.h>

namespace stratum {

JobManager::JobManager(TemplateProvider& template_provider, uint32_t extranonce2_size, const std::string& payout_address)
    : m_template_provider(template_provider), m_extranonce2_size(extranonce2_size), m_payout_address(payout_address)
{
}

std::string JobManager::NewJobId()
{
    return strprintf("%08x", m_next_job_id++);
}

std::optional<Job> JobManager::RefreshJobs(RefreshReason reason)
{
    auto tpl = m_template_provider.Refresh(reason);
    if (!tpl) return std::nullopt;

    Job job;
    LOCK(m_mutex);
    job.id = NewJobId();
    job.prevhash = uint256S(tpl->prevhash);
    job.coinb1 = "";
    job.coinb2 = "";
    job.merkle_branches = tpl->merkle_branch;
    job.version = tpl->version;
    job.nbits = tpl->nbits;
    job.ntime = tpl->ntime;
    job.clean_jobs = tpl->clean_jobs;
    job.height = tpl->height;
    job.block = tpl->block;
    job.block_template = tpl->block_template;

    m_current_job = job;
    m_jobs[job.id] = job;
    return m_current_job;
}

std::optional<Job> JobManager::CreateJobForSession(uint64_t session_id)
{
    LOCK(m_mutex);
    if (!m_current_job.has_value()) return std::nullopt;
    if (!m_extranonce1.contains(session_id)) {
        m_extranonce1.emplace(session_id, strprintf("%08x", session_id));
    }
    return m_current_job;
}

std::optional<Job> JobManager::GetJob(const std::string& job_id) const
{
    LOCK(m_mutex);
    if (const auto it = m_jobs.find(job_id); it != m_jobs.end()) return it->second;
    return std::nullopt;
}

std::string JobManager::GetSessionExtranonce1(uint64_t session_id)
{
    LOCK(m_mutex);
    if (!m_extranonce1.contains(session_id)) {
        m_extranonce1.emplace(session_id, strprintf("%08x", session_id));
    }
    return m_extranonce1.at(session_id);
}

UniValue JobManager::BuildNotify(const Job& job) const
{
    UniValue params(UniValue::VARR);
    params.push_back(job.id);
    params.push_back(job.prevhash.GetHex());
    params.push_back(job.coinb1);
    params.push_back(job.coinb2);

    UniValue branches(UniValue::VARR);
    for (const auto& branch : job.merkle_branches) branches.push_back(branch.GetHex());
    params.push_back(std::move(branches));

    params.push_back(strprintf("%08x", job.version));
    params.push_back(strprintf("%08x", job.nbits));
    params.push_back(strprintf("%08x", job.ntime));
    params.push_back(job.clean_jobs);

    UniValue payload(UniValue::VOBJ);
    payload.pushKV("id", UniValue{UniValue::VNULL});
    payload.pushKV("method", "mining.notify");
    payload.pushKV("params", std::move(params));
    return payload;
}

} // namespace stratum
