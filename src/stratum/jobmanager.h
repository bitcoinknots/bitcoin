// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_STRATUM_JOBMANAGER_H
#define BITCOIN_STRATUM_JOBMANAGER_H

#include <stratum/session.h>
#include <stratum/template_provider.h>

#include <primitives/block.h>
#include <sync.h>
#include <univalue.h>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace interfaces {
class BlockTemplate;
}

namespace stratum {

struct Job {
    std::string id;
    uint256 prevhash;
    std::string coinb1;
    std::string coinb2;
    std::vector<uint256> merkle_branches;
    uint32_t version{0};
    uint32_t nbits{0};
    uint32_t ntime{0};
    bool clean_jobs{true};
    int32_t height{0};
    CBlock block;
    std::shared_ptr<interfaces::BlockTemplate> block_template;
};

class JobManager
{
public:
    JobManager(TemplateProvider& template_provider, uint32_t extranonce2_size, const std::string& payout_address);

    std::optional<Job> RefreshJobs(RefreshReason reason);
    std::optional<Job> CreateJobForSession(uint64_t session_id);
    std::optional<Job> GetJob(const std::string& job_id) const;
    std::optional<Job> CurrentJob() const;

    std::string GetSessionExtranonce1(uint64_t session_id);
    UniValue BuildNotify(const Job& job) const;

private:
    std::string NewJobId();

    TemplateProvider& m_template_provider;
    const uint32_t m_extranonce2_size;
    const std::string m_payout_address;

    mutable Mutex m_mutex;
    std::optional<Job> m_current_job GUARDED_BY(m_mutex);
    std::unordered_map<std::string, Job> m_jobs GUARDED_BY(m_mutex);
    std::unordered_map<uint64_t, std::string> m_extranonce1 GUARDED_BY(m_mutex);
    uint64_t m_next_job_id GUARDED_BY(m_mutex){1};
};

} // namespace stratum

#endif // BITCOIN_STRATUM_JOBMANAGER_H
