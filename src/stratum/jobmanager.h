// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_STRATUM_JOBMANAGER_H
#define BITCOIN_STRATUM_JOBMANAGER_H

#include <sync.h>
#include <univalue.h>

#include <cstdint>
#include <optional>
#include <string>

namespace stratum {

struct Job {
    std::string id;
    std::string prevhash;
    std::string coinbase1;
    std::string coinbase2;
    UniValue merkle_branches{UniValue::VARR};
    std::string version;
    std::string nbits;
    std::string ntime;
    bool clean_jobs{true};
};

class JobManager
{
public:
    JobManager(std::string payout_address, uint32_t share_difficulty);

    UniValue HandleSubscribe(const UniValue& id) const;
    UniValue HandleAuthorize() const;
    UniValue HandleSubmit(const UniValue& params) const;

    Job RefreshJob();
    std::optional<Job> CurrentJob() const;
    UniValue BuildNotify(const Job& job) const;

private:
    Job BuildSkeletonJob() const;

    const std::string m_payout_address;
    const uint32_t m_share_difficulty;

    mutable Mutex m_mutex;
    Job m_current_job GUARDED_BY(m_mutex);
    uint64_t m_next_job_id GUARDED_BY(m_mutex){1};
};

} // namespace stratum

#endif // BITCOIN_STRATUM_JOBMANAGER_H
