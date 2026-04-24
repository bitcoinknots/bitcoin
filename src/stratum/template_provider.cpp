// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stratum/template_provider.h>

#include <interfaces/mining.h>
#include <logging.h>

namespace stratum {

TemplateProvider::TemplateProvider(interfaces::Mining& mining) : m_mining(mining) {}

std::optional<WorkTemplate> TemplateProvider::Refresh(RefreshReason reason)
{
    static constexpr auto MEMPOOL_REFRESH_INTERVAL = std::chrono::seconds{30};
    const auto now = std::chrono::steady_clock::now();
    const auto tip = m_mining.getTip();
    const std::optional<uint256> tip_hash = tip.has_value() ? std::make_optional(tip->hash) : std::nullopt;

    bool should_rebuild{false};
    bool clean_jobs{false};
    const char* refresh_why{"timer-only-cache-hit"};
    std::optional<WorkTemplate> cached;
    {
        LOCK(m_mutex);
        cached = m_current;
        if (!m_current.has_value()) {
            should_rebuild = true;
            clean_jobs = true;
            refresh_why = "initial-job";
        } else if (reason == RefreshReason::NEW_PREVHASH) {
            should_rebuild = true;
            clean_jobs = true;
            refresh_why = "new-prevhash";
        } else if (tip_hash.has_value() && m_last_tip_hash.has_value() && *tip_hash != *m_last_tip_hash) {
            should_rebuild = true;
            clean_jobs = true;
            refresh_why = "tip-changed";
        } else if (reason == RefreshReason::TEMPLATE_UPDATE_ONLY) {
            if ((now - m_last_template_build) >= MEMPOOL_REFRESH_INTERVAL) {
                should_rebuild = true;
                clean_jobs = false;
                refresh_why = "mempool-refresh-interval";
            }
        }
    }

    if (!should_rebuild) {
        LogPrintf("Stratum template refresh decision: built=0 reason=%s\n", refresh_why);
        return cached;
    }

    auto block_template = m_mining.createNewBlock();
    if (!block_template) {
        LogPrintf("Stratum template refresh decision: built=0 reason=%s (createNewBlock failed)\n", refresh_why);
        return std::nullopt;
    }

    WorkTemplate wt;
    const CBlock& block = block_template->getBlock();
    wt.prevhash = block.hashPrevBlock.GetHex();
    wt.version = block.nVersion;
    wt.nbits = block.nBits;
    wt.ntime = block.nTime;
    wt.height = tip.has_value() ? tip->height + 1 : 0;
    wt.coinbase_value = block.vtx.at(0)->GetValueOut();
    wt.merkle_branch = block_template->getCoinbaseMerklePath();
    wt.block = block;
    wt.clean_jobs = clean_jobs;
    wt.block_template = std::shared_ptr<interfaces::BlockTemplate>(std::move(block_template));

    LOCK(m_mutex);
    m_current = wt;
    m_last_tip_hash = block.hashPrevBlock;
    m_last_template_build = now;
    LogPrintf("Stratum template refresh decision: built=1 reason=%s prevhash=%s height=%d clean_jobs=%d\n", refresh_why, wt.prevhash, wt.height, wt.clean_jobs);
    return m_current;
}

std::optional<WorkTemplate> TemplateProvider::Current() const
{
    LOCK(m_mutex);
    return m_current;
}

} // namespace stratum
