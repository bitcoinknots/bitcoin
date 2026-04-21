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
    auto block_template = m_mining.createNewBlock();
    if (!block_template) return std::nullopt;

    WorkTemplate wt;
    const CBlock& block = block_template->getBlock();
    wt.prevhash = block.hashPrevBlock.GetHex();
    wt.version = block.nVersion;
    wt.nbits = block.nBits;
    wt.ntime = block.nTime;
    wt.height = m_mining.getTip().has_value() ? m_mining.getTip()->height + 1 : 0;
    wt.coinbase_value = block.vtx.at(0)->GetValueOut();
    wt.merkle_branch = block_template->getCoinbaseMerklePath();
    wt.block = block;
    wt.clean_jobs = reason == RefreshReason::NEW_PREVHASH;
    wt.block_template = std::shared_ptr<interfaces::BlockTemplate>(std::move(block_template));

    LOCK(m_mutex);
    m_current = wt;
    return m_current;
}

std::optional<WorkTemplate> TemplateProvider::Current() const
{
    LOCK(m_mutex);
    return m_current;
}

} // namespace stratum
