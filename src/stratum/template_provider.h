// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_STRATUM_TEMPLATE_PROVIDER_H
#define BITCOIN_STRATUM_TEMPLATE_PROVIDER_H

#include <primitives/block.h>
#include <sync.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <chrono>

namespace interfaces {
class Mining;
class BlockTemplate;
}

namespace stratum {

enum class RefreshReason {
    NEW_PREVHASH,
    TEMPLATE_UPDATE_ONLY,
};

struct WorkTemplate {
    std::string prevhash;
    uint32_t version{0};
    uint32_t nbits{0};
    uint32_t ntime{0};
    int32_t height{0};
    int64_t coinbase_value{0};
    std::vector<uint256> merkle_branch;
    CBlock block;
    bool clean_jobs{true};
    std::shared_ptr<interfaces::BlockTemplate> block_template;
};

class TemplateProvider
{
public:
    explicit TemplateProvider(interfaces::Mining& mining);

    std::optional<WorkTemplate> Refresh(RefreshReason reason);
    std::optional<WorkTemplate> Current() const;

private:
    interfaces::Mining& m_mining;

    mutable Mutex m_mutex;
    std::optional<WorkTemplate> m_current GUARDED_BY(m_mutex);
    std::optional<uint256> m_last_tip_hash GUARDED_BY(m_mutex);
    std::chrono::steady_clock::time_point m_last_template_build GUARDED_BY(m_mutex){};
};

} // namespace stratum

#endif // BITCOIN_STRATUM_TEMPLATE_PROVIDER_H
