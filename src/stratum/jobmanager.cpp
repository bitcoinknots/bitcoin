// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <uint256.h>
#include <stratum/jobmanager.h>

#include <logging.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/strencodings.h>

namespace stratum {
namespace {
std::pair<std::string, std::string> BuildCoinbaseParts(const CBlock& block, size_t extranonce_size)
{
    CMutableTransaction coinbase{*block.vtx.at(0)};
    assert(!coinbase.vin.empty());
    // Placeholder must be exactly extranonce1 + extranonce2 size.
    // The miner inserts extranonce1 (4 bytes) + extranonce2, so do not
    // double this length or the scriptSig length/push opcode becomes wrong.
    std::vector<unsigned char> marker(extranonce_size, 0x33);
    coinbase.vin[0].scriptSig = CScript() << marker;
    const CTransaction tx{coinbase};
    DataStream serialized_coinbase;
    serialized_coinbase << TX_NO_WITNESS(tx);
    const std::string coinbase_hex = HexStr(serialized_coinbase);
    const std::string marker_hex = HexStr(marker);
    const size_t marker_offset = coinbase_hex.find(marker_hex);
    assert(marker_offset != std::string::npos);
    return {coinbase_hex.substr(0, marker_offset), coinbase_hex.substr(marker_offset + marker_hex.size())};
}

std::string ReverseHexBytes(const std::string& hex)
{
    if (hex.size() % 2 != 0) return hex;
    std::string out;
    out.reserve(hex.size());
    for (size_t i = hex.size(); i > 0; i -= 2) {
        out.append(hex, i - 2, 2);
    }
    return out;
}

std::string StratumHashHex(const uint256& hash)
{
    return ReverseHexBytes(hash.GetHex());
}


std::string SwapHexWordBytes(const std::string& hex)
{
    if (hex.size() % 8 != 0) return hex;
    std::string out;
    out.reserve(hex.size());
    for (size_t i = 0; i < hex.size(); i += 8) {
        out.append(hex, i + 6, 2);
        out.append(hex, i + 4, 2);
        out.append(hex, i + 2, 2);
        out.append(hex, i + 0, 2);
    }
    return out;
}

std::string StratumPrevHashHex(const uint256& hash)
{
    // ESP-Miner / Bitaxe applies reverse_endianness_per_word() to prevhash.
    // Send prevhash pre-swapped per 32-bit word so the miner hashes the
    // real Bitcoin header prevhash bytes.
    return SwapHexWordBytes(StratumHashHex(hash));
}

} // namespace

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

    auto prevhash = uint256::FromHex(tpl->prevhash);
    if (!prevhash) return std::nullopt;

    LOCK(m_mutex);
    if (m_current_job.has_value()) {
        const Job& current = *m_current_job;
        const bool unchanged =
            current.prevhash == *prevhash &&
            current.version == tpl->version &&
            current.nbits == tpl->nbits &&
            current.ntime == tpl->ntime &&
            current.height == tpl->height &&
            current.merkle_branches == tpl->merkle_branch;
        if (unchanged) {
            LogPrintf("Stratum job refresh decision: built=0 reason=template-unchanged job_id=%s\n", current.id);
            return m_current_job;
        }
    }

    Job job;
    job.id = NewJobId();
    job.prevhash = *prevhash;
    const size_t extranonce_size = 4 + m_extranonce2_size;
    const auto [coinb1, coinb2] = BuildCoinbaseParts(tpl->block, extranonce_size);
    job.coinb1 = coinb1;
    job.coinb2 = coinb2;
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
    LogPrintf("Stratum job refresh decision: built=1 reason=%s job_id=%s prevhash=%s height=%d clean_jobs=%d\n",
              reason == RefreshReason::NEW_PREVHASH ? "new-prevhash" : "template-update",
              job.id,
              job.prevhash.GetHex(),
              job.height,
              job.clean_jobs);
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

std::optional<Job> JobManager::CurrentJob() const
{
    LOCK(m_mutex);
    return m_current_job;
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
    params.push_back(StratumPrevHashHex(job.prevhash));
    params.push_back(job.coinb1);
    params.push_back(job.coinb2);

    UniValue branches(UniValue::VARR);
    for (const auto& branch : job.merkle_branches) branches.push_back(StratumHashHex(branch));
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
