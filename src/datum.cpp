// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <datum.h>

#include <logging.h>
#include <templatediversity.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>

#include <fstream>

namespace node {

std::string StripDatumPort(const std::string& addr_port)
{
    if (addr_port.empty()) return addr_port;
    if (addr_port.front() == '[') {
        const auto close{addr_port.find(']')};
        if (close != std::string::npos) return addr_port.substr(0, close + 1);
        return addr_port; // malformed; leave as-is rather than guess
    }
    const auto colon{addr_port.rfind(':')};
    if (colon == std::string::npos) return addr_port;
    return addr_port.substr(0, colon);
}

namespace {

template <typename Key>
void AddToWindow(std::deque<Key>& recent, std::map<Key, int64_t>& counts, const Key& key)
{
    recent.push_back(key);
    ++counts[key];
    if (recent.size() > DatumTracker::DATUM_COINBASE_WINDOW) {
        const auto it{counts.find(recent.front())};
        if (--it->second == 0) counts.erase(it);
        recent.pop_front();
    }
}

//! The most common key in a window, and its share (0-100) of the window.
template <typename Key>
std::pair<std::optional<Key>, int> Dominant(const std::map<Key, int64_t>& counts)
{
    std::optional<Key> best;
    int64_t best_count{0};
    int64_t total{0};
    for (const auto& [key, count] : counts) {
        total += count;
        if (count > best_count) {
            best = key;
            best_count = count;
        }
    }
    return {best, total > 0 ? int(best_count * 100 / total) : 0};
}

} // namespace

DatumTracker::DatumTracker(fs::path ban_file, bool auto_ban, const TemplateDiversityTracker* template_diversity,
                           std::set<std::string> allowed_structures)
    : m_ban_file{std::move(ban_file)},
      m_auto_ban{auto_ban},
      m_template_diversity{template_diversity},
      m_allowed_structures{std::move(allowed_structures)}
{
    LOCK(m_mutex);
    Load();
}

void DatumTracker::RecordTemplateRequest(const std::string& addr)
{
    LOCK(m_mutex);
    DatumPeerStats& stats{m_stats[addr]};
    if (stats.first_seen == 0) stats.first_seen = GetTime();
    ++stats.gbt_calls;
    stats.last_gbt_call_time = GetTime();
}

DatumVerdict DatumTracker::RecordSubmission(const std::string& addr, const CScript& coinbase_script, const std::string& structure_key)
{
    LOCK(m_mutex);
    DatumPeerStats& stats{m_stats[addr]};
    if (stats.first_seen == 0) stats.first_seen = GetTime();
    ++stats.blocks_submitted;

    AddToWindow(stats.recent_scripts, stats.coinbase_script_counts,
                std::vector<unsigned char>(coinbase_script.begin(), coinbase_script.end()));
    AddToWindow(stats.recent_structures, stats.structure_counts, structure_key);

    DatumVerdict verdict{ComputeVerdict(addr)};
    if (verdict.heuristic_match && !m_bans.contains(addr)) {
        std::vector<std::string> signals;
        if (verdict.gbt_starved) signals.emplace_back("too few getblocktemplate calls behind submitted blocks");
        if (verdict.coinbase_stale) signals.emplace_back("one payout script dominates recent submitted blocks");
        if (verdict.pool_structure_match) {
            signals.emplace_back(strprintf("submitted blocks share a template structure that built %d%% of recent network blocks",
                                           *verdict.structure_chain_share_pct));
        }
        const std::string reason{strprintf(
            "heuristic match: %s (gbt_calls=%d, blocks_submitted=%d, coinbase_reuse=%d%%, structure_reuse=%d%%)",
            util::Join(signals, "; "), verdict.stats.gbt_calls, verdict.stats.blocks_submitted,
            verdict.coinbase_reuse_pct, verdict.structure_reuse_pct)};
        if (m_auto_ban) {
            DatumBanEntry entry;
            entry.source = "heuristic";
            entry.time = GetTime();
            entry.reason = reason;
            m_bans[addr] = entry;
            Save();
            verdict.flagged = true;
            LogWarning("Proof of Datum: auto-banned %s: %s\n", addr, reason);
        } else {
            // Advisory only: visible via getdatuminfo, never enforced on its
            // own. An operator who agrees can promote it with adddatumban.
            LogDebug(BCLog::RPC, "Proof of Datum: %s matches the heuristic (%s) but -datumautoban is off, "
                                 "so nothing is being withheld from it automatically\n", addr, reason);
        }
    }
    return verdict;
}

DatumVerdict DatumTracker::ComputeVerdict(const std::string& addr) const
{
    DatumVerdict verdict;
    const auto it{m_stats.find(addr)};
    if (it != m_stats.end()) verdict.stats = it->second;
    // No early return here even if `addr` has no recorded activity at all: a
    // manual ban must apply to exactly that case, since it exists for
    // addresses the heuristic below has nothing to go on.

    verdict.coinbase_reuse_pct = Dominant(verdict.stats.coinbase_script_counts).second;
    const auto [structure, structure_pct] = Dominant(verdict.stats.structure_counts);
    verdict.structure_reuse_pct = structure_pct;
    if (structure) {
        verdict.dominant_structure = *structure;
        verdict.structure_allowed = m_allowed_structures.contains(*structure);
        if (m_template_diversity) {
            const auto share{m_template_diversity->GetChainStructureShare(*structure)};
            if (share.sample >= DATUM_MIN_CHAIN_SAMPLE) {
                verdict.structure_chain_share_pct = int(share.blocks * 100 / share.sample);
            }
        }
    }

    if (verdict.stats.blocks_submitted >= DatumTracker::DATUM_MIN_SUBMISSIONS) {
        const int64_t gbt_ratio_pct{(verdict.stats.gbt_calls * 100) / verdict.stats.blocks_submitted};
        verdict.gbt_starved = gbt_ratio_pct < DatumTracker::DATUM_MIN_GBT_RATIO_PCT;
        verdict.coinbase_stale = verdict.coinbase_reuse_pct >= DatumTracker::DATUM_REUSE_THRESHOLD_PCT;
        verdict.pool_structure_match = !verdict.structure_allowed &&
                                       verdict.structure_reuse_pct >= DatumTracker::DATUM_REUSE_THRESHOLD_PCT &&
                                       verdict.structure_chain_share_pct.value_or(0) >= DatumTracker::DATUM_POOL_STRUCTURE_SHARE_PCT;
    }
    verdict.heuristic_match = verdict.gbt_starved || verdict.coinbase_stale || verdict.pool_structure_match;

    // `flagged` reflects only what is actually being enforced right now: real
    // membership in the ban list, whether it got there by a human's own
    // adddatumban call or (only with -datumautoban) by the heuristic above.
    // heuristic_match on its own never withholds anything.
    const auto ban_it{m_bans.find(addr)};
    if (ban_it != m_bans.end()) {
        verdict.flagged = true;
        verdict.manually_flagged = (ban_it->second.source == "manual");
    }
    return verdict;
}

DatumVerdict DatumTracker::GetVerdict(const std::string& addr) const
{
    LOCK(m_mutex);
    return ComputeVerdict(addr);
}

std::vector<std::string> DatumTracker::GetTrackedAddresses() const
{
    LOCK(m_mutex);
    std::vector<std::string> addrs;
    for (const auto& [addr, stats] : m_stats) addrs.push_back(addr);
    return addrs;
}

std::optional<DatumBanEntry> DatumTracker::IsBanned(const std::string& addr) const
{
    LOCK(m_mutex);
    const auto it{m_bans.find(addr)};
    if (it == m_bans.end()) return std::nullopt;
    return it->second;
}

void DatumTracker::AddManualBan(const std::string& addr, const std::string& reason)
{
    LOCK(m_mutex);
    DatumBanEntry entry;
    entry.reason = reason;
    entry.time = GetTime();
    entry.source = "manual";
    m_bans[addr] = entry;
    Save();
}

bool DatumTracker::RemoveBan(const std::string& addr)
{
    LOCK(m_mutex);
    const bool erased{m_bans.erase(addr) > 0};
    if (erased) Save();
    return erased;
}

std::map<std::string, DatumBanEntry> DatumTracker::ListBans() const
{
    LOCK(m_mutex);
    return m_bans;
}

void DatumTracker::Load()
{
    if (!fs::exists(m_ban_file)) return;
    std::ifstream file{m_ban_file};
    if (!file.is_open()) {
        LogWarning("Proof of Datum: could not open %s for reading\n", fs::PathToString(m_ban_file));
        return;
    }
    UniValue val;
    const std::string contents{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    if (contents.empty() || !val.read(contents) || !val.isObject()) {
        LogWarning("Proof of Datum: %s does not contain valid JSON; starting with an empty list\n",
                  fs::PathToString(m_ban_file));
        return;
    }
    for (const std::string& addr : val.getKeys()) {
        const UniValue& entry_val{val[addr]};
        DatumBanEntry entry;
        entry.reason = entry_val["reason"].isStr() ? entry_val["reason"].get_str() : "";
        entry.source = entry_val["source"].isStr() ? entry_val["source"].get_str() : "manual";
        entry.time = entry_val["time"].isNum() ? entry_val["time"].getInt<int64_t>() : 0;
        m_bans[addr] = entry;
    }
    LogPrintf("Proof of Datum: loaded %d banned address(es) from %s\n", m_bans.size(), fs::PathToString(m_ban_file));
}

void DatumTracker::Save() const
{
    UniValue out(UniValue::VOBJ);
    for (const auto& [addr, entry] : m_bans) {
        UniValue entry_val(UniValue::VOBJ);
        entry_val.pushKV("reason", entry.reason);
        entry_val.pushKV("source", entry.source);
        entry_val.pushKV("time", entry.time);
        out.pushKV(addr, entry_val);
    }
    std::ofstream file{m_ban_file};
    if (!file.is_open()) {
        LogWarning("Proof of Datum: could not open %s for writing; ban list not saved\n", fs::PathToString(m_ban_file));
        return;
    }
    file << out.write(/*prettyIndent=*/2) << std::endl;
}

} // namespace node
