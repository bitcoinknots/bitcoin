// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DATUM_H
#define BITCOIN_DATUM_H

#include <script/script.h>
#include <sync.h>
#include <util/fs.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

/**
 * Proof of Datum.
 *
 * This is not a consensus rule, and cannot be one. A block carries no record of
 * which mining protocol negotiated its template: a block built by a client that
 * picked its own transactions (in the spirit of Stratum V2 job negotiation, or
 * the DATUM protocol) and a block dictated whole by an upstream pool over bare
 * Stratum V1 are bit-for-bit indistinguishable once mined. Any scheme claiming
 * to tell them apart by inspecting the block itself would have every node
 * reach a different, unverifiable answer about the same data -- which is a
 * fork waiting to happen, not a consensus rule. So this lives entirely at the
 * node's own RPC/mining service boundary, as local policy over what one node
 * chooses to help build, never as a rule about which blocks are valid.
 *
 * What a node CAN observe about a connection asking it for mining work is how
 * that connection actually uses the service:
 *
 *   - A client doing its own template/transaction selection calls
 *     getblocktemplate repeatedly, and the blocks it goes on to submit show
 *     transaction sets that vary and overlap with this node's own mempool.
 *   - A bare protocol bridge relaying whatever an upstream pool already
 *     assembled typically never calls getblocktemplate at all, and the blocks
 *     it submits tend to reuse the same coinbase payout script over and over,
 *     because the pool -- not the connection -- decided both the template and
 *     who gets paid.
 *
 * That is a fingerprint, not a proof. It can be wrong in both directions: a
 * legitimate solo miner behind a caching proxy might look GBT-quiet, and nothing
 * stops a pool bridge from calling getblocktemplate it never uses. So the score
 * this module keeps is advisory, and the classification threshold is a policy
 * choice for whoever runs the node, not a claim of certainty.
 *
 * Because it can be wrong, and because an operator may learn some connection is
 * a bare pool relay through means this heuristic can't see at all (a public
 * disclosure, a support ticket, someone just telling them), a persistent manual
 * override list sits alongside the heuristic: an address can be flagged by
 * score, or flagged by hand, and both are recorded with a reason and survive a
 * restart. Either kind of flag does the same thing: this node stops handing
 * that connection block templates. It never refuses to relay an already-valid
 * submitted block over this, on principle -- a full node's job is to propagate
 * valid blocks regardless of what its operator thinks of who mined them, and
 * punishing that after the fact would only cost the network propagation time
 * for no one's benefit. What is being withheld is a voluntary service (this
 * node's help constructing a next block), not participation in the network.
 */

class JSONRPCRequest;

namespace node {

//! Strip the ":port" (or "]:port" for a bracketed IPv6 literal) from an
//! address string in the form produced by CService::ToStringAddrPort(), so a
//! caller reconnecting on a new ephemeral port is still recognised as the same
//! address. Returns the input unchanged if it doesn't look like host:port.
std::string StripDatumPort(const std::string& addr_port);

//! Running counters for one address's use of the mining RPC surface.
struct DatumPeerStats {
    int64_t gbt_calls{0};
    int64_t blocks_submitted{0};
    int64_t last_gbt_call_time{0};
    int64_t first_seen{0};
    //! How many of the recent submitted blocks (capped window) paid each
    //! coinbase output script, keyed by the raw script bytes.
    std::map<std::vector<unsigned char>, int64_t> coinbase_script_counts;
};

//! How this node currently reads one address's behaviour.
struct DatumVerdict {
    DatumPeerStats stats;
    //! Share (0-100) of this address's recent submitted blocks that reused its
    //! single most common coinbase output script.
    int coinbase_reuse_pct{0};
    //! True once blocks_submitted has crossed DATUM_MIN_SUBMISSIONS with
    //! essentially no getblocktemplate calls behind them: the profile of a
    //! bridge that only ever relays an already-built block.
    bool gbt_starved{false};
    //! True once coinbase_reuse_pct crosses DATUM_REUSE_THRESHOLD_PCT: the
    //! profile of a connection that never chooses its own payout, because an
    //! upstream pool already fixed it.
    bool coinbase_stale{false};
    //! gbt_starved || coinbase_stale. This is an opinion, not an enforcement
    //! decision: a handful of manually-submitted blocks sharing one payout
    //! script looks identical to this heuristic whether it came from a bare
    //! pool relay or from a debug script and a slow week, and low submission
    //! counts are exactly where that ambiguity is worst. See `flagged`.
    bool heuristic_match{false};
    //! True only if this node is actually refusing this address a template
    //! right now: either an operator called adddatumban directly, or
    //! -datumautoban is enabled and heuristic_match has held long enough to
    //! promote automatically. Never true from heuristic_match alone with
    //! auto-ban off, which is the default.
    bool flagged{false};
    //! Set when `flagged` came from a human decision (adddatumban, or
    //! reviewing an auto-ban) rather than being promoted automatically.
    bool manually_flagged{false};
};

//! A manual or heuristic-triggered entry in the persistent override list.
struct DatumBanEntry {
    std::string reason;
    int64_t time{0};
    //! "heuristic" or "manual", for display only.
    std::string source;
};

/**
 * Tracks mining-RPC usage per calling address and the persistent list of
 * addresses this node has stopped serving templates to, whether flagged
 * automatically or by hand. One instance per node (see NodeContext); safe for
 * concurrent RPC handlers.
 */
class DatumTracker
{
public:
    //! Thresholds are intentionally simple integers, not tunable weights, so
    //! an operator can read this file and know exactly what triggers a flag.
    //! Deliberately a fairly large sample: a false positive here is a real
    //! node getting locked out of GBT service on its own hardware, so the
    //! heuristic waits for a pattern sustained across many blocks rather than
    //! a handful, which any number of ordinary things (a debug script, a
    //! slow week, one-off manual submissions) can look like just as easily as
    //! an actual bare pool relay can.
    static constexpr int64_t DATUM_MIN_SUBMISSIONS{50};
    static constexpr int64_t DATUM_MIN_GBT_RATIO_PCT{25}; // gbt_calls >= 25% of blocks_submitted
    static constexpr int DATUM_REUSE_THRESHOLD_PCT{80};
    static constexpr size_t DATUM_COINBASE_WINDOW{50}; // recent blocks considered per address

    //! `auto_ban` controls whether crossing the thresholds above actually adds
    //! a persistent, enforced ban (source "heuristic") on its own. Off by
    //! default: the heuristic is always visible through GetVerdict either way,
    //! but with this off it never itself withholds service, it only ever
    //! informs an operator's own adddatumban decision.
    DatumTracker(fs::path ban_file, bool auto_ban);

    //! Record a getblocktemplate call from `addr` (already stripped of port).
    void RecordTemplateRequest(const std::string& addr) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Record a block submitted from `addr`, and re-run its classification.
    //! Returns the updated verdict, and adds a heuristic ban entry the moment
    //! the thresholds above are first crossed.
    DatumVerdict RecordSubmission(const std::string& addr, const CScript& coinbase_script) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Current verdict for `addr`, without recording anything.
    DatumVerdict GetVerdict(const std::string& addr) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Every address this node has ever recorded activity for.
    std::vector<std::string> GetTrackedAddresses() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Whether `addr` is currently refused template service, and why.
    std::optional<DatumBanEntry> IsBanned(const std::string& addr) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Add or replace a manual ban entry, persisted immediately.
    void AddManualBan(const std::string& addr, const std::string& reason) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Remove any ban (manual or heuristic) on `addr`. Returns false if there was none.
    bool RemoveBan(const std::string& addr) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Every currently banned address with its recorded reason.
    std::map<std::string, DatumBanEntry> ListBans() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    void Load() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void Save() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    DatumVerdict ComputeVerdict(const std::string& addr) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    const fs::path m_ban_file;
    const bool m_auto_ban;
    mutable Mutex m_mutex;
    std::map<std::string, DatumPeerStats> m_stats GUARDED_BY(m_mutex);
    std::map<std::string, DatumBanEntry> m_bans GUARDED_BY(m_mutex);
};

} // namespace node

#endif // BITCOIN_DATUM_H
