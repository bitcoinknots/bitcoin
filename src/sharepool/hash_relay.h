// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SHAREPOOL_HASH_RELAY_H
#define BITCOIN_SHAREPOOL_HASH_RELAY_H

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <utility>
#include <vector>
#include <uint256.h>

namespace sharepool {
/** Pace request service, not packet arrival. Network/scheduler delays can make
 * an honest sender's independently paced requests arrive with less spacing.
 * Keep one bounded pending request while credits refill instead of treating
 * local resource exhaustion as malformed input. The existing allowance is
 * unchanged: a burst of 32 services, then 32 services per second.
 * Duration credits avoid floating-point drift at the refill boundary. */
class HashRelayRequestBudget {
    using Clock = std::chrono::steady_clock;
    static constexpr auto CAPACITY{std::chrono::seconds{1}};
    static constexpr auto COST{std::chrono::microseconds{31'250}};
    Clock::time_point m_updated;
    Clock::duration m_credit{CAPACITY};

public:
    explicit HashRelayRequestBudget(Clock::time_point now = Clock::now()) : m_updated{now} {}

    /** Charge every response attempt, including unknown hashes/offsets. */
    bool Take(Clock::time_point now)
    {
        if (now > m_updated) {
            const auto elapsed = now - m_updated;
            m_credit = elapsed >= CAPACITY - m_credit ? CAPACITY : m_credit + elapsed;
            m_updated = now;
        }
        if (m_credit < COST) return false;
        m_credit -= COST;
        return true;
    }
};

/** Sequence-ordered live events may repeat a repaired hash. SPHINV itself
 * requires unique hashes in uint256 order, independently of cursor order. */
inline std::vector<uint256> CanonicalHashInventory(std::vector<uint256> hashes)
{
    std::sort(hashes.begin(), hashes.end());
    hashes.erase(std::unique(hashes.begin(), hashes.end()), hashes.end());
    return hashes;
}

/** FIFO turns among ready connections, with three required turns per ordinary
 * turn when both classes are continuously ready. Required data starts first;
 * ordinary advertisements cannot be starved by a permanently missing block.
 * A connection has at most one entry. Completing a turn removes it; more work
 * joins the tail. Callers remove disconnected, paused or otherwise unready
 * connections. This bounds overtaking among continuously ready connections;
 * it does not give an operator with many connections a single shared quota.
 */
class HashRelayTurns {
    std::deque<int64_t> m_required;
    std::deque<int64_t> m_advertised;
    unsigned m_required_run{0};

public:
    void Remove(int64_t peer)
    {
        std::erase(m_required, peer);
        std::erase(m_advertised, peer);
    }

    void Ready(int64_t peer, bool required)
    {
        auto& queue = required ? m_required : m_advertised;
        auto& other = required ? m_advertised : m_required;
        std::erase(other, peer);
        if (std::find(queue.begin(), queue.end(), peer) == queue.end()) queue.push_back(peer);
    }

    bool IsTurn(int64_t peer) const
    {
        const auto& queue = m_required.empty() || (!m_advertised.empty() && !PreferRequired()) ? m_advertised : m_required;
        return !queue.empty() && queue.front() == peer;
    }

    bool PreferRequired() const { return m_required_run < 3; }

    /** Charge a completed admission or issued request, never disconnection. */
    void Complete(int64_t peer)
    {
        if (std::find(m_required.begin(), m_required.end(), peer) != m_required.end()) {
            m_required_run = std::min(3U, m_required_run + 1);
        } else if (std::find(m_advertised.begin(), m_advertised.end(), peer) != m_advertised.end()) {
            m_required_run = 0;
        }
        Remove(peer);
    }

    size_t Size() const { return m_required.size() + m_advertised.size(); }
};

/** Paginate each store revision, then replay occasionally for peers whose
 * bounded receive queue dropped earlier advertisements. A revision arriving
 * mid-cycle causes another complete cycle, so insertions before the cursor
 * cannot permanently hide an object. No per-peer copy of the inventory.
 */
class HashRelayInventory {
    using Clock = std::chrono::steady_clock;
    std::optional<uint64_t> m_completed_revision;
    std::optional<uint64_t> m_cycle_revision;
    size_t m_offset{0};
    Clock::time_point m_next_page{};
    Clock::time_point m_next_replay{};

public:
    std::optional<std::pair<size_t, size_t>> Next(uint64_t revision, size_t count,
                                                size_t page_size, Clock::time_point now)
    {
        using namespace std::chrono_literals;
        if (now < m_next_page || page_size == 0) return std::nullopt;
        if (!m_cycle_revision) {
            if (m_completed_revision == revision && now < m_next_replay) return std::nullopt;
            m_cycle_revision = revision;
            m_offset = 0;
        }
        const size_t begin = std::min(m_offset, count);
        const size_t end = begin + std::min(page_size, count - begin);
        m_next_page = now + 1s;
        m_offset = end;
        if (end == count) {
            m_completed_revision = m_cycle_revision;
            m_cycle_revision.reset();
            m_next_replay = now + 60s;
        }
        if (begin == end) return std::nullopt;
        return std::pair{begin, end};
    }
};

/** Disk-index cursor: constant per-peer memory, regardless of archive length.
 * Finish an in-flight traversal before restarting for a changed revision, so
 * continual insertions cannot repeatedly starve the tail of the archive.
 */
class HashRelayArchiveCursor {
    using Clock = std::chrono::steady_clock;
    std::optional<uint64_t> m_completed_revision;
    std::optional<uint64_t> m_cycle_revision;
    std::optional<uint256> m_after;
    Clock::time_point m_next_page{};
    Clock::time_point m_next_replay{};

public:
    bool Ready(uint64_t revision, Clock::time_point now)
    {
        if (now < m_next_page) return false;
        if (!m_cycle_revision) {
            if (m_completed_revision == revision && now < m_next_replay) return false;
            m_cycle_revision = revision;
            m_after.reset();
        }
        return true;
    }
    std::optional<uint256> After() const { return m_after; }
    void Advance(std::optional<uint256> next, bool complete, Clock::time_point now)
    {
        using namespace std::chrono_literals;
        m_after = next;
        m_next_page = now + 1s;
        if (complete) {
            m_completed_revision = m_cycle_revision;
            m_cycle_revision.reset();
            m_next_replay = now + 60s;
        }
    }
};

/** Fair bounded live/archive announcements. Newly inserted lower-hash work
 * does not wait for an entire historical traversal, and continuous arrivals
 * cannot prevent the archive cursor from advancing. Both lanes share one
 * one-second page cadence, matching the receiver's control-message budget;
 * per-peer state is independent of archive length.
 */
class HashRelayInventoryLanes {
    using Clock = std::chrono::steady_clock;
    HashRelayArchiveCursor m_archive;
    uint64_t m_recent_after{0};
    Clock::time_point m_next_recent{};
    Clock::time_point m_next_inventory{};
    bool m_last_recent{false};

public:
    enum class Lane { None, Recent, Archive };
    Lane Next(uint64_t revision, uint64_t recent_latest, Clock::time_point now)
    {
        if (now < m_next_inventory) return Lane::None;
        const bool recent = recent_latest != m_recent_after && now >= m_next_recent;
        const bool archive = m_archive.Ready(revision, now);
        if (recent && (!archive || !m_last_recent)) {
            m_last_recent = true;
            return Lane::Recent;
        }
        if (archive) {
            m_last_recent = false;
            return Lane::Archive;
        }
        return Lane::None;
    }
    uint64_t RecentAfter() const { return m_recent_after; }
    std::optional<uint256> ArchiveAfter() const { return m_archive.After(); }
    void AdvanceRecent(uint64_t next, Clock::time_point now)
    {
        using namespace std::chrono_literals;
        m_recent_after = next;
        m_next_recent = now + 1s;
        m_next_inventory = now + 1s;
    }
    void AdvanceArchive(std::optional<uint256> next, bool complete, Clock::time_point now)
    {
        using namespace std::chrono_literals;
        m_archive.Advance(next, complete, now);
        m_next_inventory = now + 1s;
    }
};

/** Expiry is independent of send-buffer backpressure and incoming retries. */
template <typename Request>
void ExpireHashRelayRequest(std::optional<Request>& request, std::chrono::steady_clock::time_point now)
{
    if (request && request->deadline <= now) request.reset();
}

/** Keep exactly one request. Exact retries neither consume another slot nor
 * extend its original deadline; a conflicting unexpired request is malformed.
 * Shape and offset bounds must be checked before calling this helper. */
template <typename Request>
bool QueueHashRelayRequest(std::optional<Request>& pending, Request request, std::chrono::steady_clock::time_point now)
{
    ExpireHashRelayRequest(pending, now);
    if (pending) return pending->hash == request.hash && pending->offset == request.offset;
    pending.emplace(std::move(request));
    return true;
}
} // namespace sharepool
#endif // BITCOIN_SHAREPOOL_HASH_RELAY_H
