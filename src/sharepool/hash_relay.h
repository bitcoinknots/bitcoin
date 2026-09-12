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

namespace sharepool {
/** FIFO turns among ready connections, with required block data first.
 * A connection has at most one entry. Completing a turn removes it; more work
 * joins the tail. Callers remove disconnected, paused or otherwise unready
 * connections. This bounds overtaking among continuously ready connections;
 * it does not give an operator with many connections a single shared quota.
 */
class HashRelayTurns {
    std::deque<int64_t> m_required;
    std::deque<int64_t> m_advertised;

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
        const auto& queue = m_required.empty() ? m_advertised : m_required;
        return !queue.empty() && queue.front() == peer;
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

/** Expiry is independent of send-buffer backpressure and incoming retries. */
template <typename Request>
void ExpireHashRelayRequest(std::optional<Request>& request, std::chrono::steady_clock::time_point now)
{
    if (request && request->deadline <= now) request.reset();
}
} // namespace sharepool
#endif // BITCOIN_SHAREPOOL_HASH_RELAY_H
