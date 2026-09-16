// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SHAREPOOL_HASH_REQUESTS_H
#define BITCOIN_SHAREPOOL_HASH_REQUESTS_H

#include <algorithm>
#include <cstddef>
#include <deque>
#include <map>
#include <set>
#include <stdexcept>
#include <vector>

namespace sharepool {
/** Local fetch policy, never consensus validity. Every retained block owns a
 * reserved bounded dependency set. Unscoped hints share only unused capacity.
 * Requested hashes rotate to the tail, so one unavailable hash cannot retain
 * the front across peers. A new block's root precedes newly discovered children.
 * The owner serializes access and supplies its authenticated local Has lookup.
 * Small configurable bounds permit correctness tests without saturation loads.
 */
template <typename Id> class HashRequestQueue {
public:
    static constexpr size_t MAX_BLOCKS{16};
    static constexpr size_t REFERENCES_PER_BLOCK{256};
    static constexpr size_t MAX_REFERENCES{4096};
    static constexpr size_t MAX_HINTS{256};

private:
    struct Block { Id root; std::vector<Id> children; };
    const size_t m_max_blocks, m_per_block, m_total, m_max_hints;
    std::map<Id, Block> m_blocks;
    std::deque<Id> m_required, m_hints;

    size_t Reserved() const
    {
        size_t count{0};
        for (const auto& [id, block] : m_blocks) count += 1 + block.children.size();
        return count;
    }

public:
    explicit HashRequestQueue(size_t blocks = MAX_BLOCKS, size_t per_block = REFERENCES_PER_BLOCK,
                              size_t total = MAX_REFERENCES, size_t hints = MAX_HINTS)
        : m_max_blocks{blocks}, m_per_block{per_block}, m_total{total}, m_max_hints{hints}
    {
        if (!blocks || !per_block || per_block > total / blocks) throw std::invalid_argument("invalid hash request reservations");
    }

    template <typename Has> void Refresh(const Has& has)
    {
        std::vector<Id> roots, ordered;
        std::set<Id> wanted;
        for (const auto& [id, block] : m_blocks) {
            if (!has(block.root) && wanted.insert(block.root).second) roots.push_back(block.root);
        }
        // Interleave newly discovered children across block provenance.
        for (size_t index{0}; index + 1 < m_per_block; ++index) {
            for (const auto& [id, block] : m_blocks) {
                if (index < block.children.size() && !has(block.children[index]) &&
                    wanted.insert(block.children[index]).second) ordered.push_back(block.children[index]);
            }
        }
        std::erase_if(m_required, [&](const Id& id) { return !wanted.contains(id); });
        std::set<Id> queued(m_required.begin(), m_required.end());
        for (auto it = roots.rbegin(); it != roots.rend(); ++it) {
            if (queued.insert(*it).second) m_required.push_front(*it);
        }
        for (const auto& id : ordered) if (queued.insert(id).second) m_required.push_back(id);
        std::erase_if(m_hints, [&](const Id& id) { return has(id) || wanted.contains(id); });
        const size_t capacity = std::min(m_max_hints, m_total - Reserved());
        while (m_hints.size() > capacity) m_hints.pop_front();
    }

    template <typename Has> bool Track(const Id& block_id, const Id& root, const Has& has)
    {
        if (!m_blocks.contains(block_id) && m_blocks.size() >= m_max_blocks) return false;
        m_blocks.try_emplace(block_id, Block{root, {}});
        Refresh(has);
        return true;
    }

    template <typename Has> void Update(const Id& block_id, const std::vector<Id>& hashes, const Has& has)
    {
        const auto found = m_blocks.find(block_id);
        if (found == m_blocks.end()) return; // No untracked caller can pin data.
        auto& block = found->second;
        block.children.clear();
        std::set<Id> seen;
        for (const auto& hash : hashes) {
            if (hash == Id{} || hash == block.root || has(hash) || !seen.insert(hash).second) continue;
            if (block.children.size() + 1 >= m_per_block) break;
            block.children.push_back(hash);
        }
        Refresh(has); // Root metadata survives even an empty missing vector.
    }

    template <typename Has> void Forget(const Id& block_id, const Has& has)
    {
        m_blocks.erase(block_id);
        Refresh(has); // Retain dependencies still referenced by another block.
    }

    template <typename Has> void Hint(const std::vector<Id>& hashes, const Has& has)
    {
        Refresh(has);
        const size_t capacity = std::min(m_max_hints, m_total - Reserved());
        if (!capacity) return;
        const std::set<Id> required(m_required.begin(), m_required.end());
        for (const auto& hash : hashes) {
            if (hash == Id{} || has(hash) || required.contains(hash) ||
                std::find(m_hints.begin(), m_hints.end(), hash) != m_hints.end()) continue;
            if (m_hints.size() == capacity) m_hints.pop_front();
            m_hints.push_back(hash);
        }
    }

    void Requested(const Id& hash)
    {
        for (auto* queue : {&m_required, &m_hints}) {
            if (const auto found = std::find(queue->begin(), queue->end(), hash); found != queue->end()) {
                queue->erase(found);
                queue->push_back(hash);
            }
        }
    }

    std::vector<Id> Required() const { return {m_required.begin(), m_required.end()}; }
    std::vector<Id> Hints() const { return {m_hints.begin(), m_hints.end()}; }
    size_t Reservations() const { return Reserved(); }
    size_t Blocks() const { return m_blocks.size(); }
};
} // namespace sharepool
#endif // BITCOIN_SHAREPOOL_HASH_REQUESTS_H
