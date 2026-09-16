// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SHAREPOOL_RELAY_H
#define BITCOIN_SHAREPOOL_RELAY_H

#include <kernel/cs_main.h>
#include <primitives/block.h>
#include <serialize.h>
#include <span.h>
#include <threadsafety.h>
#include <uint256.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class ChainstateManager;

namespace sharepool {
inline constexpr uint8_t RELAY_TEMPLATE{1};
inline constexpr uint8_t RELAY_RECEIPT{2};
inline constexpr size_t MAX_RELAY_TEMPLATE{4'000'000};
inline constexpr size_t MAX_RELAY_RECEIPT{1024};
inline constexpr size_t MAX_RELAY_ITEMS{256};
inline constexpr size_t MAX_RELAY_BYTES{64 * 1024 * 1024};

struct RelayItem {
    uint8_t kind{0};
    uint256 id;
    SERIALIZE_METHODS(RelayItem, obj) { READWRITE(obj.kind, obj.id); }
    friend bool operator==(const RelayItem&, const RelayItem&) = default;
    friend bool operator<(const RelayItem& a, const RelayItem& b)
    {
        return a.kind != b.kind ? a.kind < b.kind : a.id < b.id;
    }
};

struct RelayObject {
    RelayItem item;
    uint256 pool;
    uint32_t origin_height{0};
    uint256 origin_parent;
    uint256 template_id;
    uint256 body_hash;
    std::vector<unsigned char> data;
};

/** Single SHA256 with RPC display order matching hashlib.sha256().hexdigest(). */
uint256 RelayDigest(Span<const unsigned char> bytes);
uint256 RelayTemplateId(const CBlockHeader& header);

/** Ephemeral transport cache. It never acknowledges miner work or selects validity.
 * The durable miner gate/archive is separate. All access requires cs_main.
 */
class RelayStore {
    uint256 m_pool GUARDED_BY(cs_main);
    uint64_t m_revision GUARDED_BY(cs_main){0};
    size_t m_bytes GUARDED_BY(cs_main){0};
    std::map<RelayItem, std::shared_ptr<const RelayObject>> m_objects GUARDED_BY(cs_main);
    bool Room(uint8_t kind, size_t size) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);

public:
    uint256 Pool() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_pool; }
    uint64_t Revision() const EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return m_revision; }
    bool Active(ChainstateManager& chainman) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool Configure(ChainstateManager& chainman, const uint256& pool, std::string& error) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void Prune(ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::vector<RelayItem> Inventory(ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool Has(ChainstateManager& chainman, uint8_t kind, const uint256& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::shared_ptr<const RelayObject> Get(ChainstateManager& chainman, uint8_t kind, const uint256& id) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::optional<RelayItem> Add(ChainstateManager& chainman, uint8_t kind, Span<const unsigned char> data,
                               std::string& error, std::optional<RelayItem> expected = std::nullopt) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
};
} // namespace sharepool
#endif // BITCOIN_SHAREPOOL_RELAY_H
