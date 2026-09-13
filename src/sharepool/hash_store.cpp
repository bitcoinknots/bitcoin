// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <sharepool/hash_store.h>

#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <hash.h>
#include <streams.h>
#include <util/strencodings.h>
#include <validation.h>

#include <algorithm>

namespace sharepool {
namespace {
constexpr size_t MAX_STORED_BYTES{1024ULL * 1024 * 1024};
constexpr size_t MAX_STORED_OBJECTS{65536};
constexpr size_t MAX_CACHE_BYTES{64 * 1024 * 1024};
constexpr size_t MAX_PENDING_BYTES{64 * 1024 * 1024};
constexpr size_t MAX_PENDING_BLOCKS{HashRequestQueue<uint256>::MAX_BLOCKS};
constexpr size_t MAX_TEMPLATE_INDEX{65536};
constexpr size_t MAX_TEMPLATE_SOURCES{4};
constexpr size_t MAX_LOCAL_TEMPLATE_BYTES{256 * 1024 * 1024};
constexpr size_t MAX_LOCAL_TRANSACTIONS{262144};
struct BoundedBytes {
    std::vector<unsigned char> data;
    template <typename Stream> void Serialize(Stream& s) const { s << data; }
    template <typename Stream> void Unserialize(Stream& s) { ReadBoundedVector(s, data, hashonly::MAX_SNAPSHOT_BYTES); }
};
struct StoredTemplate {
    CBlockHeader header;
    std::vector<Wtxid> transactions;
    uint256 body_hash;
    template <typename Stream> void Serialize(Stream& s) const { s << header << transactions << body_hash; }
    template <typename Stream> void Unserialize(Stream& s)
    {
        s >> header;
        ReadBoundedVector(s, transactions, hashonly::MAX_TEMPLATE_BYTES / 10);
        s >> body_hash;
    }
};
/** Record its actual serialized storage size even if decoding fails. No
 * content-derived length is trusted for quota accounting of quarantined data.
 */
template <typename Value> struct StoredValue {
    Value value;
    size_t size{0};
    template <typename Stream> void Unserialize(Stream& s)
    {
        size = s.size();
        s >> value;
        if (!s.empty()) throw std::ios_base::failure("trailing local record bytes");
    }
};
uint256 TemplateBodyHash(const CBlock& block)
{
    HashWriter writer;
    writer << TX_WITH_WITNESS(block);
    return writer.GetHash();
}
std::vector<unsigned char> EncodeBlock(const CBlock& block)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(block);
    return {UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
}
std::shared_ptr<CBlock> DecodeBlock(Span<const unsigned char> bytes)
{
    if (bytes.empty() || bytes.size() > hashonly::MAX_TEMPLATE_BYTES) throw std::runtime_error("hash-only block byte bound");
    return std::make_shared<CBlock>(hashonly::DecodeBlock(bytes));
}
}

HashSnapshotStore::HashSnapshotStore(const fs::path& path, bool memory_only, uint32_t profile_version)
    : m_profile_version{profile_version},
      m_db(DBParams{.path = path, .cache_bytes = 8 * 1024 * 1024, .memory_only = memory_only})
{
    LOCK(cs_main);
    // Reject an unknown selected profile even when this store is empty. The
    // selector is local configuration, never inferred from untrusted bytes.
    (void)hashonly::ProfileSnapshotHash(Span<const unsigned char>{}, m_profile_version);
    std::unique_ptr<CDBIterator> it{m_db.NewIterator()};
    for (it->Seek(std::make_pair(uint8_t{'s'}, uint256{})); it->Valid(); it->Next()) {
        std::pair<uint8_t, uint256> key;
        if (!it->GetKey(key) || key.first != 's') break;
        StoredValue<BoundedBytes> stored;
        const bool sound = it->GetValue(stored) && !stored.value.data.empty() &&
            hashonly::ProfileSnapshotHash(stored.value.data, m_profile_version) == key.second;
        const auto size = sound ? stored.value.data.size() : std::max(size_t{1}, stored.size);
        if (m_sizes.size() >= MAX_STORED_OBJECTS || size > MAX_STORED_BYTES - m_bytes) {
            throw std::runtime_error("stored hash-only snapshots exceed local quota");
        }
        m_sizes.emplace(key.second, size);
        m_bytes += size;
        if (!sound) {
            Quarantine(key.second);
            continue;
        }
        try { IndexTemplates(key.second, hashonly::DecodeSnapshot(stored.value.data)); }
        catch (const std::ios_base::failure&) { /* Retain the committed preimage for validation. */ }
    }
    // Transaction bytes are atomically stored with referencing templates. The
    // Wtxid includes witness; a body checksum also authenticates each exact
    // ordered reference list. This is local storage, not a consensus root.
    for (it->Seek(std::make_pair(uint8_t{'u'}, Wtxid{})); it->Valid(); it->Next()) {
        std::pair<uint8_t, Wtxid> key;
        if (!it->GetKey(key) || key.first != 'u') break;
        StoredValue<BoundedBytes> stored;
        const bool readable = it->GetValue(stored) && !stored.value.data.empty() &&
            stored.value.data.size() <= hashonly::MAX_TEMPLATE_BYTES;
        CTransactionRef tx;
        if (readable) {
            try { tx = hashonly::DecodeTransaction(stored.value.data); }
            catch (const std::ios_base::failure&) { }
        }
        const bool sound = tx && tx->GetWitnessHash() == key.second;
        // Sound transaction accounting excludes the vector prefix for backward
        // compatibility. Unsound records conservatively retain every disk byte.
        const auto size = sound ? stored.value.data.size() : std::max(size_t{1}, stored.size);
        if (m_transaction_sizes.size() >= MAX_LOCAL_TRANSACTIONS ||
            size > MAX_LOCAL_TEMPLATE_BYTES - m_template_bytes) {
            throw std::runtime_error("stored local transaction quota exhausted");
        }
        m_transaction_sizes.emplace(key.second, size);
        m_template_bytes += size;
        if (!sound) QuarantineTransaction(key.second);
        else CacheTransaction(key.second, tx);
    }
    for (it->Seek(std::make_pair(uint8_t{'t'}, uint256{})); it->Valid(); it->Next()) {
        std::pair<uint8_t, uint256> key;
        if (!it->GetKey(key) || key.first != 't') break;
        StoredValue<StoredTemplate> stored;
        const bool readable = it->GetValue(stored);
        const auto size = std::max(size_t{1}, stored.size);
        if (m_template_sizes.size() >= MAX_TEMPLATE_INDEX ||
            size > MAX_LOCAL_TEMPLATE_BYTES - m_template_bytes) {
            throw std::runtime_error("stored local template quota exhausted");
        }
        m_template_sizes.emplace(key.second, size);
        m_template_bytes += size;
        if (!readable || !LocalTemplate(key.second)) m_quarantined_templates.insert(key.second);
    }
    for (it->Seek(std::make_pair(uint8_t{'b'}, uint256{})); it->Valid(); it->Next()) {
        std::pair<uint8_t, uint256> key;
        if (!it->GetKey(key) || key.first != 'b') break;
        StoredValue<BoundedBytes> stored;
        const bool readable = it->GetValue(stored) && !stored.value.data.empty() &&
            stored.value.data.size() <= hashonly::MAX_TEMPLATE_BYTES;
        std::shared_ptr<CBlock> block;
        if (readable) {
            try { block = DecodeBlock(stored.value.data); }
            catch (const std::ios_base::failure&) { }
        }
        bool mutated{false};
        BlockValidationState state;
        const bool sound = block && block->GetHash() == key.second && !block->vtx.empty() &&
            block->m_txcount == block->vtx.size() && BlockMerkleRoot(*block, &mutated) == block->hashMerkleRoot &&
            !mutated && CheckWitnessMalleation(*block, true, state);
        const auto size = sound ? stored.value.data.size() : std::max(size_t{1}, stored.size);
        if (m_pending_sizes.size() >= MAX_PENDING_BLOCKS || size > MAX_PENDING_BYTES - m_pending_bytes) {
            throw std::runtime_error("pending hash-only blocks exceed local quota");
        }
        m_pending_sizes.emplace(key.second, size);
        m_pending_bytes += size;
        // A corrupted local body cannot suppress a fresh network download or
        // reserve snapshot requests. Its key and disk quota remain repairable.
        if (!sound) continue;
        m_pending.emplace(key.second, block);
        m_requests.Track(key.second, block->m_mm_rhs, [this](const auto& hash) { LOCK(cs_main); return Has(hash); });
    }
}

void HashSnapshotStore::CacheTransaction(const Wtxid& id, CTransactionRef tx)
{
    AssertLockHeld(cs_main);
    if (m_transactions.contains(id)) { m_transaction_touched[id] = ++m_clock; return; }
    const auto size = m_transaction_sizes.at(id);
    while (!m_transactions.empty() && size > MAX_CACHE_BYTES - m_transaction_cache_bytes) {
        const auto oldest = std::min_element(m_transaction_touched.begin(), m_transaction_touched.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });
        m_transaction_cache_bytes -= m_transaction_sizes.at(oldest->first);
        m_transactions.erase(oldest->first);
        m_transaction_touched.erase(oldest);
    }
    m_transactions.emplace(id, std::move(tx));
    m_transaction_touched[id] = ++m_clock;
    m_transaction_cache_bytes += size;
}

CTransactionRef HashSnapshotStore::Transaction(const Wtxid& id)
{
    AssertLockHeld(cs_main);
    if (const auto found = m_transactions.find(id); found != m_transactions.end()) {
        m_transaction_touched[id] = ++m_clock;
        return found->second;
    }
    if (!m_transaction_sizes.contains(id) || m_quarantined_transactions.contains(id)) return {};
    StoredValue<BoundedBytes> stored;
    if (!m_db.Read(std::make_pair(uint8_t{'u'}, id), stored) || stored.value.data.size() != m_transaction_sizes.at(id)) {
        QuarantineTransaction(id);
        return {};
    }
    try {
        auto tx = hashonly::DecodeTransaction(stored.value.data);
        if (tx->GetWitnessHash() == id) {
            CacheTransaction(id, tx);
            return tx;
        }
    } catch (const std::ios_base::failure&) { }
    QuarantineTransaction(id);
    return {};
}

void HashSnapshotStore::QuarantineTransaction(const Wtxid& id)
{
    AssertLockHeld(cs_main);
    if (m_transaction_sizes.contains(id)) m_quarantined_transactions.insert(id);
    if (m_transactions.erase(id)) m_transaction_cache_bytes -= m_transaction_sizes.at(id);
    m_transaction_touched.erase(id);
}

void HashSnapshotStore::Cache(const uint256& hash, std::shared_ptr<const std::vector<unsigned char>> bytes)
{
    AssertLockHeld(cs_main);
    if (m_cache.contains(hash)) { m_touched[hash] = ++m_clock; return; }
    while (!m_cache.empty() && m_cache_bytes + bytes->size() > MAX_CACHE_BYTES) {
        auto oldest = std::min_element(m_touched.begin(), m_touched.end(), [](const auto& a, const auto& b) { return a.second < b.second; });
        m_cache_bytes -= m_cache.at(oldest->first)->size();
        m_cache.erase(oldest->first);
        m_touched.erase(oldest);
    }
    m_cache_bytes += bytes->size();
    m_cache.emplace(hash, std::move(bytes));
    m_touched[hash] = ++m_clock;
}

void HashSnapshotStore::IndexTemplates(const uint256& hash, const hashonly::Snapshot& snapshot)
{
    AssertLockHeld(cs_main);
    for (size_t i = 0; i < snapshot.templates.size(); ++i) {
        const auto& record = snapshot.templates[i];
        if (m_template_sources.size() >= MAX_TEMPLATE_INDEX && !m_template_sources.contains(record.id)) continue;
        // Never let an arbitrary body with a copied header poison an ID lookup.
        auto block = std::make_shared<CBlock>(record.block);
        bool mutated{false};
        BlockValidationState state;
        if (block->vtx.empty() || block->m_txcount != block->vtx.size() ||
            BlockMerkleRoot(*block, &mutated) != block->hashMerkleRoot || mutated ||
            !CheckWitnessMalleation(*block, true, state)) continue;
        auto& sources = m_template_sources[record.id];
        std::erase_if(sources, [this](const auto& source) { LOCK(cs_main); return !Has(source.first); });
        const std::pair<uint256, uint32_t> source{hash, static_cast<uint32_t>(i)};
        if (sources.size() < MAX_TEMPLATE_SOURCES && std::find(sources.begin(), sources.end(), source) == sources.end()) {
            sources.push_back(source);
        }
    }
}

bool HashSnapshotStore::Has(const uint256& hash) const
{
    AssertLockHeld(cs_main);
    return m_sizes.contains(hash) && !m_quarantined.contains(hash);
}

void HashSnapshotStore::Quarantine(const uint256& hash, std::optional<size_t> disk_size)
{
    AssertLockHeld(cs_main);
    if (m_sizes.contains(hash)) {
        if (disk_size) {
            m_bytes = m_bytes - m_sizes.at(hash) + *disk_size;
            m_sizes[hash] = *disk_size;
        }
        m_quarantined.insert(hash);
    }
    if (const auto found = m_cache.find(hash); found != m_cache.end()) {
        m_cache_bytes -= found->second->size();
        m_cache.erase(found);
        m_touched.erase(hash);
    }
    m_requests.Refresh([this](const auto& id) { LOCK(cs_main); return Has(id); });
    // Local repair without a tracked dependent block is a speculative hint.
    Need({hash});
    ++m_revision;
}

std::shared_ptr<const std::vector<unsigned char>> HashSnapshotStore::GetShared(const uint256& hash)
{
    AssertLockHeld(cs_main);
    if (const auto found = m_cache.find(hash); found != m_cache.end()) { m_touched[hash] = ++m_clock; return found->second; }
    if (!Has(hash)) return {};
    StoredValue<BoundedBytes> stored;
    if (!m_db.Read(std::make_pair(uint8_t{'s'}, hash), stored) || stored.value.data.size() != m_sizes.at(hash) ||
        hashonly::ProfileSnapshotHash(stored.value.data, m_profile_version) != hash) {
        Quarantine(hash, std::max(size_t{1}, stored.size));
        return {};
    }
    auto bytes = std::make_shared<const std::vector<unsigned char>>(std::move(stored.value.data));
    Cache(hash, bytes);
    return bytes;
}

std::optional<std::vector<unsigned char>> HashSnapshotStore::Get(const uint256& hash)
{
    auto bytes = GetShared(hash);
    if (!bytes) return std::nullopt;
    return *bytes;
}

std::shared_ptr<const hashonly::Snapshot> HashSnapshotStore::Lookup(const uint256& hash)
{
    auto raw = GetShared(hash);
    if (!raw) return {};
    try { return std::make_shared<const hashonly::Snapshot>(hashonly::DecodeSnapshot(*raw)); }
    catch (const std::ios_base::failure&) { throw hashonly::MalformedSnapshot("hash-verified snapshot encoding is invalid"); }
}

uint256 HashSnapshotStore::Put(Span<const unsigned char> raw, std::optional<uint256> expected)
{
    AssertLockHeld(cs_main);
    if (raw.empty() || raw.size() > hashonly::MAX_SNAPSHOT_BYTES) throw std::runtime_error("hash-only snapshot byte bound");
    std::optional<hashonly::Snapshot> snapshot;
    try { snapshot = hashonly::DecodeSnapshot(raw); }
    catch (const std::ios_base::failure&) { /* Hash-verified invalid encodings prove invalidity. */ }
    const auto hash = hashonly::ProfileSnapshotHash(raw, m_profile_version);
    if (expected && *expected != hash) throw std::runtime_error("hash-only snapshot differs from requested hash");
    if (Has(hash)) return hash;
    const auto existing = m_sizes.find(hash);
    const size_t replaced = existing == m_sizes.end() ? 0 : existing->second;
    if ((existing == m_sizes.end() && m_sizes.size() >= MAX_STORED_OBJECTS) || m_bytes - replaced + raw.size() > MAX_STORED_BYTES) {
        throw std::runtime_error("local hash-only snapshot storage quota exhausted");
    }
    std::vector<unsigned char> bytes(raw.begin(), raw.end());
    if (!m_db.Write(std::make_pair(uint8_t{'s'}, hash), bytes, true)) throw std::runtime_error("cannot durably store hash-only snapshot");
    m_sizes[hash] = bytes.size();
    m_bytes = m_bytes - replaced + bytes.size();
    m_quarantined.erase(hash);
    Cache(hash, std::make_shared<const std::vector<unsigned char>>(std::move(bytes)));
    if (snapshot) IndexTemplates(hash, *snapshot);
    m_requests.Refresh([this](const auto& id) { LOCK(cs_main); return Has(id); });
    // Unvalidated contents can suggest dependencies but cannot reserve block
    // requirements. Only a tracked pending block's validator can do that.
    if (snapshot) {
        std::vector<uint256> hints;
        hints.reserve(std::min(HashRequestQueue<uint256>::MAX_HINTS, snapshot->templates.size()));
        for (const auto& record : snapshot->templates) {
            if (hints.size() == HashRequestQueue<uint256>::MAX_HINTS) break;
            hints.push_back(record.block.m_mm_rhs);
        }
        Need(hints);
    }
    ++m_revision;
    return hash;
}

std::vector<uint256> HashSnapshotStore::Inventory() const
{
    AssertLockHeld(cs_main);
    std::vector<uint256> result;
    for (const auto& [hash, size] : m_sizes) if (Has(hash)) result.push_back(hash);
    return result;
}

std::vector<uint256> HashSnapshotStore::Needed() const
{
    AssertLockHeld(cs_main);
    return m_requests.Required();
}
std::vector<uint256> HashSnapshotStore::Speculative() const
{
    AssertLockHeld(cs_main);
    return m_requests.Hints();
}
void HashSnapshotStore::Need(const std::vector<uint256>& hashes)
{
    AssertLockHeld(cs_main);
    // The generic queue invokes this predicate synchronously. Reenter the
    // recursive mutex to make the callback's lock contract explicit.
    m_requests.Hint(hashes, [this](const auto& hash) { LOCK(cs_main); return Has(hash); });
}
void HashSnapshotStore::NeedForBlock(const uint256& block, const std::vector<uint256>& hashes)
{
    AssertLockHeld(cs_main);
    m_requests.Update(block, hashes, [this](const auto& hash) { LOCK(cs_main); return Has(hash); });
}
void HashSnapshotStore::Requested(const uint256& hash)
{
    AssertLockHeld(cs_main);
    m_requests.Requested(hash);
}

void HashSnapshotStore::RememberTemplate(const CBlock& block)
{
    AssertLockHeld(cs_main);
    const auto id = hashonly::TemplateId(block);
    CBlock normalized{block};
    normalized.nNonce = normalized.m_nonce2 = normalized.m_nonce3 = normalized.m_time_offset = 0;
    normalized.m_extranonce.SetNull();
    const auto existing = m_template_sizes.find(id);
    if (normalized.vtx.empty() || std::any_of(normalized.vtx.begin(), normalized.vtx.end(), [](const auto& tx) { return !tx; }) ||
        GetSerializeSize(TX_WITH_WITNESS(normalized)) > hashonly::MAX_TEMPLATE_BYTES) throw std::runtime_error("local template byte bound");
    StoredTemplate record{normalized.GetBlockHeader(), {}, TemplateBodyHash(normalized)};
    // A known ID is insufficient: a prior local record or one of its deduped
    // transactions may have been quarantined. Only exact sound bytes are an
    // idempotent hit; validated reoffers can replace damaged records.
    if (existing != m_template_sizes.end()) {
        if (const auto known = LocalTemplate(id); known && TemplateBodyHash(*known) == record.body_hash) {
            m_quarantined_templates.erase(id);
            return;
        }
    }
    std::map<Wtxid, CTransactionRef> replacements;
    size_t replaced = existing == m_template_sizes.end() ? 0 : existing->second;
    size_t added_transactions{0};
    for (const auto& tx : normalized.vtx) {
        const auto hash = tx->GetWitnessHash();
        record.transactions.push_back(hash);
        if (!Transaction(hash) && replacements.try_emplace(hash, tx).second) {
            const auto found = m_transaction_sizes.find(hash);
            if (found == m_transaction_sizes.end()) ++added_transactions;
            else replaced += found->second;
        }
    }
    size_t increment = GetSerializeSize(record);
    for (const auto& [hash, tx] : replacements) increment += GetSerializeSize(TX_WITH_WITNESS(*tx));
    if ((existing == m_template_sizes.end() && m_template_sizes.size() >= MAX_TEMPLATE_INDEX) ||
        added_transactions > MAX_LOCAL_TRANSACTIONS - m_transaction_sizes.size() ||
        increment > MAX_LOCAL_TEMPLATE_BYTES - (m_template_bytes - replaced)) {
        throw std::runtime_error("local hash-only template index quota exhausted");
    }
    CDBBatch batch{m_db};
    for (const auto& [hash, tx] : replacements) {
        DataStream encoded;
        encoded << TX_WITH_WITNESS(*tx);
        const std::vector<unsigned char> bytes{UCharCast(encoded.data()), UCharCast(encoded.data()) + encoded.size()};
        batch.Write(std::make_pair(uint8_t{'u'}, hash), bytes);
    }
    batch.Write(std::make_pair(uint8_t{'t'}, id), record);
    if (!m_db.WriteBatch(batch, true)) throw std::runtime_error("cannot atomically store validated template and transactions");
    for (const auto& [hash, tx] : replacements) {
        m_transaction_sizes[hash] = GetSerializeSize(TX_WITH_WITNESS(*tx));
        m_quarantined_transactions.erase(hash);
        CacheTransaction(hash, tx);
    }
    m_template_sizes[id] = GetSerializeSize(record);
    m_template_bytes = m_template_bytes - replaced + increment;
    m_quarantined_templates.erase(id);
}

std::shared_ptr<const CBlock> HashSnapshotStore::LocalTemplate(const uint256& id)
{
    AssertLockHeld(cs_main);
    if (!m_template_sizes.contains(id)) return {};
    StoredValue<StoredTemplate> stored;
    if (m_db.Read(std::make_pair(uint8_t{'t'}, id), stored) && stored.size == m_template_sizes.at(id)) {
        const auto& record = stored.value;
        if (!record.header.m_header_v2 || record.header.m_txcount != record.transactions.size() || record.transactions.empty()) return {};
        auto block = std::make_shared<CBlock>(record.header);
        size_t size = GetSerializeSize(record.header) + GetSizeOfCompactSize(record.transactions.size());
        for (const auto& hash : record.transactions) {
            const auto tx = Transaction(hash);
            if (!tx || m_transaction_sizes.at(hash) > hashonly::MAX_TEMPLATE_BYTES - size) return {};
            size += m_transaction_sizes.at(hash);
            block->vtx.push_back(tx);
        }
        if (hashonly::TemplateId(*block) != id || TemplateBodyHash(*block) != record.body_hash ||
            block->nNonce || block->m_nonce2 || block->m_nonce3 || block->m_time_offset || !block->m_extranonce.IsNull() ||
            BlockMerkleRoot(*block) != block->hashMerkleRoot) return {};
        return block;
    }
    return {};
}

std::shared_ptr<const CBlock> HashSnapshotStore::Template(const uint256& id)
{
    AssertLockHeld(cs_main);
    if (const auto block = LocalTemplate(id)) {
        m_quarantined_templates.erase(id);
        return block;
    }
    if (m_template_sizes.contains(id)) m_quarantined_templates.insert(id);
    // An unsound local dedup record must not hide a full authenticated body
    // indexed from a separately hash-verified snapshot.
    const auto found = m_template_sources.find(id);
    if (found == m_template_sources.end()) return {};
    for (const auto& [hash, index] : found->second) {
        const auto snapshot = Lookup(hash);
        if (!snapshot || index >= snapshot->templates.size()) continue;
        auto block = std::make_shared<CBlock>(snapshot->templates[index].block);
        if (hashonly::TemplateId(*block) == id) return block;
    }
    return {};
}

std::optional<CAmount> HashSnapshotStore::NativeValidated(const uint256& id)
{
    AssertLockHeld(cs_main);
    const auto found = m_native_validated.find(id);
    if (found == m_native_validated.end()) return std::nullopt;
    m_native_touched[id] = ++m_clock;
    return found->second;
}
void HashSnapshotStore::SetNativeValidated(const uint256& id, CAmount reward)
{
    AssertLockHeld(cs_main);
    if (!m_native_validated.contains(id) && m_native_validated.size() >= 4096) {
        const auto oldest = std::min_element(m_native_touched.begin(), m_native_touched.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });
        m_native_validated.erase(oldest->first);
        m_native_touched.erase(oldest);
    }
    m_native_validated[id] = reward;
    m_native_touched[id] = ++m_clock;
}

bool HashSnapshotStore::QueueBlock(std::shared_ptr<const CBlock> block)
{
    AssertLockHeld(cs_main);
    const auto hash = block->GetHash();
    if (m_pending.contains(hash)) return true;
    if (GetSerializeSize(TX_WITH_WITNESS(*block)) > hashonly::MAX_TEMPLATE_BYTES) return false;
    const auto bytes = EncodeBlock(*block);
    const auto existing = m_pending_sizes.find(hash);
    const size_t replaced = existing == m_pending_sizes.end() ? 0 : existing->second;
    if ((existing == m_pending_sizes.end() && m_pending_sizes.size() >= MAX_PENDING_BLOCKS) ||
        m_pending_bytes - replaced + bytes.size() > MAX_PENDING_BYTES) return false;
    if (!m_db.Write(std::make_pair(uint8_t{'b'}, hash), bytes, true)) return false;
    m_pending_bytes = m_pending_bytes - replaced + bytes.size();
    m_pending_sizes[hash] = bytes.size();
    m_pending.emplace(hash, std::move(block));
    m_requests.Track(hash, m_pending.at(hash)->m_mm_rhs, [this](const auto& id) { LOCK(cs_main); return Has(id); });
    ++m_revision;
    return true;
}
bool HashSnapshotStore::HasPendingBlock(const uint256& hash) const
{
    AssertLockHeld(cs_main);
    return m_pending.contains(hash);
}

bool HashSnapshotStore::MatchesPendingBlock(const CBlock& block) const
{
    AssertLockHeld(cs_main);
    const auto found = m_pending.find(block.GetHash());
    return found != m_pending.end() && TemplateBodyHash(*found->second) == TemplateBodyHash(block);
}

void HashSnapshotStore::RemoveBlock(const uint256& hash)
{
    AssertLockHeld(cs_main);
    if (!m_pending_sizes.contains(hash)) return;
    if (!m_db.Erase(std::make_pair(uint8_t{'b'}, hash), true)) throw std::runtime_error("cannot remove completed pending block");
    m_pending_bytes -= m_pending_sizes.at(hash);
    m_pending_sizes.erase(hash);
    m_pending.erase(hash);
    m_requests.Forget(hash, [this](const auto& id) { LOCK(cs_main); return Has(id); });
    ++m_revision;
}
std::vector<std::shared_ptr<const CBlock>> HashSnapshotStore::PendingBlocks() const
{
    AssertLockHeld(cs_main);
    std::vector<std::shared_ptr<const CBlock>> result;
    for (const auto& [hash, block] : m_pending) result.push_back(block);
    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) { return a->m_height < b->m_height; });
    return result;
}
} // namespace sharepool
