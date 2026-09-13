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
#include <random.h>

#include <algorithm>
#include <array>
#include <limits>

namespace sharepool {
namespace {
constexpr size_t MAX_CACHE_BYTES{64 * 1024 * 1024};
constexpr size_t MAX_CACHE_OBJECTS{4096};
constexpr size_t MAX_PENDING_BYTES{64 * 1024 * 1024};
constexpr size_t MAX_PENDING_BLOCKS{HashRequestQueue<uint256>::MAX_BLOCKS};
constexpr size_t MAX_TEMPLATE_INDEX{65536};
constexpr size_t MAX_TEMPLATE_SOURCES{4};
constexpr size_t MAX_LOCAL_TEMPLATE_BYTES{256 * 1024 * 1024};
constexpr size_t MAX_LOCAL_TRANSACTIONS{262144};
// Snapshot and metadata keys, vector prefix, metadata and a small index
// allowance. This prevents tiny malformed preimages bypassing the byte quota.
constexpr uint64_t SNAPSHOT_INDEX_ALLOWANCE{128};
// Each decoded template may create an index key plus up to four source pairs
// (33 + 1 + 4*36 =178 bytes). Charging192 for every occurrence is conservative
// when many snapshots share one index, and avoids an unbounded RAM size map.
constexpr uint64_t TEMPLATE_SOURCE_ALLOWANCE{192};
struct SnapshotMeta {
    uint64_t size{0};
    uint64_t index_allowance{0};
    bool quarantined{false};
    uint256 checksum;
    SnapshotMeta() = default;
    SnapshotMeta(const uint256& key, uint64_t size_in, bool quarantine_in, uint64_t allowance = 0)
        : size{size_in}, index_allowance{allowance}, quarantined{quarantine_in}
    {
        HashWriter writer;
        writer << key << size << index_allowance << quarantined;
        checksum = writer.GetHash();
    }
    bool Valid(const uint256& key) const
    {
        return size && index_allowance <= hashonly::MAX_SNAPSHOT_BYTES * TEMPLATE_SOURCE_ALLOWANCE &&
            index_allowance % TEMPLATE_SOURCE_ALLOWANCE == 0 &&
            checksum == SnapshotMeta{key, size, quarantined, index_allowance}.checksum;
    }
    SERIALIZE_METHODS(SnapshotMeta, obj) { READWRITE(obj.size, obj.index_allowance, obj.quarantined, obj.checksum); }
};
struct TemplateSourcesRecord {
    std::vector<std::pair<uint256, uint32_t>> sources;
    template <typename Stream> void Serialize(Stream& s) const { s << sources; }
    template <typename Stream> void Unserialize(Stream& s) { ReadBoundedVector(s, sources, MAX_TEMPLATE_SOURCES); }
};
constexpr std::array<unsigned char, 12> ARCHIVE_MAGIC{'S','P','H','A','R','C','H','I','V','E',0,1};
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
bool ReadSnapshotMeta(const CDBWrapper& db, const uint256& hash, SnapshotMeta& meta)
{
    const auto key = std::make_pair(uint8_t{'m'}, hash);
    StoredValue<SnapshotMeta> stored;
    if (!db.Read(key, stored)) {
        if (db.Exists(key)) throw std::runtime_error("local archive metadata damaged; restart to rebuild the disk index");
        return false;
    }
    if (!stored.value.Valid(hash)) throw std::runtime_error("local archive metadata checksum mismatch; restart to rebuild the disk index");
    meta = stored.value;
    return true;
}
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
    : HashSnapshotStore{path, memory_only, profile_version, Options{}}
{
}

HashSnapshotStore::HashSnapshotStore(const fs::path& path, bool memory_only, uint32_t profile_version, Options options)
    : m_profile_version{profile_version},
      m_options{options},
      m_db(DBParams{.path = path, .cache_bytes = 8 * 1024 * 1024, .memory_only = memory_only}),
      m_recent_epoch{GetRandHash()}
{
    LOCK(cs_main);
    if (!m_options.max_bytes) throw std::invalid_argument("hash-only snapshot quota must be positive");
    // Reject an unknown selected profile even when this store is empty. The
    // selector is local configuration, never inferred from untrusted bytes.
    (void)hashonly::ProfileSnapshotHash(Span<const unsigned char>{}, m_profile_version);
    std::unique_ptr<CDBIterator> it{m_db.NewIterator()};
    // Rebuild disposable disk indexes from authenticated preimages, streaming
    // one record at a time. Never retain a RAM entry per historical snapshot.
    // This also repairs stale metadata after out-of-band record loss.
    for (const uint8_t prefix : {uint8_t{'m'}, uint8_t{'i'}}) {
        for (it->Seek(std::make_pair(prefix, uint256{})); it->Valid(); it->Next()) {
            std::pair<uint8_t, uint256> key;
            if (!it->GetKey(key) || key.first != prefix) break;
            if (!m_db.Erase(key)) throw std::runtime_error("cannot rebuild hash-only archive index");
        }
    }
    for (it->Seek(std::make_pair(uint8_t{'s'}, uint256{})); it->Valid(); it->Next()) {
        std::pair<uint8_t, uint256> key;
        if (!it->GetKey(key) || key.first != 's') break;
        StoredValue<BoundedBytes> stored;
        const bool sound = it->GetValue(stored) && !stored.value.data.empty() &&
            hashonly::ProfileSnapshotHash(stored.value.data, m_profile_version) == key.second;
        const auto size = sound ? stored.value.data.size() : std::max(size_t{1}, stored.size);
        std::optional<hashonly::Snapshot> snapshot;
        if (sound) {
            try { snapshot = hashonly::DecodeSnapshot(stored.value.data); }
            catch (const std::ios_base::failure&) { /* Preserve hash-correct malformed consensus evidence. */ }
        }
        const uint64_t index_allowance = snapshot ? snapshot->templates.size() * TEMPLATE_SOURCE_ALLOWANCE : 0;
        const uint64_t overhead = SNAPSHOT_INDEX_ALLOWANCE + index_allowance;
        const auto available = m_options.max_bytes - m_charged_bytes;
        if (available < overhead || size > available - overhead) {
            throw std::runtime_error("stored hash-only snapshots exceed local quota");
        }
        ++m_count;
        m_bytes += size;
        m_charged_bytes += size + overhead;
        if (!m_db.Write(std::make_pair(uint8_t{'m'}, key.second), SnapshotMeta{key.second, size, !sound, index_allowance})) {
            throw std::runtime_error("cannot recover hash-only snapshot metadata");
        }
        if (!sound) {
            ++m_quarantined_count;
            Need({key.second});
            continue;
        }
        if (snapshot) IndexTemplates(key.second, *snapshot);
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
        if (readable) for (const auto& id : stored.value.transactions) ++m_transaction_references[id];
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
    while (!m_cache.empty() && (m_cache.size() >= MAX_CACHE_OBJECTS || m_cache_bytes + bytes->size() > MAX_CACHE_BYTES)) {
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
        // Never let an arbitrary body with a copied header poison an ID lookup.
        auto block = std::make_shared<CBlock>(record.block);
        bool mutated{false};
        BlockValidationState state;
        if (block->vtx.empty() || block->m_txcount != block->vtx.size() ||
            BlockMerkleRoot(*block, &mutated) != block->hashMerkleRoot || mutated ||
            !CheckWitnessMalleation(*block, true, state)) continue;
        auto sources = TemplateSources(record.id);
        std::erase_if(sources, [this](const auto& source) { LOCK(cs_main); return !Has(source.first); });
        const std::pair<uint256, uint32_t> source{hash, static_cast<uint32_t>(i)};
        if (sources.size() < MAX_TEMPLATE_SOURCES && std::find(sources.begin(), sources.end(), source) == sources.end()) {
            sources.push_back(source);
        }
        if (!m_db.Write(std::make_pair(uint8_t{'i'}, record.id), TemplateSourcesRecord{sources})) {
            throw std::runtime_error("cannot index archived template sources");
        }
        if (!m_template_sources.contains(record.id) && m_template_sources.size() >= MAX_TEMPLATE_INDEX) {
            m_template_sources.erase(m_template_sources.begin());
        }
        m_template_sources[record.id] = std::move(sources);
    }
}

std::vector<std::pair<uint256, uint32_t>> HashSnapshotStore::TemplateSources(const uint256& id)
{
    AssertLockHeld(cs_main);
    if (const auto found = m_template_sources.find(id); found != m_template_sources.end()) return found->second;
    StoredValue<TemplateSourcesRecord> stored;
    if (!m_db.Read(std::make_pair(uint8_t{'i'}, id), stored)) return {};
    if (m_template_sources.size() >= MAX_TEMPLATE_INDEX) m_template_sources.erase(m_template_sources.begin());
    m_template_sources[id] = stored.value.sources;
    return stored.value.sources;
}

bool HashSnapshotStore::Has(const uint256& hash) const
{
    AssertLockHeld(cs_main);
    SnapshotMeta meta;
    return ReadSnapshotMeta(m_db, hash, meta) && !meta.quarantined;
}

void HashSnapshotStore::Quarantine(const uint256& hash, std::optional<size_t> disk_size)
{
    AssertLockHeld(cs_main);
    SnapshotMeta previous;
    if (ReadSnapshotMeta(m_db, hash, previous)) {
        if (previous.size > m_bytes || previous.size > m_charged_bytes ||
            m_charged_bytes - previous.size < SNAPSHOT_INDEX_ALLOWANCE + previous.index_allowance) {
            throw std::runtime_error("local archive accounting mismatch; restart to rebuild the disk index");
        }
        const SnapshotMeta meta{hash, disk_size.value_or(previous.size), true, previous.index_allowance};
        if (meta.size > std::numeric_limits<uint64_t>::max() - (m_charged_bytes - previous.size)) {
            throw std::runtime_error("damaged local archive size cannot be accounted safely");
        }
        if (!m_db.Write(std::make_pair(uint8_t{'m'}, hash), meta, true)) {
            throw std::runtime_error("cannot quarantine local archive record");
        }
        m_bytes = m_bytes - previous.size + meta.size;
        m_charged_bytes = m_charged_bytes - previous.size + meta.size;
        if (!previous.quarantined) ++m_quarantined_count;
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
    SnapshotMeta meta;
    if (!ReadSnapshotMeta(m_db, hash, meta) || meta.quarantined) return {};
    StoredValue<BoundedBytes> stored;
    if (!m_db.Read(std::make_pair(uint8_t{'s'}, hash), stored) || stored.value.data.empty() || stored.value.data.size() != meta.size ||
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
    // A reoffer, including archive recovery, must verify the durable record.
    // A still-sound RAM copy must not conceal damage to its on-disk backing.
    if (const auto found = m_cache.find(hash); found != m_cache.end()) {
        m_cache_bytes -= found->second->size();
        m_cache.erase(found);
        m_touched.erase(hash);
    }
    if (GetShared(hash)) return hash;
    SnapshotMeta previous;
    const bool existing = ReadSnapshotMeta(m_db, hash, previous);
    if ((!existing && m_db.Exists(std::make_pair(uint8_t{'s'}, hash))) ||
        (existing && (previous.size > m_bytes || previous.size > m_charged_bytes ||
                      m_charged_bytes - previous.size < SNAPSHOT_INDEX_ALLOWANCE + previous.index_allowance))) {
        throw std::runtime_error("local archive accounting mismatch; restart to rebuild the disk index");
    }
    const uint64_t replaced = existing ? previous.size : 0;
    const uint64_t charged_replacement = existing ? previous.size + SNAPSHOT_INDEX_ALLOWANCE + previous.index_allowance : 0;
    const uint64_t index_allowance = snapshot ? snapshot->templates.size() * TEMPLATE_SOURCE_ALLOWANCE : 0;
    const uint64_t overhead = SNAPSHOT_INDEX_ALLOWANCE + index_allowance;
    const auto retained = m_charged_bytes - charged_replacement;
    if (retained > m_options.max_bytes || m_options.max_bytes - retained < overhead ||
        raw.size() > m_options.max_bytes - retained - overhead) {
        throw std::runtime_error("local hash-only snapshot storage quota exhausted");
    }
    std::vector<unsigned char> bytes(raw.begin(), raw.end());
    CDBBatch batch{m_db};
    batch.Write(std::make_pair(uint8_t{'s'}, hash), bytes);
    batch.Write(std::make_pair(uint8_t{'m'}, hash), SnapshotMeta{hash, bytes.size(), false, index_allowance});
    if (!m_db.WriteBatch(batch, true)) throw std::runtime_error("cannot durably store hash-only snapshot");
    if (!existing) ++m_count;
    else if (previous.quarantined) --m_quarantined_count;
    m_bytes = m_bytes - replaced + bytes.size();
    m_charged_bytes = m_charged_bytes - charged_replacement + bytes.size() + overhead;
    Cache(hash, std::make_shared<const std::vector<unsigned char>>(std::move(bytes)));
    if (snapshot) {
        IndexTemplates(hash, *snapshot);
        if (m_profile_version == hashonly::TIDES_VERSION) ArchiveLocalTemplates(*snapshot);
    }
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
    if (m_recent_sequence == std::numeric_limits<uint64_t>::max()) {
        throw std::runtime_error("local recent inventory sequence exhausted");
    }
    m_recent_inventory.push_back({++m_recent_sequence, hash});
    if (m_recent_inventory.size() > MAX_RECENT_INVENTORY) m_recent_inventory.pop_front();
    return hash;
}

std::vector<uint256> HashSnapshotStore::Inventory() const
{
    return InventoryPage().hashes;
}

HashSnapshotStore::Page HashSnapshotStore::InventoryPage(std::optional<uint256> after, size_t limit) const
{
    AssertLockHeld(cs_main);
    if (!limit || limit > MAX_INVENTORY_PAGE) throw std::invalid_argument("hash-only inventory page bound");
    Page result;
    std::unique_ptr<CDBIterator> it{m_db.NewIterator()};
    it->Seek(std::make_pair(uint8_t{'m'}, after.value_or(uint256{})));
    size_t scanned{0};
    while (it->Valid()) {
        std::pair<uint8_t, uint256> key;
        if (!it->GetKey(key) || key.first != 'm') break;
        if (after && key.second == *after) { it->Next(); continue; }
        if (scanned == limit) return result;
        ++scanned;
        result.next = key.second;
        StoredValue<SnapshotMeta> stored;
        if (!it->GetValue(stored) || !stored.value.Valid(key.second)) {
            throw std::runtime_error("local archive metadata damaged; restart to rebuild the disk index");
        }
        if (!stored.value.quarantined) result.hashes.push_back(key.second);
        it->Next();
    }
    result.complete = true;
    return result;
}

HashSnapshotStore::RecentPage HashSnapshotStore::RecentInventory(uint64_t after, size_t limit) const
{
    AssertLockHeld(cs_main);
    if (!limit || limit > MAX_INVENTORY_PAGE) throw std::invalid_argument("hash-only recent inventory page bound");
    RecentPage result;
    result.epoch = m_recent_epoch;
    result.latest = m_recent_sequence;
    result.gap = after > result.latest ||
        (!m_recent_inventory.empty() && after < m_recent_inventory.front().sequence - 1);
    if (after > result.latest) after = 0;
    result.next = after;
    size_t scanned{0};
    for (const auto& entry : m_recent_inventory) {
        if (entry.sequence <= after) continue;
        if (scanned++ == limit) break;
        result.next = entry.sequence;
        if (Has(entry.hash)) result.entries.push_back(entry);
    }
    return result;
}

HashSnapshotStore::ArchiveResult HashSnapshotStore::ExportArchive(AutoFile& file, std::optional<uint256> after,
                                                                 size_t record_limit, uint64_t byte_limit)
{
    if (!record_limit || record_limit > MAX_INVENTORY_PAGE || !byte_limit || byte_limit > MAX_ARCHIVE_CHUNK_BYTES) {
        throw std::invalid_argument("hash-only archive chunk bound");
    }
    ArchiveResult result;
    result.next = after;
    Page page;
    { LOCK(cs_main); page = InventoryPage(after, record_limit); }
    HashWriter transcript;
    const uint8_t has_after = after.has_value();
    file << ARCHIVE_MAGIC << m_profile_version << has_after << after.value_or(uint256{});
    transcript << ARCHIVE_MAGIC << m_profile_version << has_after << after.value_or(uint256{});
    bool exhausted{false};
    for (const auto& hash : page.hashes) {
        std::shared_ptr<const std::vector<unsigned char>> raw;
        { LOCK(cs_main); raw = GetShared(hash); }
        if (!raw) { result.next = hash; continue; }
        if (raw->size() > byte_limit - result.bytes) {
            if (!result.records) throw std::runtime_error("hash-only archive byte budget cannot fit next record");
            exhausted = true;
            break;
        }
        file << uint32_t(raw->size()) << hash;
        file.write(MakeByteSpan(*raw));
        transcript << uint32_t(raw->size()) << hash;
        transcript.write(MakeByteSpan(*raw));
        ++result.records;
        result.bytes += raw->size();
        result.next = hash;
    }
    if (!exhausted) { result.next = page.next ? page.next : after; result.complete = page.complete; }
    const uint8_t has_next = result.next.has_value();
    const uint8_t complete = result.complete;
    file << uint32_t{0} << result.records << result.bytes << has_next << result.next.value_or(uint256{}) << complete;
    transcript << uint32_t{0} << result.records << result.bytes << has_next << result.next.value_or(uint256{}) << complete;
    file << transcript.GetHash();
    return result;
}

HashSnapshotStore::ArchiveResult HashSnapshotStore::ImportArchive(AutoFile& file, size_t record_limit, uint64_t byte_limit)
{
    if (!record_limit || record_limit > MAX_INVENTORY_PAGE || !byte_limit || byte_limit > MAX_ARCHIVE_CHUNK_BYTES) {
        throw std::invalid_argument("hash-only archive chunk bound");
    }
    std::array<unsigned char, ARCHIVE_MAGIC.size()> magic;
    uint32_t profile;
    uint8_t has_after;
    uint256 after;
    file >> magic >> profile >> has_after >> after;
    if (magic != ARCHIVE_MAGIC || profile != m_profile_version || has_after > 1 || (!has_after && !after.IsNull())) {
        throw std::runtime_error("hash-only archive format or selected profile mismatch");
    }
    HashWriter transcript;
    transcript << magic << profile << has_after << after;
    ArchiveResult result;
    std::optional<uint256> previous = has_after ? std::optional{after} : std::nullopt;
    while (true) {
        uint32_t size;
        file >> size;
        if (!size) break;
        if (size > hashonly::MAX_SNAPSHOT_BYTES || result.records >= record_limit || size > byte_limit - result.bytes) {
            throw std::runtime_error("hash-only archive record or chunk budget exceeded");
        }
        uint256 hash;
        file >> hash;
        if (previous && !(*previous < hash)) throw std::runtime_error("hash-only archive records are not ordered and unique");
        std::vector<unsigned char> raw(size);
        file.read(MakeWritableByteSpan(raw));
        if (hashonly::ProfileSnapshotHash(raw, m_profile_version) != hash) {
            throw std::runtime_error("hash-only archive record hash mismatch");
        }
        transcript << size << hash;
        transcript.write(MakeByteSpan(raw));
        { LOCK(cs_main); Put(raw, hash); }
        previous = hash;
        ++result.records;
        result.bytes += size;
    }
    uint64_t records, bytes;
    uint8_t has_next, complete;
    uint256 next, checksum;
    file >> records >> bytes >> has_next >> next >> complete >> checksum;
    transcript << uint32_t{0} << records << bytes << has_next << next << complete;
    if (records != result.records || bytes != result.bytes || has_next > 1 || complete > 1 ||
        (!has_next && !next.IsNull()) || (previous && (!has_next || next < *previous)) || transcript.GetHash() != checksum) {
        throw std::runtime_error("hash-only archive footer or checksum mismatch; preceding verified records retained");
    }
    std::array<std::byte, 1> trailing;
    if (file.detail_fread(trailing) != 0) throw std::runtime_error("hash-only archive has trailing data; verified records retained");
    result.next = has_next ? std::optional{next} : std::nullopt;
    result.complete = complete;
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
    if (m_profile_version == hashonly::TIDES_VERSION && !m_template_sizes.contains(id)) {
        if (const auto archived = Template(id); archived && hashonly::JobHash(*archived) == hashonly::JobHash(normalized)) return;
    }
    const auto existing = m_template_sizes.find(id);
    StoredValue<StoredTemplate> old_record;
    const bool old_readable = existing != m_template_sizes.end() && m_db.Read(std::make_pair(uint8_t{'t'}, id), old_record);
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
    if (old_readable) for (const auto& hash : old_record.value.transactions) {
        const auto found = m_transaction_references.find(hash);
        if (found != m_transaction_references.end() && found->second) --found->second;
    }
    for (const auto& hash : record.transactions) ++m_transaction_references[hash];
}

void HashSnapshotStore::ArchiveLocalTemplates(const hashonly::Snapshot& snapshot)
{
    AssertLockHeld(cs_main);
    // Full authenticated snapshot bodies become the durable template source.
    // Release duplicate standalone records only after that source is durable;
    // unfinished jobs without an archived copy retain the bounded local cache.
    std::set<uint256> remove_templates;
    std::map<Wtxid, size_t> remove_references;
    CDBBatch batch{m_db};
    for (const auto& item : snapshot.templates) {
        if (remove_templates.contains(item.id)) continue;
        const auto local = LocalTemplate(item.id);
        if (!local || hashonly::JobHash(*local) != hashonly::JobHash(item.block)) continue;
        const auto sources = TemplateSources(item.id);
        if (sources.empty()) continue;
        remove_templates.insert(item.id);
        batch.Erase(std::make_pair(uint8_t{'t'}, item.id));
        for (const auto& tx : local->vtx) ++remove_references[tx->GetWitnessHash()];
    }
    if (remove_templates.empty()) return;
    std::set<Wtxid> remove_transactions;
    for (const auto& [id, count] : remove_references) {
        const auto found = m_transaction_references.find(id);
        if (found != m_transaction_references.end() && found->second == count) {
            remove_transactions.insert(id);
            batch.Erase(std::make_pair(uint8_t{'u'}, id));
        }
    }
    if (!m_db.WriteBatch(batch, true)) throw std::runtime_error("cannot release archived local templates");
    for (const auto& id : remove_templates) {
        m_template_bytes -= m_template_sizes.at(id);
        m_template_sizes.erase(id);
        m_quarantined_templates.erase(id);
    }
    for (const auto& [id, count] : remove_references) {
        const auto found = m_transaction_references.find(id);
        if (found != m_transaction_references.end()) {
            if (found->second <= count) m_transaction_references.erase(found);
            else found->second -= count;
        }
    }
    for (const auto& id : remove_transactions) {
        if (const auto found = m_transaction_sizes.find(id); found != m_transaction_sizes.end()) {
            if (m_transactions.erase(id)) m_transaction_cache_bytes -= found->second;
            m_template_bytes -= found->second;
            m_transaction_sizes.erase(found);
        }
        m_transaction_touched.erase(id);
        m_quarantined_transactions.erase(id);
    }
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
    for (const auto& [hash, index] : TemplateSources(id)) {
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
