// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <sharepool/hash_store.h>

#include <consensus/merkle.h>
#include <consensus/validation.h>
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
constexpr size_t MAX_PENDING_BLOCKS{16};
constexpr size_t MAX_TEMPLATE_INDEX{65536};
constexpr size_t MAX_LOCAL_TEMPLATE_BYTES{256 * 1024 * 1024};
struct BoundedBytes {
    std::vector<unsigned char> data;
    template <typename Stream> void Serialize(Stream& s) const { s << data; }
    template <typename Stream> void Unserialize(Stream& s) { ReadBoundedVector(s, data, hashonly::MAX_SNAPSHOT_BYTES); }
};
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

HashSnapshotStore::HashSnapshotStore(const fs::path& path, bool memory_only)
    : m_db(DBParams{.path = path, .cache_bytes = 8 * 1024 * 1024, .memory_only = memory_only})
{
    LOCK(cs_main);
    std::unique_ptr<CDBIterator> it{m_db.NewIterator()};
    for (it->Seek(std::make_pair(uint8_t{'s'}, uint256{})); it->Valid(); it->Next()) {
        std::pair<uint8_t, uint256> key;
        if (!it->GetKey(key) || key.first != 's') break;
        BoundedBytes bytes;
        if (!it->GetValue(bytes) || hashonly::SnapshotHash(bytes.data) != key.second) {
            throw std::runtime_error("stored hash-only snapshot failed integrity verification");
        }
        if (m_sizes.size() >= MAX_STORED_OBJECTS || m_bytes + bytes.data.size() > MAX_STORED_BYTES) {
            throw std::runtime_error("stored hash-only snapshots exceed local quota");
        }
        m_sizes.emplace(key.second, bytes.data.size());
        m_bytes += bytes.data.size();
        try { IndexTemplates(key.second, hashonly::DecodeSnapshot(bytes.data)); }
        catch (const std::ios_base::failure&) { /* Retain the committed preimage for validation. */ }
    }
    for (it->Seek(std::make_pair(uint8_t{'t'}, uint256{})); it->Valid(); it->Next()) {
        std::pair<uint8_t, uint256> key;
        if (!it->GetKey(key) || key.first != 't') break;
        BoundedBytes bytes;
        if (!it->GetValue(bytes) || bytes.data.size() > hashonly::MAX_TEMPLATE_BYTES ||
            m_template_sizes.size() >= MAX_TEMPLATE_INDEX ||
            m_template_bytes + bytes.data.size() > MAX_LOCAL_TEMPLATE_BYTES) {
            throw std::runtime_error("stored local template exceeds quota or cannot be read");
        }
        m_template_sizes.emplace(key.second, bytes.data.size());
        m_template_bytes += bytes.data.size();
        auto block = DecodeBlock(bytes.data);
        if (hashonly::TemplateId(*block) != key.second) throw std::runtime_error("stored local template identity mismatch");
        m_template_sources.try_emplace(key.second, uint256{}, 0);
    }
    for (it->Seek(std::make_pair(uint8_t{'b'}, uint256{})); it->Valid(); it->Next()) {
        std::pair<uint8_t, uint256> key;
        if (!it->GetKey(key) || key.first != 'b') break;
        BoundedBytes bytes;
        if (!it->GetValue(bytes)) throw std::runtime_error("pending hash-only block failed decoding");
        auto block = DecodeBlock(bytes.data);
        if (block->GetHash() != key.second || m_pending.size() >= MAX_PENDING_BLOCKS ||
            m_pending_bytes + bytes.data.size() > MAX_PENDING_BYTES) throw std::runtime_error("pending hash-only block bounds or identity failed");
        m_pending.emplace(key.second, block);
        m_pending_sizes.emplace(key.second, bytes.data.size());
        m_pending_bytes += bytes.data.size();
        if (!Has(block->m_mm_rhs)) m_needed.insert(block->m_mm_rhs);
    }
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
        auto block = DecodeBlock(record.block);
        bool mutated{false};
        BlockValidationState state;
        if (block->vtx.empty() || block->m_txcount != block->vtx.size() ||
            BlockMerkleRoot(*block, &mutated) != block->hashMerkleRoot || mutated ||
            !CheckWitnessMalleation(*block, true, state)) continue;
        m_template_sources.try_emplace(record.id, hash, static_cast<uint32_t>(i));
    }
}

bool HashSnapshotStore::Has(const uint256& hash) const
{
    AssertLockHeld(cs_main);
    return m_sizes.contains(hash) && !m_quarantined.contains(hash);
}

void HashSnapshotStore::Quarantine(const uint256& hash)
{
    AssertLockHeld(cs_main);
    if (m_sizes.contains(hash)) m_quarantined.insert(hash);
    if (const auto found = m_cache.find(hash); found != m_cache.end()) {
        m_cache_bytes -= found->second->size();
        m_cache.erase(found);
        m_touched.erase(hash);
    }
    if (m_needed.size() < 4096) m_needed.insert(hash);
    ++m_revision;
}

std::shared_ptr<const std::vector<unsigned char>> HashSnapshotStore::GetShared(const uint256& hash)
{
    AssertLockHeld(cs_main);
    if (const auto found = m_cache.find(hash); found != m_cache.end()) { m_touched[hash] = ++m_clock; return found->second; }
    if (!Has(hash)) return {};
    BoundedBytes value;
    if (!m_db.Read(std::make_pair(uint8_t{'s'}, hash), value) || hashonly::SnapshotHash(value.data) != hash) {
        Quarantine(hash);
        return {};
    }
    auto bytes = std::make_shared<const std::vector<unsigned char>>(std::move(value.data));
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
    const auto hash = hashonly::SnapshotHash(raw);
    if (expected && *expected != hash) throw std::runtime_error("hash-only snapshot differs from requested hash");
    if (Has(hash)) { m_needed.erase(hash); return hash; }
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
    m_needed.erase(hash);
    // Origin snapshot dependencies are discovered without trusting their contents.
    if (snapshot) for (const auto& record : snapshot->templates) {
        auto block = DecodeBlock(record.block);
        if (!Has(block->m_mm_rhs) && m_needed.size() < 4096) m_needed.insert(block->m_mm_rhs);
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
    return {m_needed.begin(), m_needed.end()};
}
void HashSnapshotStore::Need(const std::vector<uint256>& hashes)
{
    AssertLockHeld(cs_main);
    for (const auto& hash : hashes) if (!hash.IsNull() && !Has(hash) && m_needed.size() < 4096) m_needed.insert(hash);
}

void HashSnapshotStore::RememberTemplate(const CBlock& block)
{
    AssertLockHeld(cs_main);
    const auto id = hashonly::TemplateId(block);
    CBlock normalized{block};
    normalized.nNonce = normalized.m_nonce2 = normalized.m_nonce3 = normalized.m_time_offset = 0;
    normalized.m_extranonce.SetNull();
    auto bytes = EncodeBlock(normalized);
    const auto existing = m_template_sizes.find(id);
    if (existing != m_template_sizes.end()) return;
    if (bytes.size() > hashonly::MAX_TEMPLATE_BYTES ||
        m_template_sizes.size() >= MAX_TEMPLATE_INDEX || m_template_bytes + bytes.size() > MAX_LOCAL_TEMPLATE_BYTES) {
        throw std::runtime_error("local hash-only template index quota exhausted");
    }
    if (!m_db.Write(std::make_pair(uint8_t{'t'}, id), bytes, true)) throw std::runtime_error("cannot store validated full template");
    m_template_sizes[id] = bytes.size();
    m_template_bytes += bytes.size();
    m_template_sources.try_emplace(id, uint256{}, 0);
}

std::shared_ptr<const CBlock> HashSnapshotStore::Template(const uint256& id)
{
    AssertLockHeld(cs_main);
    BoundedBytes bytes;
    if (m_db.Read(std::make_pair(uint8_t{'t'}, id), bytes)) {
        auto block = DecodeBlock(bytes.data);
        if (hashonly::TemplateId(*block) == id) return block;
        return {};
    }
    const auto found = m_template_sources.find(id);
    if (found == m_template_sources.end()) return {};
    const auto snapshot = Lookup(found->second.first);
    if (!snapshot || found->second.second >= snapshot->templates.size()) return {};
    auto block = DecodeBlock(snapshot->templates[found->second.second].block);
    return hashonly::TemplateId(*block) == id ? block : nullptr;
}

std::optional<CAmount> HashSnapshotStore::NativeValidated(const uint256& id) const
{
    AssertLockHeld(cs_main);
    const auto found = m_native_validated.find(id);
    return found == m_native_validated.end() ? std::nullopt : std::optional<CAmount>{found->second};
}
void HashSnapshotStore::SetNativeValidated(const uint256& id, CAmount reward)
{
    AssertLockHeld(cs_main);
    if (m_native_validated.size() >= 4096) m_native_validated.erase(m_native_validated.begin());
    m_native_validated[id] = reward;
}

bool HashSnapshotStore::QueueBlock(std::shared_ptr<const CBlock> block)
{
    AssertLockHeld(cs_main);
    const auto hash = block->GetHash();
    if (m_pending.contains(hash)) return true;
    const auto bytes = EncodeBlock(*block);
    if (m_pending.size() >= MAX_PENDING_BLOCKS || m_pending_bytes + bytes.size() > MAX_PENDING_BYTES) return false;
    if (!m_db.Write(std::make_pair(uint8_t{'b'}, hash), bytes, true)) return false;
    m_pending_bytes += bytes.size();
    m_pending_sizes.emplace(hash, bytes.size());
    m_pending.emplace(hash, std::move(block));
    ++m_revision;
    return true;
}
void HashSnapshotStore::RemoveBlock(const uint256& hash)
{
    AssertLockHeld(cs_main);
    if (!m_pending.contains(hash)) return;
    if (!m_db.Erase(std::make_pair(uint8_t{'b'}, hash), true)) throw std::runtime_error("cannot remove completed pending block");
    m_pending_bytes -= m_pending_sizes.at(hash);
    m_pending_sizes.erase(hash);
    m_pending.erase(hash);
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
