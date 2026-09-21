// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <templatediversity.h>

#include <chain.h>
#include <coins.h>
#include <consensus/validation.h>
#include <kernel/chain.h>
#include <kernel/mempool_entry.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <script/script.h>
#include <script/solver.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <undo.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>

namespace node {
namespace {

constexpr uint32_t VERSION_ROLLING_MASK{0x1fffe000};
constexpr uint32_t VERSION_SIGNAL_MASK{0x00001fff};
//! Shorter printable runs show up by chance in random extranonce bytes often enough to make keys flap.
constexpr size_t MIN_TAG_RUN{5};

int64_t FeerateSatKvB(CAmount fee, int64_t vsize)
{
    if (vsize <= 0) return 0;
    return fee * 1000 / vsize;
}

std::optional<int64_t> Median(std::vector<int64_t> values)
{
    if (values.empty()) return std::nullopt;
    const auto mid{values.begin() + values.size() / 2};
    std::nth_element(values.begin(), mid, values.end());
    return *mid;
}

bool IsPrintable(unsigned char c) { return c >= 0x20 && c < 0x7f; }

std::string ExtractTag(const CScript& script_sig)
{
    CScript::const_iterator pc{script_sig.begin()};
    opcodetype op;
    std::vector<unsigned char> height_push;
    // Skip the BIP34 height so its bytes never read as text.
    if (!script_sig.GetOp(pc, op, height_push)) pc = script_sig.begin();

    std::string tag, run;
    const auto flush{[&] {
        if (run.size() >= MIN_TAG_RUN) tag += (tag.empty() ? "" : " ") + run;
        run.clear();
    }};
    for (; pc < script_sig.end(); ++pc) {
        if (IsPrintable(*pc)) {
            run += char(*pc);
        } else {
            flush();
        }
    }
    flush();
    return tag;
}

std::string StructureKey(const CBlock& block)
{
    const CTransaction& cb{*block.vtx[0]};

    std::string layout;
    const CScript& script_sig{cb.vin[0].scriptSig};
    CScript::const_iterator pc{script_sig.begin()};
    opcodetype op;
    std::vector<unsigned char> data;
    for (int n{0}; pc < script_sig.end(); ++n) {
        if (!script_sig.GetOp(pc, op, data)) {
            layout += ".!";
            break;
        }
        if (n == 0) continue; // BIP34 height
        if (n > 6) {
            layout += ".+";
            break;
        }
        if (op <= OP_PUSHDATA4) {
            // Text is a claim and varies per tag, so only binary pushes contribute their length.
            const bool text{data.size() >= MIN_TAG_RUN && std::all_of(data.begin(), data.end(), IsPrintable)};
            layout += text ? ".a" : strprintf(".%u", data.size());
        } else {
            layout += strprintf(".o%02x", int(op));
        }
    }

    const int commit_idx{GetWitnessCommitmentIndex(block)};
    const std::string commit_pos{commit_idx == NO_WITNESS_COMMITMENT        ? "none" :
                                 size_t(commit_idx) + 1 == cb.vout.size() ? "last" :
                                 commit_idx == 0                          ? "first" :
                                                                            "mid"};

    // Consecutive outputs of one type collapse, so pools that split payouts
    // across a varying number of recipients keep a stable key.
    std::string outs, last_type;
    int payouts{0};
    for (size_t i{0}; i < cb.vout.size(); ++i) {
        if (int(i) == commit_idx) continue;
        std::vector<std::vector<unsigned char>> solutions;
        std::string type{GetTxnOutputType(Solver(cb.vout[i].scriptPubKey, solutions))};
        if (cb.vout[i].nValue == 0) {
            type = "z:" + type;
        } else {
            ++payouts;
        }
        if (type != last_type) {
            outs += (outs.empty() ? "" : ",") + type;
            last_type = type;
        }
    }
    const std::string payout_bucket{payouts <= 1 ? strprintf("%d", payouts) : payouts <= 3 ? "2-3" : "4+"};

    const uint32_t version{static_cast<uint32_t>(block.nVersion)};
    return strprintf("v%d/lt%s/seq%08x/ss%s/wc%s%s/out%s/p%s/top%x/sig%03x/vr%d",
                     cb.version, cb.nLockTime == 0 ? "0" : "n", cb.vin[0].nSequence,
                     layout, commit_pos, cb.vin[0].scriptWitness.IsNull() ? "" : "+w",
                     outs, payout_bucket,
                     version >> 29, version & VERSION_SIGNAL_MASK, (version & VERSION_ROLLING_MASK) != 0);
}

} // namespace

std::string BlockStructureKey(const CBlock& block)
{
    return StructureKey(block);
}

BlockFingerprint FingerprintBlock(const CBlock& block, const CBlockUndo* undo, int height)
{
    BlockFingerprint fp;
    fp.hash = block.GetHash();
    fp.height = height;
    fp.tx_count = block.vtx.size();
    fp.structure_key = StructureKey(block);
    fp.coinbase_tag = ExtractTag(block.vtx[0]->vin[0].scriptSig);

    if (!undo || undo->vtxundo.size() + 1 != block.vtx.size()) return fp;
    fp.have_undo = true;

    CCoinsView dummy;
    CCoinsViewCache view{&dummy};
    std::vector<int64_t> feerates;
    feerates.reserve(block.vtx.size());
    for (size_t i{1}; i < block.vtx.size(); ++i) {
        const CTransaction& tx{*block.vtx[i]};
        const CTxUndo& txundo{undo->vtxundo[i - 1]};
        CAmount value_in{0};
        for (size_t j{0}; j < tx.vin.size(); ++j) {
            const Coin& prev{txundo.vprevout[j]};
            value_in += prev.out.nValue;
            view.AddCoin(tx.vin[j].prevout, Coin{prev}, /*possible_overwrite=*/true);
        }
        const int64_t vsize{(GetTransactionWeight(tx) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR};
        feerates.push_back(FeerateSatKvB(value_in - tx.GetValueOut(), vsize));

        const auto [dc_script, dc_witness] = DatacarrierBytes(tx, view);
        const int64_t dc_bytes{int64_t(dc_script + dc_witness)};
        fp.datacarrier_bytes += dc_bytes;
        if (dc_bytes > MAX_OP_RETURN_RELAY) ++fp.datacarrier_txs;
    }

    if (feerates.size() >= 2) {
        int ordered{0};
        for (size_t i{1}; i < feerates.size(); ++i) {
            if (feerates[i - 1] >= feerates[i]) ++ordered;
        }
        fp.feerate_ordered_pct = int(ordered * 100 / int(feerates.size() - 1));
    }
    if (const auto median{Median(feerates)}) fp.median_feerate = *median;
    return fp;
}

TemplateDiversityTracker::TemplateDiversityTracker(const ChainstateManager& chainman, const CTxMemPool& mempool)
    : m_chainman{chainman}, m_mempool{mempool} {}

void TemplateDiversityTracker::MempoolTransactionsRemovedForBlock(const std::vector<RemovedMempoolTransactionInfo>& txs_removed_for_block, unsigned int nBlockHeight)
{
    std::vector<int64_t> feerates;
    feerates.reserve(txs_removed_for_block.size());
    for (const auto& removed : txs_removed_for_block) {
        feerates.push_back(FeerateSatKvB(removed.info.m_fee, removed.info.m_virtual_transaction_size));
    }
    LOCK(m_mutex);
    m_pending_threshold[nBlockHeight] = Median(std::move(feerates));
    while (m_pending_threshold.size() > 16) m_pending_threshold.erase(m_pending_threshold.begin());
}

void TemplateDiversityTracker::BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex)
{
    if (role == ChainstateRole::BACKGROUND) return;

    const uint256 block_hash{pindex->GetBlockHash()};
    const std::string structure{BlockStructureKey(*block)};
    std::optional<std::optional<int64_t>> pending;
    {
        LOCK(m_mutex);
        const auto it{m_pending_threshold.find(pindex->nHeight)};
        if (it != m_pending_threshold.end()) {
            pending = it->second;
            m_pending_threshold.erase(it);
        }
        // A connection's own submitted blocks must never count as evidence that its structure is common.
        if (!m_local_submissions.contains(block_hash)) {
            ++m_chain_counts[structure];
            m_chain_order.push_back(structure);
            if (m_chain_order.size() > TEMPLATE_DIVERSITY_LIVE_WINDOW) {
                const auto count_it{m_chain_counts.find(m_chain_order.front())};
                if (--count_it->second == 0) m_chain_counts.erase(count_it);
                m_chain_order.pop_front();
            }
        }
    }
    if (!pending || m_chainman.IsInitialBlockDownload()) return;

    // Callbacks run asynchronously, so the mempool may already hold txs that
    // arrived after this block; the age cutoff keeps those from counting.
    LiveSelection live;
    live.threshold_feerate = *pending;
    const int64_t cutoff{GetTime<std::chrono::seconds>().count() - TEMPLATE_DIVERSITY_MIN_AGE_SECONDS};
    {
        LOCK(m_mempool.cs);
        for (const CTxMemPoolEntry& entry : m_mempool.entryAll()) {
            if (entry.GetTime().count() > cutoff) continue;
            ++live.eligible_txs;
            const int64_t own{FeerateSatKvB(entry.GetModifiedFee(), entry.GetTxSize())};
            const int64_t with_ancestors{FeerateSatKvB(entry.GetModFeesWithAncestors(), entry.GetSizeWithAncestors())};
            if (live.threshold_feerate && std::min(own, with_ancestors) <= *live.threshold_feerate) continue;
            ++live.skipped_txs;
            live.skipped_fees += entry.GetModifiedFee();
        }
    }

    LogDebug(BCLog::MEMPOOL, "template diversity: block %s at height %d skipped %d of %d eligible mempool txs\n",
             pindex->GetBlockHash().ToString(), pindex->nHeight, live.skipped_txs, live.eligible_txs);

    LOCK(m_mutex);
    if (m_live.emplace(block_hash, live).second) {
        m_live_order.push_back(block_hash);
        while (m_live_order.size() > TEMPLATE_DIVERSITY_LIVE_WINDOW) {
            m_live.erase(m_live_order.front());
            m_live_order.pop_front();
        }
    }
}

std::optional<LiveSelection> TemplateDiversityTracker::GetLiveSelection(const uint256& block_hash) const
{
    LOCK(m_mutex);
    const auto it{m_live.find(block_hash)};
    if (it == m_live.end()) return std::nullopt;
    return it->second;
}

void TemplateDiversityTracker::MarkLocalSubmission(const uint256& block_hash)
{
    LOCK(m_mutex);
    if (m_local_submissions.insert(block_hash).second) {
        m_local_order.push_back(block_hash);
        while (m_local_order.size() > TEMPLATE_DIVERSITY_LIVE_WINDOW) {
            m_local_submissions.erase(m_local_order.front());
            m_local_order.pop_front();
        }
    }
}

TemplateDiversityTracker::StructureShare TemplateDiversityTracker::GetChainStructureShare(const std::string& structure_key) const
{
    LOCK(m_mutex);
    const auto it{m_chain_counts.find(structure_key)};
    return {it == m_chain_counts.end() ? 0 : it->second, int64_t(m_chain_order.size())};
}

FingerprintWindow CollectRecentFingerprints(ChainstateManager& chainman, const TemplateDiversityTracker* tracker, int nblocks)
{
    struct Pending {
        const CBlockIndex* index;
        bool have_data;
        bool have_undo;
    };
    std::vector<Pending> todo;
    {
        LOCK(cs_main);
        for (const CBlockIndex* pindex{chainman.ActiveChain().Tip()}; pindex && int(todo.size()) < nblocks; pindex = pindex->pprev) {
            todo.push_back({pindex, (pindex->nStatus & BLOCK_HAVE_DATA) != 0, (pindex->nStatus & BLOCK_HAVE_UNDO) != 0});
        }
    }

    FingerprintWindow window;
    for (const Pending& item : todo) {
        CBlock block;
        if (!item.have_data || !chainman.m_blockman.ReadBlock(block, *item.index)) {
            ++window.unavailable;
            continue;
        }
        CBlockUndo undo;
        const bool have_undo{item.have_undo && chainman.m_blockman.ReadBlockUndo(undo, *item.index)};
        window.blocks.emplace_back(FingerprintBlock(block, have_undo ? &undo : nullptr, item.index->nHeight),
                                   tracker ? tracker->GetLiveSelection(item.index->GetBlockHash()) : std::nullopt);
    }
    return window;
}

} // namespace node
