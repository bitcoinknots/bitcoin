// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <primitives/block.h>
#include <pow.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/chaintype.h>
#include <util/check.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

// The existing `pow` target cannot exercise this code. It sets nHeight and pprev from
// independent ConsumeBool() calls, so a block may claim a height its parent chain does
// not support, and CBlockIndex::GetAncestor asserts on the inconsistency before any
// rule is reached. Mainnet's 2016-block interval also needs a deeper chain than that
// target's entropy builds.
//
// This one builds a well-formed chain instead: heights are consecutive, pprev is
// linked, skip pointers are built, and the retarget interval is shortened so a chain
// long enough to retarget many times fits in a fuzz input. The rules under test do not
// depend on the interval's value.
//
// The attacker model is the strongest one consensus permits: every timestamp is chosen
// freely, subject only to the rules a node would enforce. What is asserted is that the
// two rules stay consistent with each other, and that the security bound they are
// supposed to give actually holds for every schedule reachable this way.

namespace {

//! A short retarget interval, so the fuzzer can reach many retargets.
constexpr int64_t kInterval{16};

Consensus::Params TimewarpParams()
{
    Consensus::Params params{Params().GetConsensus()};
    params.nPowTargetSpacing = 600;
    params.nPowTargetTimespan = kInterval * params.nPowTargetSpacing;
    params.fPowNoRetargeting = false;
    params.fPowAllowMinDifficultyBlocks = false;
    params.enforce_BIP94 = false;
    params.TimewarpFixHeight = 0; // active from the start of the chain
    return params;
}

void initialize_timewarp()
{
    SelectParams(ChainType::MAIN);
}

} // namespace

FUZZ_TARGET(timewarp, .init = initialize_timewarp)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const Consensus::Params params{TimewarpParams()};
    const int64_t interval{params.DifficultyAdjustmentInterval()};
    Assert(interval == kInterval);
    const int64_t T{params.nPowTargetTimespan};

    // Room for several retargets, but bounded so one input cannot run forever.
    const int blocks{provider.ConsumeIntegralInRange<int>(2 * static_cast<int>(interval),
                                                          12 * static_cast<int>(interval))};

    std::vector<std::unique_ptr<CBlockIndex>> chain;
    chain.reserve(static_cast<size_t>(blocks));

    const int64_t start_time{provider.ConsumeIntegralInRange<int64_t>(1'000'000'000, 2'000'000'000)};
    const uint32_t start_bits{UintToArith256(params.powLimit).GetCompact()};

    auto& genesis{*chain.emplace_back(std::make_unique<CBlockIndex>())};
    genesis.pprev = nullptr;
    genesis.nHeight = 0;
    genesis.nTime = static_cast<uint32_t>(start_time);
    genesis.nBits = start_bits;
    genesis.BuildSkip();

    int64_t measured{0};      // sum of the clamped spans the retargets credited
    int retargets{0};
    // The telescoping endpoints: where the first accounted window started and where the
    // last accounted one ended. Block timestamps are not monotonic (only median time
    // past is), so the chain's final block is NOT necessarily its latest timestamp and
    // cannot stand in for these.
    int64_t span_start{-1}, span_end{-1};

    for (int height = 1; height < blocks; ++height) {
        CBlockIndex* prev{chain.back().get()};

        // Lowest timestamp consensus permits here: median time past plus one, and the
        // closing-block floor where it applies.
        int64_t floor_time{prev->GetMedianTimePast() + 1};
        const std::optional<int64_t> closing{MinimumClosingBlockTime(prev, params)};
        if (closing) {
            // THE CONSISTENCY INVARIANT. The floor must anchor to exactly the block the
            // next retarget measures from, or the two rules disagree and a miner can be
            // forced to produce a block validation will reject. height is the closing
            // block, so the retarget follows it at height + 1.
            Assert((height + 1) % interval == 0);
            const CBlockIndex* window_start{prev->GetAncestor(static_cast<int>(height - interval))};
            Assert(window_start != nullptr);
            Assert(*closing == window_start->GetBlockTime());
            floor_time = std::max(floor_time, *closing);
        } else if ((height + 1) % interval == 0 && height >= interval) {
            // A closing block at or above the activation height must always carry a
            // floor; a gap here is the off-by-one that would reopen the attack.
            Assert(false);
        }

        // The attacker picks any legal timestamp at or above the floor.
        const int64_t ntime{provider.ConsumeIntegralInRange<int64_t>(
            floor_time, floor_time + 16 * T)};

        auto& block{*chain.emplace_back(std::make_unique<CBlockIndex>())};
        block.pprev = prev;
        block.nHeight = height;
        block.nTime = static_cast<uint32_t>(ntime);
        CBlockHeader header;
        header.nTime = static_cast<uint32_t>(ntime);
        block.nBits = GetNextWorkRequired(prev, &header, params);
        block.BuildSkip();

        // Account for what each retarget credited, to check the bound at the end.
        if (height % interval == 0 && height > static_cast<int>(interval)) {
            const CBlockIndex* last{block.pprev};                       // closing block
            const CBlockIndex* first{last->GetAncestor(static_cast<int>(last->nHeight - interval))};
            if (first != nullptr) {
                const int64_t span{last->GetBlockTime() - first->GetBlockTime()};
                // Rule B forbids a negative span outright.
                Assert(span >= 0);
                measured += std::clamp<int64_t>(span, T / 4, T * 4);
                if (span_start < 0) span_start = first->GetBlockTime();
                span_end = last->GetBlockTime();
                ++retargets;
            }
        }
    }

    // FindInheritedInvalidBlocks re-derives both rules over the whole block index at
    // startup, for an activation height that need not be the one the chain was built
    // under: that is the late-upgrade case it exists for. Run its two conditions over
    // this chain under a DIFFERENT activation height than it was built with, which is
    // the shape most likely to reach an edge the normal paths do not. Nothing about the
    // verdict is asserted here, because both conditions are "recompute and compare" and
    // any assertion against the same recomputation would only restate determinism. What
    // is being checked is that neither condition can assert, crash, or walk off the end
    // of a chain, for any shape the fuzzer can build.
    {
        Consensus::Params rescan{params};
        rescan.TimewarpFixHeight = provider.ConsumeIntegralInRange<int>(0, blocks + 1);
        // nHeight is stored outside the PoW-committed header and is not checked at load,
        // so an index read from disk can claim a height its parent chain does not
        // support. That is the shape that makes GetAncestor walk past genesis, and it is
        // exactly what a chain built consistently above cannot produce, so perturb one
        // entry here. The scan must skip such an entry rather than judge it.
        if (chain.size() > 2 && provider.ConsumeBool()) {
            const size_t victim{provider.ConsumeIntegralInRange<size_t>(1, chain.size() - 1)};
            chain[victim]->nHeight = provider.ConsumeIntegralInRange<int>(0, 4 * static_cast<int>(interval));
        }
        for (const auto& idx : chain) {
            if (idx->pprev == nullptr) continue;
            if (idx->nHeight != idx->pprev->nHeight + 1) continue;  // as the scan does
            if (const std::optional<int64_t> floor{MinimumClosingBlockTime(idx->pprev, rescan)}) {
                (void)(idx->GetBlockTime() < *floor);
            }
            if (rescan.IsTimewarpFixHeight(idx->pprev->nHeight) &&
                idx->nHeight % rescan.DifficultyAdjustmentInterval() == 0) {
                CBlockHeader h;
                h.nTime = idx->nTime;
                (void)GetNextWorkRequired(idx->pprev, &h, rescan);
            }
        }
    }

    // THE SECURITY BOUND. Contiguous windows make consecutive spans share an endpoint,
    // so they telescope: their sum is exactly span_end - span_start, however the
    // attacker arranges the timestamps in between. The floor keeps each span
    // non-negative, so the only way credited time can exceed that is the low clamp
    // crediting a span below T/4 as T/4.
    if (retargets > 0) {
        const int64_t telescoped{span_end - span_start};
        Assert(telescoped >= 0);
        Assert(measured <= telescoped + retargets * (T / 4));
    }
}
