// Coverage for the timewarp attack and the two rules that close it: contiguous retarget
// windows (src/pow.cpp) and a floor on the block that closes a window
// (MinimumClosingBlockTime). Both are stated at their change sites.
//
// Everything here drives the real GetNextWorkRequired(), the real
// MinimumClosingBlockTime() and the real CBlockIndex::GetMedianTimePast() against
// mainnet consensus parameters, so the arithmetic under test is production code. The
// one thing modelled rather than measured is the attacker's hash rate, marked
// ASSUMPTION where it is used.
//
// Height convention, since every test depends on it: GetNextWorkRequired(pindexLast)
// retargets when (pindexLast->nHeight + 1) % 2016 == 0, so a retarget follows only a
// tip at height 2016k - 1. Each test primes the chain to such a height first.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cmath>
#include <optional>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(timewarp_tests, BasicTestingSetup)

namespace {

//! Arbitrary attack start time; nothing depends on its value.
constexpr int64_t T_START{1700000000};

//! nBits for a difficulty 2^shift above the chain's minimum.
uint32_t BitsAboveFloor(const Consensus::Params& params, int shift)
{
    arith_uint256 target = UintToArith256(params.powLimit);
    target >>= shift;
    return target.GetCompact();
}

double TargetOf(uint32_t nbits)
{
    arith_uint256 target;
    target.SetCompact(nbits);
    return target.getdouble();
}

double DifficultyOf(uint32_t nbits, const Consensus::Params& params)
{
    return UintToArith256(params.powLimit).getdouble() / TargetOf(nbits);
}

struct ChainSim {
    std::vector<CBlockIndex> blocks;
    Consensus::Params params;
    size_t n{0};
    //! Lets a test mine what the closing-block floor forbids, to show it is load-bearing.
    bool ignore_closing_floor{false};

    ChainSim(size_t cap, const Consensus::Params& p) : blocks(cap), params(p) {}

    CBlockIndex* Tip() { return &blocks[n - 1]; }

    void Start(int64_t ntime, uint32_t nbits)
    {
        blocks[0].pprev = nullptr;
        blocks[0].nHeight = 0;
        blocks[0].nTime = static_cast<uint32_t>(ntime);
        blocks[0].nBits = nbits;
        blocks[0].BuildSkip();
        n = 1;
    }

    uint32_t NextBits()
    {
        CBlockHeader header;
        header.nTime = static_cast<uint32_t>(Tip()->nTime + 1);
        return GetNextWorkRequired(Tip(), &header, params);
    }

    void Add(int64_t ntime)
    {
        BOOST_REQUIRE(n < blocks.size());
        BOOST_REQUIRE_GE(ntime, MinNextTime());
        CBlockIndex& b = blocks[n];
        b.pprev = &blocks[n - 1];
        b.nHeight = static_cast<int>(n);
        b.nBits = NextBits();
        b.nTime = static_cast<uint32_t>(ntime);
        b.BuildSkip();
        ++n;
    }

    //! Lowest timestamp consensus permits for the next block: median time past plus one,
    //! and the closing-block floor where that applies. Calling the production helper
    //! keeps the simulated attacker inside the rules by construction.
    int64_t MinNextTime()
    {
        int64_t t{Tip()->GetMedianTimePast() + 1};
        if (ignore_closing_floor) return t;
        if (const std::optional<int64_t> closing{MinimumClosingBlockTime(Tip(), params)}) {
            t = std::max(t, *closing);
        }
        return t;
    }

    int64_t TimeAt(int64_t height) const { return static_cast<int64_t>(blocks[height].nTime); }
};

//! Honest mining: blocks arrive at exactly the target spacing.
void HonestBlocks(ChainSim& c, int64_t count)
{
    for (int64_t i = 0; i < count; ++i) c.Add(c.Tip()->nTime + c.params.nPowTargetSpacing);
}

//! Prime a chain to height 2016k - 1, the only height at which a retarget follows.
void PrimeToRetarget(ChainSim& c)
{
    HonestBlocks(c, c.params.DifficultyAdjustmentInterval() - 1);
}

Consensus::Params LegacyParams(const ArgsManager& args)
{
    return CreateChainParams(args, ChainType::MAIN)->GetConsensus();
}

//! Mainnet parameters with the new rules active from the start of the chain.
Consensus::Params ForkParams(const ArgsManager& args)
{
    auto params = LegacyParams(args);
    params.TimewarpFixHeight = 0;
    return params;
}

} // namespace

// The window for the retarget at height R is [R-2016, R-1]: 2016 blocks but only 2015
// inter-block intervals, so a chain running at exactly the target spacing is measured
// one spacing short every period. What that ratio is, rather than where it leads, is
// what this checks: holding the spacing fixed is not an equilibrium under the legacy
// rule, and with the usual difficulty feedback the chain instead settles at a block
// interval of 600 * 2016/2015 = 600.298s, 0.05% slow, for as long as the rule stands.
// The contiguous window measures 2016 intervals, so its ratio is exactly 1 and its
// equilibrium spacing is exactly the target.
BOOST_AUTO_TEST_CASE(off_by_one_biases_honest_chain)
{
    const auto legacy = LegacyParams(*m_node.args);
    const int64_t interval = legacy.DifficultyAdjustmentInterval();
    BOOST_CHECK_EQUAL(interval, 2016);

    const uint32_t start_bits{BitsAboveFloor(legacy, 48)};

    ChainSim c(3 * interval + 2, legacy);
    c.Start(T_START, start_bits);
    PrimeToRetarget(c);
    const double before = TargetOf(c.NextBits());
    HonestBlocks(c, interval);
    const double after = TargetOf(c.NextBits());

    BOOST_TEST_MESSAGE("honest chain, current rule: target ratio per period = "
                       << after / before << " (2015/2016 = " << 2015.0 / 2016.0 << ")");
    BOOST_CHECK_CLOSE(after / before, 2015.0 / 2016.0, 0.01);

    ChainSim f(3 * interval + 2, ForkParams(*m_node.args));
    f.Start(T_START, start_bits);
    PrimeToRetarget(f);
    const double f_before = TargetOf(f.NextBits());
    HonestBlocks(f, interval);
    const double f_after = TargetOf(f.NextBits());

    BOOST_TEST_MESSAGE("honest chain, fork rule:    target ratio per period = " << f_after / f_before);
    BOOST_CHECK_CLOSE(f_after / f_before, 1.0, 0.01);
}

// The attack itself, under today's rules: freeze the period at median time past plus
// one, spike the closing block, and the backward jump into the unmeasured seam costs
// nothing.
BOOST_AUTO_TEST_CASE(current_rule_drains_difficulty)
{
    const auto legacy = LegacyParams(*m_node.args);
    const int64_t interval = legacy.DifficultyAdjustmentInterval();
    const int periods = 8;

    ChainSim c(static_cast<size_t>(interval) * (periods + 2) + 2, legacy);
    const uint32_t start_bits{BitsAboveFloor(legacy, 48)};
    c.Start(T_START, start_bits);
    PrimeToRetarget(c);

    const double d_start = DifficultyOf(start_bits, legacy);
    double real_now = static_cast<double>(c.Tip()->nTime);
    const double real_at_start = real_now;

    for (int p = 0; p < periods; ++p) {
        for (int64_t i = 0; i < interval; ++i) {
            // ASSUMPTION: the attacker holds the hash rate that produced d_start.
            real_now += legacy.nPowTargetSpacing * DifficultyOf(c.NextBits(), legacy) / d_start;
            c.Add(i == interval - 1 ? std::max<int64_t>(c.MinNextTime(),
                                                        static_cast<int64_t>(real_now) + MAX_FUTURE_BLOCK_TIME)
                                    : c.MinNextTime());
        }
    }

    const double d_end = DifficultyOf(c.NextBits(), legacy);
    BOOST_TEST_MESSAGE("current rule: " << periods << " periods, difficulty x" << d_end / d_start
                       << " of start, per-period divisor " << std::pow(d_start / d_end, 1.0 / periods)
                       << ", real time spent " << (real_now - real_at_start) / 86400.0 << "d");
    BOOST_CHECK(d_end < d_start / 100.0);
}

// Contiguous windows mean consecutive windows share an endpoint, so the spans partition
// the chain's own elapsed time exactly. Recovered from the real nBits the code produces:
// with no period clamped, target_new / target_old is the measured span over the target
// timespan, so the sum below is what production actually measured.
BOOST_AUTO_TEST_CASE(windows_partition_chain_time)
{
    const int64_t interval = LegacyParams(*m_node.args).DifficultyAdjustmentInterval();
    const int periods = 4;
    // Per-period spacings that keep every span well inside the clamps.
    const int64_t spacing[periods]{500, 700, 640, 560};

    auto run = [&](const Consensus::Params& params) {
        ChainSim c(static_cast<size_t>(interval) * (periods + 2) + 2, params);
        c.Start(T_START, BitsAboveFloor(params, 48));
        PrimeToRetarget(c);
        const int64_t first_close{c.Tip()->nHeight};
        double measured{0};
        double prev_target{TargetOf(c.NextBits())};
        for (int p = 0; p < periods; ++p) {
            for (int64_t i = 0; i < interval; ++i) c.Add(c.Tip()->nTime + spacing[p]);
            const double target{TargetOf(c.NextBits())};
            measured += (target / prev_target) * params.nPowTargetTimespan;
            prev_target = target;
        }
        const double elapsed = static_cast<double>(c.TimeAt(c.Tip()->nHeight) - c.TimeAt(first_close));
        return std::make_pair(measured, elapsed);
    };

    const auto [fork_measured, fork_elapsed] = run(ForkParams(*m_node.args));
    BOOST_TEST_MESSAGE("fork rule:    measured " << fork_measured << "s over " << fork_elapsed
                       << "s of chain time (" << fork_measured / fork_elapsed << "x)");
    BOOST_CHECK_CLOSE(fork_measured, fork_elapsed, 0.01);

    const auto [legacy_measured, legacy_elapsed] = run(LegacyParams(*m_node.args));
    BOOST_TEST_MESSAGE("current rule: measured " << legacy_measured << "s over " << legacy_elapsed
                       << "s of chain time (" << legacy_measured / legacy_elapsed << "x)");
    BOOST_CHECK_CLOSE(legacy_measured / legacy_elapsed, 2015.0 / 2016.0, 0.01);
}

// The residual that killed the previous attempt at this fix: an asymmetric cycle of two
// long periods (4x down each) paid for by one period whose span the low clamp credits as
// target/4 (4x up). Under contiguous windows alone it ratchets, because closing a period
// below where the window started rewinds chain time and lets the same stretch of real
// time be measured again. The closing-block floor removes the rewind.
//
// What is left once no time can be manufactured is the DAA's own limit. Splitting M
// seconds of chain time into periods of span s maximises the drop at s = e*T, not at the
// 4x clamp: the ratio is (T/s) per period over M/s periods, so the decay is exp(-M/(e*T))
// and a schedule of 4T spans is strictly weaker than one of e*T spans. That is the bound
// asserted here. It is the DAA responding to a chain that really is slow, not a timewarp,
// and it is still anchored because M cannot outrun real time by more than
// MAX_FUTURE_BLOCK_TIME once for the chain's life.
BOOST_AUTO_TEST_CASE(murch_zawy_cycle_cannot_rewind_chain_time)
{
    const auto params = ForkParams(*m_node.args);
    const int64_t interval = params.DifficultyAdjustmentInterval();
    const int64_t T = params.nPowTargetTimespan;
    const int cycles = 3;

    ChainSim c(static_cast<size_t>(interval) * (3 * cycles + 2) + 2, params);
    const uint32_t start_bits{BitsAboveFloor(params, 48)};
    c.Start(T_START, start_bits);
    PrimeToRetarget(c);

    const double d_start = DifficultyOf(start_bits, params);
    const int64_t base = c.TimeAt(c.Tip()->nHeight);
    int64_t last_close{base};
    double measured{0};
    double prev_target{TargetOf(c.NextBits())};

    auto close_period_at = [&](int64_t closing_time) {
        for (int64_t i = 0; i < interval; ++i) {
            c.Add(i == interval - 1 ? std::max(c.MinNextTime(), closing_time) : c.MinNextTime());
        }
        const int64_t close{c.TimeAt(c.Tip()->nHeight)};
        // The rewind the attack depends on: a window must start no earlier than the
        // previous one ended, or the same real time can be measured twice.
        BOOST_CHECK_GE(close, last_close);
        last_close = close;
        const double target{TargetOf(c.NextBits())};
        measured += (target / prev_target) * T;
        prev_target = target;
        return DifficultyOf(c.NextBits(), params);
    };

    double d{d_start};
    for (int k = 0; k < cycles; ++k) {
        d = close_period_at(base + (8 * k + 4) * T + 1);
        BOOST_TEST_MESSAGE("cycle " << k << " long 1:   difficulty x" << d / d_start);
        d = close_period_at(base + (8 * k + 8) * T + 1);
        BOOST_TEST_MESSAGE("cycle " << k << " long 2:   difficulty x" << d / d_start);
        d = close_period_at(0); // as early as consensus permits
        BOOST_TEST_MESSAGE("cycle " << k << " collapse: difficulty x" << d / d_start);
    }

    const double chain_time = static_cast<double>(last_close - base);
    // Tight bound: equal spans of e*T maximise the decay, giving exp(-M/(e*T)).
    const double bound = std::exp(chain_time / (std::exp(1.0) * T));
    // The low clamp credits any span below target/4 as target/4. That credit raises
    // difficulty, so it is the only way measured time may exceed elapsed time.
    const double credit = 3.0 * cycles * T / 4.0;
    BOOST_TEST_MESSAGE("after " << cycles << " asymmetric cycles: difficulty x" << d / d_start
                       << " of start over " << chain_time / 86400.0
                       << "d of chain time; the clamp alone permits x" << 1.0 / bound);
    BOOST_TEST_MESSAGE("measured " << measured / 86400.0 << "d against " << chain_time / 86400.0
                       << "d of chain time plus " << credit / 86400.0 << "d of low-clamp credit");
    BOOST_CHECK_LE(measured, chain_time + credit);
    BOOST_CHECK_GE(d / d_start, 1.0 / bound);
}

// Without the floor the same schedule beats that bound, which is what makes the test
// above load-bearing rather than a restatement of the clamps.
BOOST_AUTO_TEST_CASE(rewinding_the_window_start_beats_the_clamp_bound)
{
    const auto params = ForkParams(*m_node.args);
    const int64_t interval = params.DifficultyAdjustmentInterval();
    const int64_t T = params.nPowTargetTimespan;
    const int cycles = 3;

    ChainSim c(static_cast<size_t>(interval) * (3 * cycles + 2) + 2, params);
    c.ignore_closing_floor = true;
    const uint32_t start_bits{BitsAboveFloor(params, 48)};
    c.Start(T_START, start_bits);
    PrimeToRetarget(c);

    const double d_start = DifficultyOf(start_bits, params);
    const int64_t base = c.TimeAt(c.Tip()->nHeight);
    double measured{0};
    double prev_target{TargetOf(c.NextBits())};

    auto close_period_at = [&](int64_t closing_time) {
        for (int64_t i = 0; i < interval; ++i) {
            c.Add(i == interval - 1 ? std::max(c.MinNextTime(), closing_time) : c.MinNextTime());
        }
        const double target{TargetOf(c.NextBits())};
        measured += (target / prev_target) * T;
        prev_target = target;
        return DifficultyOf(c.NextBits(), params);
    };

    double d{d_start};
    for (int k = 0; k < cycles; ++k) {
        d = close_period_at(base + 4 * T + 1);
        d = close_period_at(base + 8 * T + 1);
        d = close_period_at(0);
    }

    const double chain_time = static_cast<double>(std::max<int64_t>(c.TimeAt(c.Tip()->nHeight) - base, 0));
    const double bound = std::exp(chain_time / (std::exp(1.0) * T));
    const double credit = 3.0 * cycles * T / 4.0;
    BOOST_TEST_MESSAGE("with the window start rewound: difficulty x" << d / d_start << " of start over "
                       << chain_time / 86400.0 << "d of chain time; the clamp alone permits x" << 1.0 / bound);
    BOOST_TEST_MESSAGE("measured " << measured / 86400.0 << "d against " << chain_time / 86400.0
                       << "d of chain time plus " << credit / 86400.0 << "d of low-clamp credit");
    BOOST_CHECK_GT(measured, chain_time + credit);
    BOOST_CHECK_LT(d / d_start, 1.0 / bound);
}

// The floor applies to the block closing a period, and only from the hardfork height.
BOOST_AUTO_TEST_CASE(minimum_closing_block_time_applies_where_stated)
{
    auto params = LegacyParams(*m_node.args);
    const int64_t interval = params.DifficultyAdjustmentInterval();
    // Activate partway along, at a height that is not a period boundary.
    params.TimewarpFixHeight = static_cast<int>(2 * interval + 8);

    ChainSim c(static_cast<size_t>(interval) * 4 + 2, params);
    c.Start(T_START, BitsAboveFloor(params, 48));
    HonestBlocks(c, 4 * interval);

    for (int64_t h = 1; h < 4 * interval; ++h) {
        const CBlockIndex* prev{&c.blocks[h - 1]};
        const auto floor{MinimumClosingBlockTime(prev, params)};
        const bool closes{h % interval == interval - 1 && h >= interval};
        const bool active{h >= params.TimewarpFixHeight};
        BOOST_CHECK_EQUAL(floor.has_value(), closes && active);
        if (floor) BOOST_CHECK_EQUAL(*floor, c.TimeAt(h - interval));
    }
}

// The floor is the block the next retarget measures from, so a block exactly on it
// produces a span of zero and anything below it would produce a negative one.
BOOST_AUTO_TEST_CASE(floor_is_the_next_windows_start)
{
    const auto params = ForkParams(*m_node.args);
    const int64_t interval = params.DifficultyAdjustmentInterval();

    ChainSim c(static_cast<size_t>(interval) * 3 + 2, params);
    c.Start(T_START, BitsAboveFloor(params, 48));
    PrimeToRetarget(c);
    const double before = TargetOf(c.NextBits());

    HonestBlocks(c, interval - 1);
    const auto floor{MinimumClosingBlockTime(c.Tip(), params)};
    BOOST_REQUIRE(floor.has_value());
    HonestBlocks(c, 1);
    BOOST_CHECK_EQUAL(c.Tip()->nHeight, 2 * interval - 1);

    // The retarget that follows measured exactly from the floor.
    const double measured{(TargetOf(c.NextBits()) / before) * params.nPowTargetTimespan};
    BOOST_CHECK_CLOSE(measured, static_cast<double>(c.TimeAt(c.Tip()->nHeight) - *floor), 0.01);
}

// A lower bound on a timestamp could in principle demand a time the future-time limit
// forbids, leaving a period impossible to close. It cannot, because the floor is drawn
// from a timestamp the chain already carries, and every such timestamp was inside some
// node's future-time limit when it was accepted. This drives a chain stamped as far
// ahead as the rules ever allow, which is what keeps the floor as high as it can go.
BOOST_AUTO_TEST_CASE(minimum_time_never_reaches_beyond_the_chain)
{
    const auto params = ForkParams(*m_node.args);
    const int64_t interval = params.DifficultyAdjustmentInterval();

    ChainSim c(static_cast<size_t>(interval) * 3 + 2, params);
    c.Start(T_START, BitsAboveFloor(params, 48));

    int64_t highest{T_START};
    while (c.Tip()->nHeight < 2 * interval) {
        BOOST_CHECK_LE(node::GetMinimumTime(c.Tip(), params), highest + 1);
        const int64_t next{std::max(c.MinNextTime(), highest)};
        c.Add(next);
        highest = std::max(highest, next);
    }
}

// A template must never be built below the floor, or the node would mine a block its own
// validation rejects.
BOOST_AUTO_TEST_CASE(get_minimum_time_applies_the_closing_floor)
{
    const auto params = ForkParams(*m_node.args);
    const int64_t interval = params.DifficultyAdjustmentInterval();

    ChainSim c(static_cast<size_t>(interval) * 3 + 2, params);
    c.Start(T_START, BitsAboveFloor(params, 48));
    HonestBlocks(c, interval - 2);
    // Spike the block that closes the first window far ahead, so median time past
    // afterwards sits below it and only the floor keeps the next closing block legal.
    const int64_t spike{c.Tip()->nTime + 3 * params.nPowTargetTimespan};
    c.Add(spike);
    BOOST_CHECK_EQUAL(c.Tip()->nHeight, interval - 1);
    while (c.Tip()->nHeight < 2 * interval - 2) c.Add(c.MinNextTime());

    const CBlockIndex* prev{c.Tip()};
    BOOST_CHECK_EQUAL((prev->nHeight + 1) % interval, interval - 1);
    BOOST_CHECK_LT(prev->GetMedianTimePast() + 1, spike);
    BOOST_CHECK_EQUAL(node::GetMinimumTime(prev, params), spike);
}

// A window may only be closed contiguously once its closing block carried the floor, or
// the span it produces would not be guaranteed non-negative. Both rules therefore read
// the closing block's height, so the first contiguous retarget is the one whose window
// was closed at or above the activation height. Nothing is grandfathered.
BOOST_AUTO_TEST_CASE(activation_is_gated_on_the_closing_blocks_height)
{
    auto params = LegacyParams(*m_node.args);
    const int64_t interval = params.DifficultyAdjustmentInterval();
    // Partway through the second period: the block closing it is the first to be floored.
    params.TimewarpFixHeight = static_cast<int>(2 * interval + 1);

    ChainSim c(static_cast<size_t>(interval) * 4 + 2, params);
    c.Start(T_START, BitsAboveFloor(params, 48));
    PrimeToRetarget(c);

    // Height 4031 closes the second period below the activation height, so the retarget
    // at 4032 keeps the old window.
    BOOST_CHECK(!MinimumClosingBlockTime(&c.blocks[2 * interval - 2], params).has_value());
    const double at_2016 = TargetOf(c.NextBits());
    HonestBlocks(c, interval);
    const double at_4032 = TargetOf(c.NextBits());

    // Height 6047 closes the third period above it, so the retarget at 6048 is contiguous.
    HonestBlocks(c, interval - 1);
    BOOST_CHECK(MinimumClosingBlockTime(c.Tip(), params).has_value());
    HonestBlocks(c, 1);
    const double at_6048 = TargetOf(c.NextBits());

    BOOST_TEST_MESSAGE("retarget below activation: x" << at_4032 / at_2016
                       << ", first one above it: x" << at_6048 / at_4032);
    BOOST_CHECK_CLOSE(at_4032 / at_2016, 2015.0 / 2016.0, 0.01);
    BOOST_CHECK_CLOSE(at_6048 / at_4032, 1.0, 0.01);
}

// The one-off target shift for the new proof of work algorithm is applied on top of the
// contiguous-window retarget when the hardfork height is itself a retarget height.
BOOST_AUTO_TEST_CASE(target_shift_composes_with_contiguous_windows)
{
    auto params = LegacyParams(*m_node.args);
    const int64_t interval = params.DifficultyAdjustmentInterval();
    params.TimewarpFixHeight = 0;
    params.Blake2bHeight = static_cast<int>(2 * interval);
    params.Blake2bTargetShift = 4;

    ChainSim c(static_cast<size_t>(interval) * 3 + 2, params);
    c.Start(T_START, BitsAboveFloor(params, 48));
    PrimeToRetarget(c);
    HonestBlocks(c, interval);
    BOOST_CHECK_EQUAL(c.Tip()->nHeight + 1, params.Blake2bHeight);
    const uint32_t shifted{c.NextBits()};

    auto unshifted_params = params;
    unshifted_params.Blake2bTargetShift = 0;
    ChainSim u(static_cast<size_t>(interval) * 3 + 2, unshifted_params);
    u.Start(T_START, BitsAboveFloor(params, 48));
    PrimeToRetarget(u);
    HonestBlocks(u, interval);
    const uint32_t unshifted{u.NextBits()};

    BOOST_TEST_MESSAGE("target shift over contiguous windows: x" << TargetOf(shifted) / TargetOf(unshifted));
    BOOST_CHECK_CLOSE(TargetOf(shifted) / TargetOf(unshifted), 16.0, 0.01);
}

BOOST_AUTO_TEST_SUITE_END()
