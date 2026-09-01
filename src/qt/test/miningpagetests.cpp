// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license.

#include <qt/miningpage.h>
#include <qt/test/miningpagetests.h>

#include <QTest>

#include <cmath>

namespace {
constexpr uint64_t MINUTE_MS{60 * 1000};
constexpr double HASHES_PER_DIFFICULTY{4294967296.0};

void CheckState(const MiningHashrateResult& result, MiningHashrateState state)
{
    QCOMPARE(static_cast<int>(result.state), static_cast<int>(state));
}
} // namespace

void MiningPageTests::hashrateBaselineAndFormula()
{
    MiningHashrateTracker tracker;
    tracker.resume();

    CheckState(tracker.update(0, true, true, 1, 0, 0), MiningHashrateState::CollectingBaseline);
    CheckState(tracker.update(0, true, true, 1, 1, 0), MiningHashrateState::CollectingBaseline);
    CheckState(tracker.update(MINUTE_MS - 1, true, true, 1, 1, 1), MiningHashrateState::CollectingBaseline);

    const MiningHashrateResult result{tracker.update(MINUTE_MS, true, true, 1, 1, 60)};
    CheckState(result, MiningHashrateState::Ready);
    QVERIFY(result.hashrate_ths);
    const double expected{60 * HASHES_PER_DIFFICULTY / 60.0 / 1.0e12};
    QVERIFY(std::abs(*result.hashrate_ths - expected) < 1e-15);
    const MiningHashrateResult held{tracker.update(MINUTE_MS + 30 * 1000, true, true, 1, 1, 120)};
    CheckState(held, MiningHashrateState::Ready);
    QVERIFY(held.hashrate_ths);
    QCOMPARE(*held.hashrate_ths, *result.hashrate_ths);

    MiningHashrateTracker no_shares;
    no_shares.resume();
    no_shares.update(0, true, true, 2, 1, 0);
    const MiningHashrateResult empty{no_shares.update(61 * 1000, true, true, 2, 1, 0)};
    CheckState(empty, MiningHashrateState::NoAcceptedShares);
    QVERIFY(!empty.hashrate_ths);
    const MiningHashrateResult new_share{no_shares.update(90 * 1000, true, true, 2, 1, 1)};
    CheckState(new_share, MiningHashrateState::CollectingBaseline);
    QVERIFY(!new_share.hashrate_ths);

    MiningHashrateTracker non_minute;
    non_minute.resume();
    non_minute.update(0, true, true, 3, 1, 10);
    const MiningHashrateResult irregular{non_minute.update(61 * 1000, true, true, 3, 1, 71)};
    QVERIFY(irregular.hashrate_ths);
    QVERIFY(std::abs(*irregular.hashrate_ths - (61 * HASHES_PER_DIFFICULTY / 61.0 / 1.0e12)) < 1e-15);
}

void MiningPageTests::hashrateWindowAndResets()
{
    MiningHashrateTracker tracker;
    tracker.resume();
    tracker.update(0, true, true, 10, 1, 0);
    for (uint64_t minute = 1; minute <= 5; ++minute) {
        CheckState(tracker.update(minute * MINUTE_MS, true, true, 10, 1, minute * 10), MiningHashrateState::Ready);
    }

    const MiningHashrateResult expired{tracker.update(11 * MINUTE_MS, true, true, 10, 1, 110)};
    CheckState(expired, MiningHashrateState::CollectingBaseline);
    QVERIFY(!expired.hashrate_ths);

    CheckState(tracker.update(12 * MINUTE_MS, true, true, 11, 1, 120), MiningHashrateState::CollectingBaseline);
    CheckState(tracker.update(13 * MINUTE_MS, true, true, 11, 1, 1), MiningHashrateState::CollectingBaseline);
    CheckState(tracker.update(12 * MINUTE_MS, true, true, 11, 1, 2), MiningHashrateState::CollectingBaseline);

    CheckState(tracker.update(13 * MINUTE_MS, false, false, 0, 0, 0), MiningHashrateState::Disabled);
    CheckState(tracker.update(14 * MINUTE_MS, true, false, 0, 0, 0), MiningHashrateState::Stopped);

    MiningHashrateTracker discontinuities;
    discontinuities.resume();
    discontinuities.update(0, true, true, 20, 1, 0);
    CheckState(discontinuities.update(MINUTE_MS, true, true, 20, 1, 10), MiningHashrateState::Ready);
    CheckState(discontinuities.update(2 * MINUTE_MS, true, true, 21, 1, 20), MiningHashrateState::CollectingBaseline);
    QVERIFY(!discontinuities.history().back().hashrate_ths);
    CheckState(discontinuities.update(3 * MINUTE_MS, true, true, 21, 1, 30), MiningHashrateState::Ready);
    CheckState(discontinuities.update(4 * MINUTE_MS, true, true, 21, 1, 1), MiningHashrateState::CollectingBaseline);
    QVERIFY(!discontinuities.history().back().hashrate_ths);
    CheckState(discontinuities.update(5 * MINUTE_MS, true, true, 21, 1, 11), MiningHashrateState::Ready);
    CheckState(discontinuities.update(6 * MINUTE_MS, true, true, 21, 0, 11), MiningHashrateState::CollectingBaseline);
    QVERIFY(!discontinuities.history().back().hashrate_ths);
}

void MiningPageTests::hashrateVisibilityAndHistory()
{
    MiningHashrateTracker tracker;
    tracker.resume();
    tracker.update(0, true, true, 1, 1, 0);
    const MiningHashrateResult current{tracker.update(MINUTE_MS, true, true, 1, 1, 60)};
    CheckState(current, MiningHashrateState::Ready);
    QCOMPARE(tracker.history().size(), 1);
    QVERIFY(current.hashrate_ths);
    QVERIFY(tracker.history().back().hashrate_ths);
    QCOMPARE(*tracker.history().back().hashrate_ths, *current.hashrate_ths);

    tracker.pause(2 * MINUTE_MS);
    QCOMPARE(tracker.history().size(), 2);
    QVERIFY(!tracker.history().back().hashrate_ths);
    tracker.resume();
    CheckState(tracker.update(10 * MINUTE_MS, true, true, 1, 1, 600), MiningHashrateState::CollectingBaseline);
    CheckState(tracker.update(11 * MINUTE_MS, true, true, 1, 1, 660), MiningHashrateState::Ready);

    for (uint64_t minute = 12; minute <= 1500; ++minute) {
        tracker.update(minute * MINUTE_MS, true, true, 1, 1, minute * 60);
    }
    QVERIFY(tracker.history().size() <= 1440);
    QVERIFY(tracker.history().front().timestamp_ms >= (1500 - 1440) * MINUTE_MS);
}

void MiningPageTests::networkHashrateAndChance()
{
    QVERIFY(!MiningNetworkHashrateThs(0));
    QVERIFY(!MiningNetworkHashrateThs(-1));
    const auto network{MiningNetworkHashrateThs(1)};
    QVERIFY(network);
    QVERIFY(std::abs(*network - HASHES_PER_DIFFICULTY / 600.0 / 1.0e12) < 1e-15);
    QCOMPARE(MiningHashrateText(*network), QStringLiteral("7.2 MH/s"));
    const auto regtest_network{MiningNetworkHashrateThs(4.656542373906925e-10)};
    QVERIFY(regtest_network);
    QCOMPARE(MiningHashrateText(*regtest_network), QStringLiteral("0.00333 H/s"));
    QCOMPARE(MiningHashrateText(0.000143), QStringLiteral("143.0 MH/s"));
    QCOMPARE(MiningHashrateText(0.143), QStringLiteral("143.0 GH/s"));

    QVERIFY(!MiningChancePerBlockPercent(1, 0));
    const auto tiny{MiningChancePerBlockPercent(*network * 1e-8, 1)};
    QVERIFY(tiny);
    QCOMPARE(MiningChanceText(tiny), QStringLiteral("1e-06%"));
    const auto capped{MiningChancePerBlockPercent(*network * 2, 1)};
    QVERIFY(capped);
    QCOMPARE(*capped, 100.0);
    QCOMPARE(MiningChanceText(capped), QStringLiteral("100%"));
}

void MiningPageTests::hashrateAxisUsesHundreds()
{
    const MiningHashrateAxis low_mh{MiningHashrateAxisFor(0.0000716)};
    QCOMPARE(low_mh.unit, QStringLiteral("MH/s"));
    QCOMPARE(std::llround(low_mh.tick_ths / low_mh.unit_ths), 100LL);
    QCOMPARE(std::llround(low_mh.maximum_ths / low_mh.unit_ths), 100LL);

    const MiningHashrateAxis mh{MiningHashrateAxisFor(0.0003195)};
    QCOMPARE(mh.unit, QStringLiteral("MH/s"));
    QCOMPARE(std::llround(mh.tick_ths / mh.unit_ths), 100LL);
    QCOMPARE(std::llround(mh.maximum_ths / mh.unit_ths), 400LL);

    const MiningHashrateAxis gh{MiningHashrateAxisFor(1.2)};
    QCOMPARE(gh.unit, QStringLiteral("GH/s"));
    QCOMPARE(std::llround(gh.tick_ths / gh.unit_ths), 500LL);
    QCOMPARE(std::llround(gh.maximum_ths / gh.unit_ths), 1500LL);

    const MiningHashrateAxis th{MiningHashrateAxisFor(200)};
    QCOMPARE(th.unit, QStringLiteral("TH/s"));
    QCOMPARE(std::llround(th.tick_ths / th.unit_ths), 100LL);
    QCOMPARE(std::llround(th.maximum_ths / th.unit_ths), 300LL);
}

void MiningPageTests::bestShareFormatting()
{
    QCOMPARE(MiningBestShareText(0), QStringLiteral("—"));
    QCOMPARE(MiningBestShareText(32768), QStringLiteral("32768"));
    QCOMPARE(MiningBestShareText(1000000), QStringLiteral("1M"));
    QCOMPARE(MiningBestShareText(189000000), QStringLiteral("189M"));
    QCOMPARE(MiningBestShareText(1234567), QStringLiteral("1.23M"));
    QCOMPARE(MiningBestShareText(999500000), QStringLiteral("1G"));
    QCOMPARE(MiningBestShareText(876000000000000), QStringLiteral("876T"));
}

void MiningPageTests::summaryLabelsDistinguishSharesAndBlocks()
{
    QCOMPARE(MiningSummaryMetricText(0), QStringLiteral("Accepted shares"));
    QCOMPARE(MiningSummaryMetricText(1), QStringLiteral("Rejected shares"));
    QCOMPARE(MiningSummaryMetricText(2), QStringLiteral("Stale / obsolete shares"));
    QCOMPARE(MiningSummaryMetricText(3), QStringLiteral("Other rejected shares"));
    QCOMPARE(MiningSummaryMetricText(4), QStringLiteral("Best Share"));
    QCOMPARE(MiningSummaryMetricText(5), QStringLiteral("Block submissions"));
}
