// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sharepool/hash_relay.h>
#include <sharepool/hash_requests.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <optional>
#include <set>

using namespace std::chrono_literals;

BOOST_AUTO_TEST_SUITE(sharepool_hash_relay_tests)

BOOST_AUTO_TEST_CASE(ready_peers_cannot_overtake_each_other)
{
    sharepool::HashRelayTurns turns;
    for (const auto peer : {7, 2, 9, 4}) turns.Ready(peer, false);
    // Repeated arrivals and the order of later scheduler visits cannot move a
    // waiting connection ahead of another. New work rejoins behind waiting work.
    for (int round{0}; round < 20; ++round) {
        for (const auto peer : {7, 2, 9, 4}) {
            for (const auto visited : {4, 9, 2, 7}) turns.Ready(visited, false);
            BOOST_CHECK_EQUAL(turns.Size(), 4U);
            BOOST_CHECK(turns.IsTurn(peer));
            turns.Remove(peer);
            turns.Ready(peer, false);
        }
    }
}

BOOST_AUTO_TEST_CASE(required_data_priority_and_disconnected_turns)
{
    sharepool::HashRelayTurns turns;
    turns.Ready(1, false);
    turns.Ready(2, true);
    turns.Ready(3, true);
    turns.Ready(4, false);
    BOOST_CHECK(turns.IsTurn(2));
    turns.Remove(2); // Disconnection or send-buffer pause must free its turn.
    BOOST_CHECK(turns.IsTurn(3));
    turns.Ready(1, true); // A new block promotes existing speculative work.
    BOOST_CHECK(turns.IsTurn(3));
    turns.Remove(3);
    BOOST_CHECK(turns.IsTurn(1));
    turns.Ready(1, false); // Requirement fulfilled elsewhere; join ordinary tail.
    BOOST_CHECK(turns.IsTurn(4));
    turns.Remove(4);
    turns.Remove(1);
    BOOST_CHECK_EQUAL(turns.Size(), 0U);
    BOOST_CHECK(!turns.IsTurn(1));
}

BOOST_AUTO_TEST_CASE(ordinary_ready_data_gets_service_amid_required_work)
{
    sharepool::HashRelayTurns turns;
    turns.Ready(1, true);
    turns.Ready(2, false);
    for (int cycle{0}; cycle < 3; ++cycle) {
        for (int required{0}; required < 3; ++required) {
            BOOST_CHECK(turns.IsTurn(1));
            turns.Complete(1);
            turns.Ready(1, true);
        }
        BOOST_CHECK(!turns.PreferRequired());
        BOOST_CHECK(turns.IsTurn(2));
        turns.Complete(2);
        turns.Ready(2, false);
        BOOST_CHECK(turns.PreferRequired());
    }
    // Disconnecting an ordinary peer cannot block the remaining required work.
    for (int i{0}; i < 3; ++i) { turns.Complete(1); turns.Ready(1, true); }
    turns.Remove(2);
    BOOST_CHECK(turns.IsTurn(1));
}

BOOST_AUTO_TEST_CASE(block_request_reservations_displace_only_speculative_hints)
{
    // Two tracked blocks, three references each, six slots in total. These
    // small policy bounds exercise full capacity with only a few items.
    sharepool::HashRequestQueue<int> requests{2, 3, 6, 4};
    const auto absent = [](int) { return false; };
    requests.Hint({10, 11, 12, 13}, absent);
    requests.Update(999, {14}, absent); // Untracked callers cannot pin data.
    BOOST_CHECK(requests.Required().empty());
    BOOST_REQUIRE(requests.Track(101, 1, absent));
    requests.Update(101, {2, 3, 4}, absent);
    BOOST_REQUIRE(requests.Track(102, 5, absent));
    requests.Update(102, {6, 7}, absent);
    BOOST_CHECK(requests.Hints().empty());
    const auto needed = requests.Required();
    BOOST_CHECK(std::set<int>(needed.begin(), needed.end()) == std::set<int>({1, 2, 3, 5, 6, 7}));
    BOOST_CHECK_EQUAL(requests.Reservations(), 6U);
    requests.Hint({20, 21}, absent);
    BOOST_CHECK(requests.Hints().empty());
    BOOST_CHECK(!requests.Track(103, 8, absent));
    requests.Forget(101, absent);
    requests.Hint({20, 21, 22}, absent);
    BOOST_CHECK_EQUAL(requests.Hints().size(), 3U);
    BOOST_CHECK_EQUAL(requests.Required().size(), 3U);
}

BOOST_AUTO_TEST_CASE(required_dependencies_refill_progressively_and_keep_their_root)
{
    sharepool::HashRequestQueue<int> requests{1, 3, 3, 1};
    std::set<int> available;
    const auto has = [&](int id) { return available.contains(id); };
    BOOST_REQUIRE(requests.Track(100, 1, has));
    requests.Update(100, {2, 3, 4, 5}, has);
    BOOST_CHECK(requests.Required() == std::vector<int>({1, 2, 3}));
    available.insert(2);
    available.insert(3);
    requests.Update(100, {2, 3, 4, 5}, has);
    BOOST_CHECK(requests.Required() == std::vector<int>({1, 4, 5}));
    requests.Update(100, {}, has);
    BOOST_CHECK(requests.Required() == std::vector<int>({1}));
    available.insert(1);
    requests.Refresh(has);
    BOOST_CHECK(requests.Required().empty());
}

BOOST_AUTO_TEST_CASE(request_rotation_and_shared_provenance_survive_refresh)
{
    sharepool::HashRequestQueue<int> requests{2, 3, 6, 2};
    const auto absent = [](int) { return false; };
    BOOST_REQUIRE(requests.Track(101, 1, absent));
    requests.Update(101, {3}, absent);
    BOOST_REQUIRE(requests.Track(102, 2, absent));
    requests.Update(102, {3, 4}, absent);
    BOOST_CHECK_EQUAL(requests.Required().front(), 2); // New root precedes children.
    const auto initial = requests.Required();
    for (const auto id : initial) {
        BOOST_CHECK_EQUAL(requests.Required().front(), id);
        requests.Requested(id);
        requests.Refresh(absent); // No refresh may undo the issued turn.
    }
    BOOST_CHECK(requests.Required() == initial);
    requests.Forget(101, absent);
    const auto remaining = requests.Required();
    BOOST_CHECK(std::set<int>(remaining.begin(), remaining.end()) == std::set<int>({2, 3, 4}));
    requests.Forget(102, absent);
    BOOST_CHECK(requests.Required().empty());
}

BOOST_AUTO_TEST_CASE(inventory_is_quiet_until_change_or_recovery_replay)
{
    sharepool::HashRelayInventory inventory;
    const auto now = std::chrono::steady_clock::time_point{} + 1s;
    auto page = inventory.Next(1, 4, 256, now);
    BOOST_REQUIRE(page);
    BOOST_CHECK_EQUAL(page->first, 0U);
    BOOST_CHECK_EQUAL(page->second, 4U);
    for (int seconds{1}; seconds < 60; ++seconds) {
        BOOST_CHECK(!inventory.Next(1, 4, 256, now + std::chrono::seconds{seconds}));
    }
    BOOST_CHECK(inventory.Next(1, 4, 256, now + 60s));
    BOOST_CHECK(!inventory.Next(2, 5, 256, now + 60s)); // Keep the one-second rate limit.
    page = inventory.Next(2, 5, 256, now + 61s);
    BOOST_REQUIRE(page);
    BOOST_CHECK_EQUAL(page->second, 5U);
    // A newly connected peer has its own cursor and learns unchanged data.
    sharepool::HashRelayInventory newcomer;
    BOOST_CHECK(newcomer.Next(2, 5, 256, now + 61s));
}

BOOST_AUTO_TEST_CASE(inventory_changes_during_pagination_get_a_full_followup)
{
    sharepool::HashRelayInventory inventory;
    const auto now = std::chrono::steady_clock::time_point{} + 1s;
    auto page = inventory.Next(1, 600, 256, now);
    BOOST_REQUIRE(page);
    BOOST_CHECK_EQUAL(page->second, 256U);
    page = inventory.Next(2, 601, 256, now + 1s);
    BOOST_REQUIRE(page);
    BOOST_CHECK_EQUAL(page->first, 256U);
    BOOST_CHECK_EQUAL(page->second, 512U);
    page = inventory.Next(2, 601, 256, now + 2s);
    BOOST_REQUIRE(page);
    BOOST_CHECK_EQUAL(page->second, 601U);
    // A sorted insertion before the old cursor is recovered without waiting for
    // the periodic replay, or resetting every page while data keeps arriving.
    page = inventory.Next(2, 601, 256, now + 3s);
    BOOST_REQUIRE(page);
    BOOST_CHECK_EQUAL(page->first, 0U);
    BOOST_CHECK_EQUAL(page->second, 256U);
    BOOST_CHECK(inventory.Next(2, 601, 256, now + 4s));
    BOOST_CHECK(inventory.Next(2, 601, 256, now + 5s));
    BOOST_CHECK(!inventory.Next(2, 601, 256, now + 6s));
}

BOOST_AUTO_TEST_CASE(empty_and_shrinking_inventory_does_not_emit_empty_messages)
{
    sharepool::HashRelayInventory inventory;
    const auto now = std::chrono::steady_clock::time_point{} + 1s;
    BOOST_CHECK(!inventory.Next(1, 0, 256, now));
    BOOST_CHECK(!inventory.Next(1, 0, 256, now + 1s));
    BOOST_CHECK(inventory.Next(2, 600, 256, now + 2s));
    // Quarantine may shrink the global inventory below an outstanding cursor.
    BOOST_CHECK(!inventory.Next(3, 2, 256, now + 3s));
    const auto page = inventory.Next(3, 2, 256, now + 4s);
    BOOST_REQUIRE(page);
    BOOST_CHECK_EQUAL(page->first, 0U);
    BOOST_CHECK_EQUAL(page->second, 2U);
}

BOOST_AUTO_TEST_CASE(archive_cursor_replays_after_sixty_seconds_and_finishes_changed_cycles)
{
    sharepool::HashRelayArchiveCursor cursor;
    const auto now = std::chrono::steady_clock::time_point{} + 1s;
    const uint256 first{1}, second{2};
    BOOST_REQUIRE(cursor.Ready(1, now));
    cursor.Advance(first, false, now);
    BOOST_CHECK(!cursor.Ready(2, now));
    BOOST_REQUIRE(cursor.Ready(2, now + 1s));
    BOOST_CHECK(cursor.After() == first); // A new revision never resets the tail.
    cursor.Advance(second, true, now + 1s);
    BOOST_REQUIRE(cursor.Ready(2, now + 2s)); // Replay the changed cycle promptly.
    BOOST_CHECK(!cursor.After());
    cursor.Advance(second, true, now + 2s);
    BOOST_CHECK(!cursor.Ready(2, now + 61s));
    BOOST_CHECK(cursor.Ready(2, now + 62s));
    BOOST_CHECK(!cursor.After());
}

BOOST_AUTO_TEST_CASE(archive_cursor_advances_empty_quarantine_pages)
{
    sharepool::HashRelayArchiveCursor cursor;
    const auto now = std::chrono::steady_clock::time_point{} + 1s;
    BOOST_REQUIRE(cursor.Ready(1, now));
    cursor.Advance(uint256{7}, false, now); // No available hashes in this page.
    BOOST_REQUIRE(cursor.Ready(1, now + 1s));
    BOOST_CHECK(cursor.After() == uint256{7});
    cursor.Advance(uint256{9}, true, now + 1s);
    BOOST_CHECK(!cursor.Ready(1, now + 2s));
}

BOOST_AUTO_TEST_CASE(recent_work_and_archive_tail_both_progress_under_continual_insertion)
{
    sharepool::HashRelayInventoryLanes lanes;
    using Lane = sharepool::HashRelayInventoryLanes::Lane;
    const auto now = std::chrono::steady_clock::time_point{} + 1s;
    // The archived cursor can be far beyond a newly arriving small hash. The
    // live lane's insertion sequence is independent of that archive hash key.
    BOOST_CHECK(lanes.Next(1, 0, now) == Lane::Archive);
    lanes.AdvanceArchive(uint256{100}, false, now);
    for (uint64_t i{1}; i <= 20; ++i) {
        const auto time = now + std::chrono::seconds{2 * i - 1};
        BOOST_CHECK(lanes.Next(i + 1, i, time) == Lane::Recent);
        BOOST_CHECK_EQUAL(lanes.RecentAfter(), i - 1);
        lanes.AdvanceRecent(i, time);
        BOOST_CHECK(lanes.Next(i + 1, i, time) == Lane::None);
        BOOST_CHECK(lanes.Next(i + 1, i, time + 999ms) == Lane::None);
        BOOST_CHECK(lanes.Next(i + 1, i, time + 1s) == Lane::Archive);
        BOOST_CHECK(lanes.ArchiveAfter() == uint256{static_cast<uint8_t>(99 + i)});
        lanes.AdvanceArchive(uint256{static_cast<uint8_t>(100 + i)}, false, time + 1s);
        BOOST_CHECK(lanes.Next(i + 1, i, time + 1s) == Lane::None);
    }
    // Restart resets a store's insertion sequence; an existing cursor reads
    // that reset instead of suppressing all future announcements.
    BOOST_CHECK(lanes.Next(100, 0, now + 41s) == Lane::Recent);
    lanes.AdvanceRecent(0, now + 41s);
}

BOOST_AUTO_TEST_CASE(combined_live_archive_rate_fits_receiver_control_tokens)
{
    sharepool::HashRelayInventoryLanes lanes;
    using Lane = sharepool::HashRelayInventoryLanes::Lane;
    const auto start = std::chrono::steady_clock::time_point{} + 1s;
    double tokens{7}; // The receiver's initial eight tokens minus SPHHELLO.
    size_t recent{0}, archive{0};
    for (uint64_t tick{0}; tick < 1000; ++tick) {
        const auto now = start + std::chrono::milliseconds{tick * 100};
        if (tick) tokens = std::min(8.0, tokens + 0.1);
        const auto lane = lanes.Next(tick + 1, tick + 1, now);
        if (lane == Lane::None) continue;
        BOOST_REQUIRE(tokens >= 1);
        --tokens;
        if (lane == Lane::Recent) {
            ++recent;
            lanes.AdvanceRecent(tick + 1, now);
        } else {
            ++archive;
            lanes.AdvanceArchive(uint256{static_cast<uint8_t>(archive)}, false, now);
        }
        BOOST_CHECK(lanes.Next(tick + 2, tick + 2, now + 999ms) == Lane::None);
    }
    BOOST_CHECK_EQUAL(recent, 50U);
    BOOST_CHECK_EQUAL(archive, 50U);
}

BOOST_AUTO_TEST_CASE(live_event_order_and_repeated_repairs_emit_canonical_wire_inventory)
{
    const std::vector<uint256> events{uint256{9}, uint256{2}, uint256{7}, uint256{2}, uint256{9}};
    const auto wire = sharepool::CanonicalHashInventory(events);
    BOOST_CHECK(wire == std::vector<uint256>({uint256{2}, uint256{7}, uint256{9}}));
    BOOST_CHECK_EQUAL(events.size(), 5U); // Five sequence events, three wire IDs.
    sharepool::HashRelayInventoryLanes lanes;
    const auto now = std::chrono::steady_clock::time_point{} + 1s;
    BOOST_CHECK(lanes.Next(5, 5, now) == sharepool::HashRelayInventoryLanes::Lane::Recent);
    lanes.AdvanceRecent(5, now); // Sorting never substitutes a hash/count for the sequence cursor.
    BOOST_CHECK_EQUAL(lanes.RecentAfter(), 5U);
}

BOOST_AUTO_TEST_CASE(expired_serve_request_no_longer_conflicts_with_new_request)
{
    struct Request {
        int hash;
        std::chrono::steady_clock::time_point deadline;
    };
    const auto now = std::chrono::steady_clock::time_point{} + 1s;
    std::optional<Request> request{Request{1, now + 30s}};
    sharepool::ExpireHashRelayRequest(request, now + 29s);
    BOOST_REQUIRE(request);
    BOOST_CHECK_EQUAL(request->hash, 1);
    // This cleanup is called before the send-pause return and before checking
    // an incoming request for conflicts with the existing request.
    sharepool::ExpireHashRelayRequest(request, now + 30s);
    BOOST_CHECK(!request);
    request.emplace(Request{2, now + 60s});
    sharepool::ExpireHashRelayRequest(request, now + 31s);
    BOOST_REQUIRE(request);
    BOOST_CHECK_EQUAL(request->hash, 2);
    BOOST_CHECK(request->deadline == now + 60s);
}

BOOST_AUTO_TEST_CASE(request_service_keeps_the_existing_burst_and_refill_allowance)
{
    const auto now = std::chrono::steady_clock::time_point{} + 1s;
    sharepool::HashRelayRequestBudget budget{now};
    for (int i{0}; i < 32; ++i) BOOST_REQUIRE(budget.Take(now));
    BOOST_CHECK(!budget.Take(now));
    BOOST_CHECK(!budget.Take(now + 31'249us));
    BOOST_CHECK(budget.Take(now + 31'250us));
    BOOST_CHECK(!budget.Take(now + 31'250us));
    BOOST_CHECK(budget.Take(now + 62'500us));
    // Idle time cannot accumulate an unlimited disk/response burst.
    for (int i{0}; i < 32; ++i) BOOST_REQUIRE(budget.Take(now + 1h));
    BOOST_CHECK(!budget.Take(now + 1h));
    BOOST_CHECK(!budget.Take(now + 1s)); // No credit from a backward timestamp.
}

BOOST_AUTO_TEST_CASE(captured_large_transfer_request_burst_waits_without_being_dropped)
{
    // Actual SPHGET arrival offsets from the failed 100-origin native shared
    // fixture, in microseconds. The old receive-token check disconnected at
    // request51 even though requests were generated by an honest native peer.
    constexpr std::array<int64_t, 51> arrivals{0, 141945, 365278, 375822, 380972, 385716,
        390077, 394237, 398238, 402009, 405795, 409448, 412892, 416300, 419666, 422956,
        426167, 429623, 432810, 435984, 439144, 442250, 445331, 448406, 451457, 454539,
        457621, 460697, 463763, 466813, 469894, 472975, 476055, 479140, 482213, 485306,
        488395, 491481, 604758, 610014, 615046, 619740, 725556, 733698, 740066, 745685,
        861865, 873020, 879784, 885727, 890923};
    struct Request {
        int hash;
        uint32_t offset;
        std::chrono::steady_clock::time_point deadline;
    };
    const auto start = std::chrono::steady_clock::time_point{} + 1s;
    sharepool::HashRelayRequestBudget budget{start};
    std::optional<Request> pending;
    size_t served{0};
    for (size_t i{0}; i < arrivals.size(); ++i) {
        const auto now = start + std::chrono::microseconds{arrivals[i]};
        BOOST_REQUIRE(sharepool::QueueHashRelayRequest(pending, Request{1, uint32_t(i * 65536), now + 30s}, now));
        if (budget.Take(now)) {
            ++served;
            pending.reset();
        }
    }
    BOOST_CHECK_EQUAL(served, 50U);
    BOOST_REQUIRE(pending);
    BOOST_CHECK_EQUAL(pending->offset, 50U * 65536);
    const auto last = start + std::chrono::microseconds{arrivals.back()};
    BOOST_CHECK(!budget.Take(last + 1ms));
    BOOST_REQUIRE(budget.Take(last + 6ms));
    ++served;
    pending.reset();
    BOOST_CHECK_EQUAL(served, arrivals.size());
}

BOOST_AUTO_TEST_CASE(throttled_request_retries_stay_bounded_and_do_not_extend_deadlines)
{
    struct Request {
        int hash;
        uint32_t offset;
        std::chrono::steady_clock::time_point deadline;
    };
    const auto now = std::chrono::steady_clock::time_point{} + 1s;
    sharepool::HashRelayRequestBudget budget{now};
    for (int i{0}; i < 32; ++i) BOOST_REQUIRE(budget.Take(now));
    std::optional<Request> pending;
    BOOST_REQUIRE(sharepool::QueueHashRelayRequest(pending, Request{7, 65536, now + 30s}, now));
    BOOST_CHECK(!budget.Take(now));
    // Coalescing retries entails no extra queued payload, response or disk read.
    for (int i{0}; i < 100; ++i) {
        BOOST_REQUIRE(sharepool::QueueHashRelayRequest(pending, Request{7, 65536, now + 31s}, now + 1ms));
        BOOST_CHECK(!budget.Take(now + 1ms));
        BOOST_CHECK(pending->deadline == now + 30s);
    }
    BOOST_CHECK(!sharepool::QueueHashRelayRequest(pending, Request{8, 65536, now + 31s}, now + 1ms));
    BOOST_CHECK(!sharepool::QueueHashRelayRequest(pending, Request{7, 131072, now + 31s}, now + 1ms));
    BOOST_CHECK_EQUAL(pending->hash, 7);
    BOOST_CHECK_EQUAL(pending->offset, 65536U);
    // Expiry remains effective even when no byte/service credit was available.
    BOOST_REQUIRE(sharepool::QueueHashRelayRequest(pending, Request{8, 0, now + 60s}, now + 30s));
    BOOST_CHECK_EQUAL(pending->hash, 8);
    BOOST_CHECK(pending->deadline == now + 60s);
}

BOOST_AUTO_TEST_SUITE_END()
