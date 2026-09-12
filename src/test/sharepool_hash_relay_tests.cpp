// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sharepool/hash_relay.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <chrono>
#include <optional>

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

BOOST_AUTO_TEST_SUITE_END()
