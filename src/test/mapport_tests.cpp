// Copyright (c) 2025 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <mapport.h>

// These tests intentionally avoid enabling any mapping protocol in order to
// exercise the control flow in mapport.cpp without starting background threads
// or performing any network operations.

BOOST_AUTO_TEST_SUITE(mapport_tests)

BOOST_AUTO_TEST_CASE(start_stop_no_protocols)
{
    // Starting with both protocols disabled should be a quick no-op.
    StartMapPort(false, false);

    // Interrupt/Stop should be safe even if the thread was never started.
    InterruptMapPort();
    StopMapPort();

    // Repeat to ensure idempotency of the stop path.
    InterruptMapPort();
    StopMapPort();
}

BOOST_AUTO_TEST_SUITE_END()
