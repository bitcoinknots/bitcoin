// Copyright (c) 2025 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <mapport.h>
#include <chrono>
#include <thread>
#include <test/util/setup_common.h>
#include <netaddress.h>
#include <netbase.h>
#include <util/threadinterrupt.h>
#include <mapport_hooks.h>

// Simple stub implementations matching the hook signatures (no network IO)
static std::optional<CNetAddr> StubNoGateway(Network) { return std::nullopt; }
static std::vector<CNetAddr> StubNoLocalAddrs() { return {}; }
static std::variant<MappingResult, MappingError> StubPCPNoResources(
    const PCPMappingNonce&, const CNetAddr&, const CNetAddr&, uint16_t, uint32_t, CThreadInterrupt&)
{
    return MappingError{MappingError::NO_RESOURCES};
}
static std::variant<MappingResult, MappingError> StubPMPNoResources(
    const CNetAddr&, uint16_t, uint32_t, CThreadInterrupt&)
{
    return MappingError{MappingError::NO_RESOURCES};
}

struct MapportStubGuard {
    // Save originals
    decltype(mapport_hooks::QueryDefaultGatewayFn)  qdg_orig = mapport_hooks::QueryDefaultGatewayFn;
    decltype(mapport_hooks::PCPRequestPortMapFn)    pcp_orig = mapport_hooks::PCPRequestPortMapFn;
    decltype(mapport_hooks::NATPMPRequestPortMapFn) pmp_orig = mapport_hooks::NATPMPRequestPortMapFn;
    decltype(mapport_hooks::GetLocalAddressesFn)    gla_orig = mapport_hooks::GetLocalAddressesFn;
    ~MapportStubGuard() {
        mapport_hooks::QueryDefaultGatewayFn  = qdg_orig;
        mapport_hooks::PCPRequestPortMapFn    = pcp_orig;
        mapport_hooks::NATPMPRequestPortMapFn = pmp_orig;
        mapport_hooks::GetLocalAddressesFn    = gla_orig;
    }
};

// These tests intentionally avoid enabling any mapping protocol in order to
// exercise the control flow in mapport.cpp without performing any real
// network operations. We rely on the fact that UPnP support is not compiled
// in this build (USE_UPNP undefined). Enabling UPnP will still start the
// mapport thread, but it won't attempt any UPnP work; we immediately
// interrupt to keep the test fast and deterministic.

BOOST_FIXTURE_TEST_SUITE(mapport_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(start_thread_with_upnp_only_then_interrupt)
{
    // Start the background thread by enabling only UPnP (no actual UPnP code
    // will run in this build). Immediately interrupt and stop it to exercise
    // ThreadMapPort(), StartThreadMapPort(), InterruptMapPort(), and StopMapPort().
    StartMapPort(true, false);

    // Give the thread a tiny slice to start. Not strictly necessary, but helps
    // stabilize coverage across machines.
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    InterruptMapPort();
    StopMapPort();

    // Calling stop again should be a no-op.
    StopMapPort();
}

BOOST_AUTO_TEST_CASE(repeated_start_calls_are_idempotent)
{
    // Start once with UPnP only, then start again. The second call should not
    // start a second thread. Interrupt/stop will terminate the single thread.
    StartMapPort(true, false);
    StartMapPort(true, false);

    InterruptMapPort();
    StopMapPort();
}

BOOST_AUTO_TEST_CASE(toggle_enable_disable_sequences)
{
    // Sequence of toggles to exercise DispatchMapPort paths where
    // current==NONE and enabled toggles between NONE and non-NONE.
    StartMapPort(false, false); // No thread should be started.
    StartMapPort(true, false);  // Start thread (UPnP-only path).

    // Disable again while thread may be running. The thread will only exit
    // after interrupt/stop.
    StartMapPort(false, false);
    InterruptMapPort();
    StopMapPort();

    // Final sanity: calls are safe repeatedly.
    InterruptMapPort();
    StopMapPort();
}

BOOST_AUTO_TEST_CASE(start_with_pcp_only_then_interrupt)
{
    // Avoid any real network. Force no default gateways and no local addresses.
    MapportStubGuard guard;
    mapport_hooks::QueryDefaultGatewayFn = &StubNoGateway;
    mapport_hooks::GetLocalAddressesFn = &StubNoLocalAddrs;
    mapport_hooks::PCPRequestPortMapFn = &StubPCPNoResources;
    mapport_hooks::NATPMPRequestPortMapFn = &StubPMPNoResources;

    StartMapPort(false, true);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    InterruptMapPort();
    StopMapPort();
}

BOOST_AUTO_TEST_CASE(enabling_another_protocol_does_not_switch)
{
    // Avoid network: no gateways so PCP does nothing.
    MapportStubGuard guard;
    mapport_hooks::QueryDefaultGatewayFn = [](Network){ return std::optional<CNetAddr>{}; };
    mapport_hooks::GetLocalAddressesFn = [](){ return std::vector<CNetAddr>{}; };

    // Start with PCP only, then enable UPnP in addition. According to
    // DispatchMapPort(), enabling another protocol does not switch away from
    // the currently used one; the dispatch should early-return.
    StartMapPort(false, true); // Start PCP path.
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    // Enable UPnP while PCP is active.
    StartMapPort(true, true);

    // Clean up.
    InterruptMapPort();
    StopMapPort();
}

BOOST_AUTO_TEST_SUITE_END()
