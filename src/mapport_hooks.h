// Copyright (c) 2025 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <common/netif.h>
#include <common/pcp.h>
#include <netaddress.h>
#include <util/threadinterrupt.h>

#include <optional>
#include <variant>
#include <vector>

// Lightweight indirection hooks for mapport's network-dependent helpers.
// These function-pointer hooks default to the real implementations in
// production, and can be reassigned by unit tests at runtime to inject
// deterministic behavior without performing any real network I/O.
namespace mapport_hooks {
using QueryDefaultGateway_t = std::optional<CNetAddr>(*)(Network);
using PCPRequestPortMap_t   = std::variant<MappingResult, MappingError>(*)(
    const PCPMappingNonce&, const CNetAddr&, const CNetAddr&, uint16_t, uint32_t, CThreadInterrupt&);
using NATPMPRequestPortMap_t = std::variant<MappingResult, MappingError>(*)(
    const CNetAddr&, uint16_t, uint32_t, CThreadInterrupt&);
using GetLocalAddresses_t = std::vector<CNetAddr>(*)();

// Defaults point to the real implementations. Tests may override these at runtime.
inline QueryDefaultGateway_t QueryDefaultGatewayFn = QueryDefaultGateway;
inline PCPRequestPortMap_t   PCPRequestPortMapFn = [](const PCPMappingNonce& nonce, const CNetAddr& gateway,
                                                      const CNetAddr& bind, uint16_t port, uint32_t lifetime,
                                                      CThreadInterrupt& interrupt) {
    return PCPRequestPortMap(nonce, gateway, bind, port, lifetime, interrupt);
};
inline NATPMPRequestPortMap_t NATPMPRequestPortMapFn = [](const CNetAddr& gateway, uint16_t port,
                                                          uint32_t lifetime, CThreadInterrupt& interrupt) {
    return NATPMPRequestPortMap(gateway, port, lifetime, interrupt);
};
inline GetLocalAddresses_t GetLocalAddressesFn = [](){ return GetLocalAddresses(); };
} // namespace mapport_hooks
