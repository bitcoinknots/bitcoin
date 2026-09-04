// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_POLICY_SETTINGS_H
#define BITCOIN_NODE_POLICY_SETTINGS_H

#include <univalue.h>
#include <util/result.h>

#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace node {
struct NodeContext;

enum class PolicySettingType { Bool, Int, Amount, Number, String };

//! One row per bitcoind config-named corepolicy/mempool setting exposed over RPC.
struct PolicySettingDef {
    std::string name;                //!< bitcoind config option name (e.g. "permitbarepubkey")
    PolicySettingType type;
    bool restart_required{false};    //!< true when a change only takes effect after restart (spkreuse)
    //! Upper bound for Int settings; keeps the unsigned/scaled assignments below from wrapping.
    int64_t max{std::numeric_limits<uint32_t>::max()};
};

//! Ordered registry of all settings exposed by dumpsettings/setsettings.
const std::vector<PolicySettingDef>& PolicySettingRegistry();
const PolicySettingDef* FindPolicySetting(std::string_view name);

//! Read a setting's current live value (from mempool options / policy globals).
util::Result<UniValue> ReadPolicySetting(NodeContext& node, std::string_view name);

//! Validate (coerce and range/format check) a value for a setting without any
//! side effects. Used to make setsettings validate the whole batch before applying.
util::Result<void> ValidatePolicySetting(std::string_view name, const UniValue& value);

//! Validate and apply a setting change: mutate live policy state and write it to
//! the store the GUI uses for that setting (settings.json or the read-write
//! config file). Returns an error if the value is invalid or persistence failed.
util::Result<void> UpdatePolicySetting(NodeContext& node, std::string_view name, const UniValue& value);

} // namespace node

#endif // BITCOIN_NODE_POLICY_SETTINGS_H
