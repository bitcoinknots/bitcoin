// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/args.h>
#include <node/context.h>
#include <node/policy_settings.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/result.h>
#include <util/string.h>

#include <string>
#include <vector>

using node::NodeContext;
using node::PolicySettingDef;
using node::PolicySettingType;

static std::string SettingTypeName(PolicySettingType type)
{
    switch (type) {
    case PolicySettingType::Bool: return "bool";
    case PolicySettingType::Int: return "int";
    case PolicySettingType::Amount: return "amount";
    case PolicySettingType::Number: return "number";
    case PolicySettingType::String: return "string";
    }
    return "string";
}

static RPCHelpMan dumpsettings()
{
    return RPCHelpMan{"dumpsettings",
        "\nExport the node's corepolicy/mempool settings as JSON.\n"
        "Intended for headless deployments that replicate the GUI settings interface over RPC.\n",
        {
            {"detailed", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include per-setting metadata (type and help text) instead of just the value"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::OBJ_DYN, "settings", "map of setting name to value (or, when detailed, to a metadata object)",
                    {
                        {RPCResult::Type::STR, "setting", "the current value (bool/number/string), or a metadata object when detailed"},
                    }},
            },
            /*skip_type_check=*/true},
        RPCExamples{
            HelpExampleCli("dumpsettings", "")
            + HelpExampleCli("dumpsettings", "true")
            + HelpExampleRpc("dumpsettings", "true")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const bool detailed = !request.params[0].isNull() && request.params[0].get_bool();

            NodeContext& node = EnsureAnyNodeContext(request.context);
            const ArgsManager& args = EnsureAnyArgsman(request.context);

            UniValue settings(UniValue::VOBJ);
            for (const PolicySettingDef& def : node::PolicySettingRegistry()) {
                auto value = node::ReadPolicySetting(node, def.name);
                if (!value) continue; // e.g. mempool disabled
                if (!detailed) {
                    settings.pushKV(def.name, *value);
                    continue;
                }
                UniValue meta(UniValue::VOBJ);
                meta.pushKV("value", *value);
                meta.pushKV("type", SettingTypeName(def.type));
                if (def.restart_required) meta.pushKV("restart_required", true);
                if (auto help = args.GetArgHelpText("-" + def.name)) meta.pushKV("help", *help);
                settings.pushKV(def.name, meta);
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("settings", settings);
            return result;
        },
    };
}

static RPCHelpMan setsettings()
{
    return RPCHelpMan{"setsettings",
        "\nUpdate one or more corepolicy/mempool settings.\n"
        "All settings are validated first; if any value is invalid, none are applied.\n"
        "Valid changes are applied to the running node and persisted for restart.\n",
        {
            {"settings", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "Object with setting names as keys and new values as values",
                {
                    {"setting", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A setting name (see dumpsettings) and its new value"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::OBJ_DYN, "results", "map of setting name to result", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::BOOL, "applied", "whether the change was applied"},
                        {RPCResult::Type::BOOL, "restart_required", /*optional=*/true, "whether a restart is required to take effect (only when applied)"},
                        {RPCResult::Type::STR, "error", /*optional=*/true, "why the change failed (only when not applied)"},
                    }},
                }},
            },
            /*skip_type_check=*/true},
        RPCExamples{
            HelpExampleCli("setsettings", "'{\"rejectparasites\": true, \"maxmempool\": 500}'")
            + HelpExampleRpc("setsettings", "{\"rejectparasites\": true}")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const UniValue& settings = request.params[0].get_obj();
            const std::vector<std::string> keys = settings.getKeys();

            NodeContext& node = EnsureAnyNodeContext(request.context);

            // Pass 1: reject unknown keys and validate every value with no side effects.
            std::vector<std::string> errors;
            for (const std::string& key : keys) {
                if (!node::FindPolicySetting(key)) {
                    errors.push_back(strprintf("%s: unknown setting", key));
                    continue;
                }
                auto check = node::ValidatePolicySetting(key, settings[key]);
                if (!check) errors.push_back(strprintf("%s: %s", key, util::ErrorString(check).original));
            }

            if (!errors.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid settings: %s", util::Join(errors, "; ")));
            }

            // Every mempool-backed setting needs the mempool; check once up front so a
            // mid-batch failure cannot leave earlier settings already applied.
            EnsureAnyMemPool(request.context);

            // Pass 2: apply all (validated) changes.
            UniValue results(UniValue::VOBJ);
            for (const std::string& key : keys) {
                const PolicySettingDef* def = node::FindPolicySetting(key);
                auto applied = node::UpdatePolicySetting(node, key, settings[key]);
                UniValue entry(UniValue::VOBJ);
                if (!applied) {
                    entry.pushKV("applied", false);
                    entry.pushKV("error", util::ErrorString(applied).original);
                } else {
                    entry.pushKV("applied", true);
                    entry.pushKV("restart_required", def->restart_required);
                }
                results.pushKV(key, entry);
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("results", results);
            return result;
        },
    };
}

void RegisterSettingsRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"settings", &dumpsettings},
        {"settings", &setsettings},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
