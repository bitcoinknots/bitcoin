// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/policy_settings.h>

#include <common/args.h>
#include <common/settings.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <kernel/mempool_options.h>
#include <node/context.h>
#include <node/mempool_args.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <sync.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <validation.h>

#include <chrono>
#include <optional>

using common::SettingsValue;

namespace node {

namespace {

// Coerced/validated form of an incoming value, filled per setting type.
struct Normalized {
    bool b{false};
    int64_t i{0};
    CAmount amount{0};      // for Amount: satoshis-per-kvB
    int64_t hundredths{0};  // for Number (fixed-point, 2 decimals)
    std::string s;
};

// Persist to settings.json (mirrors interfaces::Node::updateRwSetting).
[[nodiscard]] bool PersistJson(ArgsManager& args, const std::string& key, const SettingsValue& value)
{
    args.LockSettings([&](common::Settings& settings) {
        if (value.isNull()) {
            settings.rw_settings.erase(key);
        } else {
            settings.rw_settings[key] = value;
        }
    });
    return args.WriteSettingsFile();
}

CTxMemPool* MemPool(NodeContext& node) { return node.mempool.get(); }

[[nodiscard]] bool CoerceBool(const UniValue& v, bool& out)
{
    if (v.isBool()) { out = v.get_bool(); return true; }
    if (v.isNum()) { out = v.getInt<int>() != 0; return true; }
    if (v.isStr()) {
        const std::string& s = v.get_str();
        if (s == "1" || s == "true") { out = true; return true; }
        if (s == "0" || s == "false") { out = false; return true; }
    }
    return false;
}

[[nodiscard]] bool CoerceInt(const UniValue& v, int64_t& out)
{
    if (v.isNum()) { out = v.getInt<int64_t>(); return true; }
    if (v.isStr()) { return ParseInt64(v.get_str(), &out); }
    return false;
}

// Reverse of the -mempoolreplacement / -mempooltruc string parsers (matches the
// GUI's CanonicalMempoolReplacement / CanonicalMempoolTRUC).
std::string RbfPolicyToString(RBFPolicy p)
{
    switch (p) {
    case RBFPolicy::Never:  return "never";
    case RBFPolicy::OptIn:  return "fee,optin";
    case RBFPolicy::Always: return "fee,-optin";
    }
    return "fee,-optin";
}

std::string TrucPolicyToString(TRUCPolicy p)
{
    switch (p) {
    case TRUCPolicy::Reject:  return "reject";
    case TRUCPolicy::Accept:  return "accept";
    case TRUCPolicy::Enforce: return "enforce";
    }
    return "accept";
}

std::string PermitEphemeralToString(const kernel::MemPoolOptions& o)
{
    if (!(o.permitephemeral_anchor || o.permitephemeral_send || o.permitephemeral_dust)) return "reject";
    return std::string(o.permitephemeral_anchor ? "" : "-") + "anchor," +
           (o.permitephemeral_send ? "" : "-") + "send," +
           (o.permitephemeral_dust ? "" : "-") + "dust";
}

// Registry, ordered for stable output. Grouped by category for readability.
const std::vector<PolicySettingDef> g_registry{
    // mempool
    {"maxmempool", PolicySettingType::Int},
    {"mempoolexpiry", PolicySettingType::Int},
    {"mempoolreplacement", PolicySettingType::String},
    {"mempooltruc", PolicySettingType::String},
    {"minrelaytxfee", PolicySettingType::Amount},
    {"incrementalrelayfee", PolicySettingType::Amount},
    {"minrelaycoinblocks", PolicySettingType::Int},
    {"minrelaymaturity", PolicySettingType::Int},
    {"limitancestorcount", PolicySettingType::Int},
    {"limitancestorsize", PolicySettingType::Int},
    {"limitdescendantcount", PolicySettingType::Int},
    {"limitdescendantsize", PolicySettingType::Int},
    // policy toggles
    {"rejectparasites", PolicySettingType::Bool},
    {"rejecttokens", PolicySettingType::Bool},
    {"subdustfeepenalty", PolicySettingType::Bool},
    {"acceptnonstdtxn", PolicySettingType::Bool},
    {"acceptunknownwitness", PolicySettingType::Bool},
    {"permitbaremultisig", PolicySettingType::Bool},
    {"permitbarepubkey", PolicySettingType::Bool},
    {"permitbareanchor", PolicySettingType::Bool},
    {"permitbaredatacarrier", PolicySettingType::Bool},
    {"permitephemeral", PolicySettingType::String},
    {"spkreuse", PolicySettingType::String, /*restart_required=*/true},
    // data carrier
    {"datacarriersize", PolicySettingType::Int},
    {"acceptnonstddatacarrier", PolicySettingType::Bool},
    {"datacarriercost", PolicySettingType::Number},
    // sigops / script
    {"bytespersigop", PolicySettingType::Int},
    {"bytespersigopstrict", PolicySettingType::Int},
    {"maxscriptsize", PolicySettingType::Int},
    {"maxtxlegacysigops", PolicySettingType::Int},
    // dust
    {"dustrelayfee", PolicySettingType::Amount},
    {"dustdynamic", PolicySettingType::String},
};

// Validate + coerce an incoming value for the given setting. No side effects.
util::Result<Normalized> Normalize(const PolicySettingDef& def, const UniValue& value)
{
    Normalized n;
    switch (def.type) {
    case PolicySettingType::Bool:
        if (!CoerceBool(value, n.b)) return util::Error{Untranslated(strprintf("%s must be a boolean", def.name))};
        return n;
    case PolicySettingType::Int:
        if (!CoerceInt(value, n.i)) return util::Error{Untranslated(strprintf("%s must be an integer", def.name))};
        if (n.i < 0) return util::Error{Untranslated(strprintf("%s must not be negative", def.name))};
        if (n.i > def.max) return util::Error{Untranslated(strprintf("%s must not be greater than %d", def.name, def.max))};
        return n;
    case PolicySettingType::Amount: {
        const std::string s = value.isNum() ? value.getValStr() : (value.isStr() ? value.get_str() : "");
        std::optional<CAmount> parsed = ParseMoney(s);
        if (!parsed) return util::Error{Untranslated(strprintf("%s is not a valid amount", def.name))};
        n.amount = *parsed;
        return n;
    }
    case PolicySettingType::Number: {
        const std::string s = value.isNum() ? value.getValStr() : (value.isStr() ? value.get_str() : "");
        if (!ParseFixedPoint(s, 2, &n.hundredths) || n.hundredths < 0) {
            return util::Error{Untranslated(strprintf("%s is not a valid number", def.name))};
        }
        return n;
    }
    case PolicySettingType::String:
        if (!value.isStr()) return util::Error{Untranslated(strprintf("%s must be a string", def.name))};
        n.s = value.get_str();
        // Per-setting string validation, reusing the startup parsers.
        if (def.name == "mempooltruc") {
            if (n.s != "reject" && n.s != "accept" && n.s != "enforce") {
                return util::Error{Untranslated("mempooltruc must be one of: reject, accept, enforce")};
            }
        } else if (def.name == "spkreuse") {
            if (n.s != "conflict" && n.s != "allow") {
                return util::Error{Untranslated("spkreuse must be one of: conflict, allow")};
            }
        } else if (def.name == "dustdynamic") {
            auto parsed = ParseDustDynamicOpt(n.s, /*max_fee_estimate_blocks=*/1008);
            if (!parsed) return util::Error{util::ErrorString(parsed)};
        } else if (def.name == "permitephemeral") {
            // Validate by applying to a throwaway options struct.
            kernel::MemPoolOptions probe;
            ApplyPermitEphemeralOption(SettingsValue(n.s), probe);
        }
        // mempoolreplacement accepts any comma list; parsed leniently at startup.
        return n;
    }
    return util::Error{Untranslated("unknown setting type")};
}

} // namespace

const std::vector<PolicySettingDef>& PolicySettingRegistry() { return g_registry; }

const PolicySettingDef* FindPolicySetting(std::string_view name)
{
    for (const auto& def : g_registry) {
        if (def.name == name) return &def;
    }
    return nullptr;
}

util::Result<void> ValidatePolicySetting(std::string_view name, const UniValue& value)
{
    const PolicySettingDef* def = FindPolicySetting(name);
    if (!def) return util::Error{Untranslated(strprintf("unknown setting: %s", name))};
    auto norm = Normalize(*def, value);
    if (!norm) return util::Error{util::ErrorString(norm)};
    return {};
}

util::Result<UniValue> ReadPolicySetting(NodeContext& node, std::string_view name)
{
    const PolicySettingDef* def = FindPolicySetting(name);
    if (!def) return util::Error{Untranslated(strprintf("unknown setting: %s", name))};

    ArgsManager& args = *Assert(node.args);
    CTxMemPool* pool = MemPool(node);
    const std::string n{name};

    // Settings not backed by live mempool options.
    if (n == "datacarriercost") return UniValue(double(g_weight_per_data_byte) / WITNESS_SCALE_FACTOR);
    if (n == "bytespersigop") return UniValue((int64_t)nBytesPerSigOp);
    if (n == "bytespersigopstrict") return UniValue((int64_t)nBytesPerSigOpStrict);
    if (n == "maxscriptsize") return UniValue((int64_t)g_script_size_policy_limit);
    if (n == "spkreuse") return UniValue(args.GetArg("-spkreuse", "allow"));

    if (!pool) return util::Error{Untranslated("mempool not available")};
    const kernel::MemPoolOptions& o = pool->m_opts;

    if (n == "maxmempool") return UniValue((int64_t)(o.max_size_bytes / 1'000'000));
    if (n == "mempoolexpiry") return UniValue((int64_t)std::chrono::duration_cast<std::chrono::hours>(o.expiry).count());
    if (n == "mempoolreplacement") return UniValue(RbfPolicyToString(o.rbf_policy));
    if (n == "mempooltruc") return UniValue(TrucPolicyToString(o.truc_policy));
    if (n == "minrelaytxfee") return UniValue(UniValue::VNUM, FormatMoney(o.min_relay_feerate.GetFeePerK()));
    if (n == "incrementalrelayfee") return UniValue(UniValue::VNUM, FormatMoney(o.incremental_relay_feerate.GetFeePerK()));
    if (n == "minrelaycoinblocks") return UniValue((int64_t)o.minrelaycoinblocks);
    if (n == "minrelaymaturity") return UniValue((int64_t)o.minrelaymaturity);
    if (n == "limitancestorcount") return UniValue((int64_t)o.limits.ancestor_count);
    if (n == "limitancestorsize") return UniValue((int64_t)(o.limits.ancestor_size_vbytes / 1'000));
    if (n == "limitdescendantcount") return UniValue((int64_t)o.limits.descendant_count);
    if (n == "limitdescendantsize") return UniValue((int64_t)(o.limits.descendant_size_vbytes / 1'000));
    if (n == "rejectparasites") return UniValue(o.reject_parasites);
    if (n == "rejecttokens") return UniValue(o.reject_tokens);
    if (n == "subdustfeepenalty") return UniValue(o.subdustfeepenalty);
    if (n == "acceptnonstdtxn") return UniValue(!o.require_standard);
    if (n == "acceptunknownwitness") return UniValue(o.acceptunknownwitness);
    if (n == "permitbaremultisig") return UniValue(o.permit_bare_multisig);
    if (n == "permitbarepubkey") return UniValue(o.permit_bare_pubkey);
    if (n == "permitbareanchor") return UniValue(o.permitbareanchor);
    if (n == "permitbaredatacarrier") return UniValue(o.permitbaredatacarrier);
    if (n == "permitephemeral") return UniValue(PermitEphemeralToString(o));
    if (n == "datacarriersize") return UniValue((int64_t)o.max_datacarrier_bytes.value_or(0));
    if (n == "acceptnonstddatacarrier") return UniValue(o.accept_non_std_datacarrier);
    if (n == "maxtxlegacysigops") return UniValue((int64_t)o.maxtxlegacysigops);
    if (n == "dustrelayfee") return UniValue(UniValue::VNUM, FormatMoney(o.dust_relay_feerate_floor.GetFeePerK()));
    // dustdynamic is read from the persisted setting string (matches the GUI); we
    // persist it on every change, so this reflects the current value.
    if (n == "dustdynamic") return UniValue(args.GetArg("-dustdynamic", DEFAULT_DUST_DYNAMIC));

    return util::Error{Untranslated(strprintf("unhandled setting: %s", name))};
}

util::Result<void> UpdatePolicySetting(NodeContext& node, std::string_view name, const UniValue& value)
{
    const PolicySettingDef* def = FindPolicySetting(name);
    if (!def) return util::Error{Untranslated(strprintf("unknown setting: %s", name))};

    auto norm = Normalize(*def, value);
    if (!norm) return util::Error{util::ErrorString(norm)};
    const Normalized& nv = *norm;

    ArgsManager& args = *Assert(node.args);
    CTxMemPool* pool = MemPool(node);
    const std::string n{name};

    // Persist helpers. Only the settings.json path can report a write failure;
    // ModifyRWConfigFile() has no status to propagate.
    auto json = [&](const std::string& key, const SettingsValue& v) -> util::Result<void> {
        if (!PersistJson(args, key, v)) return util::Error{Untranslated(strprintf("failed to write settings file for %s", key))};
        return {};
    };
    auto rwconf = [&](const std::string& key, const std::string& v) { args.ModifyRWConfigFile(key, v); };

    // ---- Globals (no mempool required) ----
    if (n == "datacarriercost") {
        g_weight_per_data_byte = (unsigned int)((nv.hundredths * WITNESS_SCALE_FACTOR + 99) / 100);
        return json("datacarriercost", UniValue(double(nv.hundredths) / 100.0));
    }
    if (n == "bytespersigop") { nBytesPerSigOp = (unsigned int)nv.i; rwconf("bytespersigop", strprintf("%d", nv.i)); return {}; }
    if (n == "bytespersigopstrict") { nBytesPerSigOpStrict = (unsigned int)nv.i; rwconf("bytespersigopstrict", strprintf("%d", nv.i)); return {}; }
    if (n == "maxscriptsize") { g_script_size_policy_limit = (unsigned int)nv.i; return json("maxscriptsize", UniValue(nv.i)); }
    if (n == "spkreuse") { rwconf("spkreuse", nv.s); return {}; } // restart-required; no live field

    if (!pool) return util::Error{Untranslated("mempool not available")};
    kernel::MemPoolOptions& o = pool->m_opts;

    // ---- Mempool size / expiry (with live trim on shrink) ----
    if (n == "maxmempool" || n == "mempoolexpiry") {
        bool shrink;
        if (n == "maxmempool") {
            const int64_t old = o.max_size_bytes;
            o.max_size_bytes = nv.i * 1'000'000;
            shrink = o.max_size_bytes < old;
            args.ForceSetArg("-maxmempool", strprintf("%d", nv.i));
            rwconf("maxmempool", strprintf("%d", nv.i));
        } else {
            const auto old = o.expiry;
            o.expiry = std::chrono::hours{nv.i};
            shrink = o.expiry < old;
            args.ForceSetArg("-mempoolexpiry", strprintf("%d", nv.i));
            rwconf("mempoolexpiry", strprintf("%d", nv.i));
        }
        if (shrink && node.chainman) {
            LOCK(cs_main);
            LOCK(pool->cs);
            LimitMempoolSize(*pool, node.chainman->ActiveChainstate().CoinsTip());
        }
        return {};
    }

    // ---- Ancestor/descendant limits ----
    if (n == "limitancestorcount") { o.limits.ancestor_count = nv.i; args.ForceSetArg("-limitancestorcount", strprintf("%d", nv.i)); rwconf("limitancestorcount", strprintf("%d", nv.i)); return {}; }
    if (n == "limitancestorsize") { o.limits.ancestor_size_vbytes = nv.i * 1'000; args.ForceSetArg("-limitancestorsize", strprintf("%d", nv.i)); rwconf("limitancestorsize", strprintf("%d", nv.i)); return {}; }
    if (n == "limitdescendantcount") { o.limits.descendant_count = nv.i; args.ForceSetArg("-limitdescendantcount", strprintf("%d", nv.i)); rwconf("limitdescendantcount", strprintf("%d", nv.i)); return {}; }
    if (n == "limitdescendantsize") { o.limits.descendant_size_vbytes = nv.i * 1'000; args.ForceSetArg("-limitdescendantsize", strprintf("%d", nv.i)); rwconf("limitdescendantsize", strprintf("%d", nv.i)); return {}; }

    // ---- Fee rates (satoshis-per-kvB via ParseMoney) ----
    if (n == "minrelaytxfee") { o.min_relay_feerate = CFeeRate(nv.amount); rwconf("minrelaytxfee", FormatMoney(nv.amount)); return {}; }
    if (n == "incrementalrelayfee") { o.incremental_relay_feerate = CFeeRate(nv.amount); rwconf("incrementalrelayfee", FormatMoney(nv.amount)); return {}; }
    if (n == "dustrelayfee") {
        const CFeeRate feerate{nv.amount};
        o.dust_relay_feerate_floor = feerate;
        if (o.dust_relay_feerate < feerate || !o.dust_relay_target) {
            o.dust_relay_feerate = feerate;
        } else {
            pool->UpdateDynamicDustFeerate();
        }
        rwconf("dustrelayfee", FormatMoney(nv.amount));
        return {};
    }

    // ---- Simple integer m_opts, persisted to settings.json ----
    if (n == "minrelaycoinblocks") { o.minrelaycoinblocks = nv.i; return json("minrelaycoinblocks", UniValue(nv.i)); }
    if (n == "minrelaymaturity") { o.minrelaymaturity = nv.i; return json("minrelaymaturity", UniValue(nv.i)); }
    if (n == "maxtxlegacysigops") { o.maxtxlegacysigops = nv.i; return json("maxtxlegacysigops", UniValue(nv.i)); }

    // ---- Boolean policy toggles ----
    if (n == "rejectparasites") { o.reject_parasites = nv.b; return json("rejectparasites", UniValue(nv.b)); }
    if (n == "rejecttokens") { o.reject_tokens = nv.b; return json("rejecttokens", UniValue(nv.b)); }
    if (n == "subdustfeepenalty") { o.subdustfeepenalty = nv.b; return json("subdustfeepenalty", UniValue(nv.b)); }
    if (n == "acceptunknownwitness") { o.acceptunknownwitness = nv.b; return json("acceptunknownwitness", UniValue(nv.b)); }
    if (n == "permitbarepubkey") { o.permit_bare_pubkey = nv.b; return json("permitbarepubkey", UniValue(nv.b)); }
    if (n == "permitbareanchor") { o.permitbareanchor = nv.b; return json("permitbareanchor", UniValue(nv.b)); }
    if (n == "permitbaredatacarrier") { o.permitbaredatacarrier = nv.b; return json("permitbaredatacarrier", UniValue(nv.b)); }
    if (n == "acceptnonstddatacarrier") { o.accept_non_std_datacarrier = nv.b; return json("acceptnonstddatacarrier", UniValue(nv.b)); }
    if (n == "acceptnonstdtxn") { o.require_standard = !nv.b; rwconf("acceptnonstdtxn", strprintf("%d", nv.b)); return {}; }
    if (n == "permitbaremultisig") { o.permit_bare_multisig = nv.b; rwconf("permitbaremultisig", strprintf("%d", nv.b)); return {}; }

    // ---- Data carrier size (toggles the datacarrier bool key) ----
    if (n == "datacarriersize") {
        if (nv.i > 0) {
            if (!o.max_datacarrier_bytes.has_value()) rwconf("datacarrier", "1");
            rwconf("datacarriersize", strprintf("%d", nv.i));
            o.max_datacarrier_bytes = (unsigned)nv.i;
        } else {
            rwconf("datacarrier", "0");
            o.max_datacarrier_bytes = std::nullopt;
        }
        return {};
    }

    // ---- Special string settings ----
    if (n == "mempoolreplacement") {
        // Match the startup token parser (see ApplyArgsManOptions in mempool_args.cpp).
        std::optional<bool> optin;
        bool fee{false};
        for (const auto& opt : util::SplitString(nv.s, ",+")) {
            if (opt == "optin") optin = true;
            else if (opt == "-optin") optin = false;
            else if (opt == "fee") fee = true;
        }
        o.rbf_policy = optin.value_or(false) ? RBFPolicy::OptIn : (fee ? RBFPolicy::Always : RBFPolicy::Never);
        args.ModifyRWConfigFile("mempoolreplacement", nv.s);
        return json("mempoolfullrbf", UniValue(o.rbf_policy == RBFPolicy::Always ? "1" : "0"));
    }
    if (n == "mempooltruc") {
        o.truc_policy = (nv.s == "reject") ? TRUCPolicy::Reject : (nv.s == "enforce") ? TRUCPolicy::Enforce : TRUCPolicy::Accept;
        return json("mempooltruc", UniValue(nv.s));
    }
    if (n == "permitephemeral") {
        ApplyPermitEphemeralOption(SettingsValue(nv.s), o);
        return json("permitephemeral", UniValue(nv.s));
    }
    if (n == "dustdynamic") {
        auto parsed = ParseDustDynamicOpt(nv.s, /*max_fee_estimate_blocks=*/1008);
        if (!parsed) return util::Error{util::ErrorString(parsed)};
        o.dust_relay_target = parsed->first;
        o.dust_relay_multiplier = parsed->second;
        return json("dustdynamic", UniValue(nv.s));
    }

    return util::Error{Untranslated(strprintf("unhandled setting: %s", name))};
}

} // namespace node
