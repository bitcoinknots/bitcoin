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

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>
#include <map>
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

// Persist to settings.json (mirrors interfaces::Node::updateRwSetting). On a
// failed write the in-memory value is put back, so nothing has changed.
[[nodiscard]] util::Result<void> PersistJson(ArgsManager& args, const std::string& key, const SettingsValue& value)
{
    std::optional<SettingsValue> old;
    args.LockSettings([&](common::Settings& settings) {
        if (auto it{settings.rw_settings.find(key)}; it != settings.rw_settings.end()) old = it->second;
        if (value.isNull()) {
            settings.rw_settings.erase(key);
        } else {
            settings.rw_settings[key] = value;
        }
    });
    std::string error{"failed to write settings file"};
    try {
        if (args.WriteSettingsFile()) return {};
    } catch (const std::exception& e) {
        error = e.what();
    }
    args.LockSettings([&](common::Settings& settings) {
        if (old) {
            settings.rw_settings[key] = *old;
        } else {
            settings.rw_settings.erase(key);
        }
    });
    return util::Error{Untranslated(strprintf("%s: %s", key, error))};
}

// Persist to the read-write config file, which throws if it cannot be written.
[[nodiscard]] util::Result<void> PersistRWConf(ArgsManager& args, const std::map<std::string, std::string>& values)
{
    try {
        args.ModifyRWConfigFile(values);
        return {};
    } catch (const std::exception& e) {
        return util::Error{Untranslated(strprintf("failed to write the read-write config file: %s", e.what()))};
    }
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
        // Saturate like the startup option parsing, which accepts any value.
        n.i = std::min(n.i, def.max);
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
        if (def.name == "mempoolreplacement") {
            // The values dumpsettings reports, as the GUI offers them.
            if (n.s != "never" && n.s != "fee,optin" && n.s != "fee,-optin") {
                return util::Error{Untranslated("mempoolreplacement must be one of: never, fee,optin, fee,-optin")};
            }
        } else if (def.name == "mempooltruc") {
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
        }
        // permitephemeral takes any comma list, which startup parses leniently too.
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

    // Each change is persisted before it is applied, so a failed write leaves
    // the running node as it was.
    auto json = [&](const std::string& key, const SettingsValue& v) { return PersistJson(args, key, v); };
    auto rwconf = [&](const std::string& key, const std::string& v) { return PersistRWConf(args, {{key, v}}); };

    // ---- Globals (no mempool required) ----
    if (n == "datacarriercost") {
        // Saturate so the weight below fits g_weight_per_data_byte.
        constexpr int64_t max_hundredths{(int64_t{std::numeric_limits<unsigned int>::max()} * 100 - 99) / WITNESS_SCALE_FACTOR};
        const int64_t hundredths{std::min(nv.hundredths, max_hundredths)};
        if (auto r{json("datacarriercost", UniValue(double(hundredths) / 100.0))}; !r) return r;
        g_weight_per_data_byte = (hundredths * WITNESS_SCALE_FACTOR + 99) / 100;
        return {};
    }
    if (n == "bytespersigop" || n == "bytespersigopstrict") {
        if (auto r{rwconf(n, strprintf("%d", nv.i))}; !r) return r;
        (n == "bytespersigop" ? nBytesPerSigOp : nBytesPerSigOpStrict) = nv.i;
        return {};
    }
    if (n == "maxscriptsize") {
        if (auto r{json("maxscriptsize", UniValue(nv.i))}; !r) return r;
        g_script_size_policy_limit = nv.i;
        return {};
    }
    if (n == "spkreuse") return rwconf("spkreuse", nv.s); // restart-required; no live field

    if (!pool) return util::Error{Untranslated("mempool not available")};
    kernel::MemPoolOptions& o = pool->m_opts;

    // ---- Mempool size / expiry (with live trim on shrink) ----
    if (n == "maxmempool" || n == "mempoolexpiry") {
        if (auto r{rwconf(n, strprintf("%d", nv.i))}; !r) return r;
        args.ForceSetArg("-" + n, strprintf("%d", nv.i));
        bool shrink;
        if (n == "maxmempool") {
            const int64_t old = o.max_size_bytes;
            o.max_size_bytes = nv.i * 1'000'000;
            shrink = o.max_size_bytes < old;
        } else {
            const auto old = o.expiry;
            o.expiry = std::chrono::hours{nv.i};
            shrink = o.expiry < old;
        }
        if (shrink && node.chainman) {
            LOCK(cs_main);
            LOCK(pool->cs);
            LimitMempoolSize(*pool, node.chainman->ActiveChainstate().CoinsTip());
        }
        return {};
    }

    // ---- Ancestor/descendant limits ----
    if (n == "limitancestorcount" || n == "limitancestorsize" || n == "limitdescendantcount" || n == "limitdescendantsize") {
        if (auto r{rwconf(n, strprintf("%d", nv.i))}; !r) return r;
        args.ForceSetArg("-" + n, strprintf("%d", nv.i));
        if (n == "limitancestorcount") o.limits.ancestor_count = nv.i;
        if (n == "limitancestorsize") o.limits.ancestor_size_vbytes = nv.i * 1'000;
        if (n == "limitdescendantcount") o.limits.descendant_count = nv.i;
        if (n == "limitdescendantsize") o.limits.descendant_size_vbytes = nv.i * 1'000;
        return {};
    }

    // ---- Fee rates (satoshis-per-kvB via ParseMoney) ----
    if (n == "minrelaytxfee" || n == "incrementalrelayfee" || n == "dustrelayfee") {
        if (auto r{rwconf(n, FormatMoney(nv.amount))}; !r) return r;
        const CFeeRate feerate{nv.amount};
        if (n == "minrelaytxfee") {
            o.min_relay_feerate = feerate;
        } else if (n == "incrementalrelayfee") {
            o.incremental_relay_feerate = feerate;
        } else {
            o.dust_relay_feerate_floor = feerate;
            if (o.dust_relay_feerate < feerate || !o.dust_relay_target) {
                o.dust_relay_feerate = feerate;
            } else {
                pool->UpdateDynamicDustFeerate();
            }
        }
        return {};
    }

    // ---- Simple integer m_opts, persisted to settings.json ----
    if (n == "minrelaycoinblocks" || n == "minrelaymaturity" || n == "maxtxlegacysigops") {
        if (auto r{json(n, UniValue(nv.i))}; !r) return r;
        if (n == "minrelaycoinblocks") o.minrelaycoinblocks = nv.i;
        if (n == "minrelaymaturity") o.minrelaymaturity = nv.i;
        if (n == "maxtxlegacysigops") o.maxtxlegacysigops = nv.i;
        return {};
    }

    // ---- Boolean policy toggles ----
    const std::map<std::string, bool*> json_bools{
        {"rejectparasites", &o.reject_parasites},
        {"rejecttokens", &o.reject_tokens},
        {"subdustfeepenalty", &o.subdustfeepenalty},
        {"acceptunknownwitness", &o.acceptunknownwitness},
        {"permitbarepubkey", &o.permit_bare_pubkey},
        {"permitbareanchor", &o.permitbareanchor},
        {"permitbaredatacarrier", &o.permitbaredatacarrier},
        {"acceptnonstddatacarrier", &o.accept_non_std_datacarrier},
    };
    if (auto it{json_bools.find(n)}; it != json_bools.end()) {
        if (auto r{json(n, UniValue(nv.b))}; !r) return r;
        *it->second = nv.b;
        return {};
    }
    if (n == "acceptnonstdtxn" || n == "permitbaremultisig") {
        if (auto r{rwconf(n, strprintf("%d", nv.b))}; !r) return r;
        if (n == "acceptnonstdtxn") o.require_standard = !nv.b;
        if (n == "permitbaremultisig") o.permit_bare_multisig = nv.b;
        return {};
    }

    // ---- Data carrier size (toggles the datacarrier bool key) ----
    if (n == "datacarriersize") {
        if (nv.i > 0) {
            std::map<std::string, std::string> values{{"datacarriersize", strprintf("%d", nv.i)}};
            if (!o.max_datacarrier_bytes.has_value()) values.emplace("datacarrier", "1");
            if (auto r{PersistRWConf(args, values)}; !r) return r;
            o.max_datacarrier_bytes = (unsigned)nv.i;
        } else {
            if (auto r{rwconf("datacarrier", "0")}; !r) return r;
            o.max_datacarrier_bytes = std::nullopt;
        }
        return {};
    }

    // ---- Special string settings ----
    if (n == "mempoolreplacement") {
        const RBFPolicy policy{nv.s == "never" ? RBFPolicy::Never : nv.s == "fee,optin" ? RBFPolicy::OptIn : RBFPolicy::Always};
        if (auto r{rwconf("mempoolreplacement", nv.s)}; !r) return r;
        if (auto r{json("mempoolfullrbf", UniValue(policy == RBFPolicy::Always ? "1" : "0"))}; !r) return r;
        o.rbf_policy = policy;
        return {};
    }
    if (n == "mempooltruc") {
        if (auto r{json("mempooltruc", UniValue(nv.s))}; !r) return r;
        o.truc_policy = (nv.s == "reject") ? TRUCPolicy::Reject : (nv.s == "enforce") ? TRUCPolicy::Enforce : TRUCPolicy::Accept;
        return {};
    }
    if (n == "permitephemeral") {
        if (auto r{json("permitephemeral", UniValue(nv.s))}; !r) return r;
        ApplyPermitEphemeralOption(SettingsValue(nv.s), o);
        return {};
    }
    if (n == "dustdynamic") {
        auto parsed = ParseDustDynamicOpt(nv.s, /*max_fee_estimate_blocks=*/1008);
        if (!parsed) return util::Error{util::ErrorString(parsed)};
        if (auto r{json("dustdynamic", UniValue(nv.s))}; !r) return r;
        o.dust_relay_target = parsed->first;
        o.dust_relay_multiplier = parsed->second;
        if (o.dust_relay_target) {
            pool->UpdateDynamicDustFeerate();
        } else {
            o.dust_relay_feerate = o.dust_relay_feerate_floor;
        }
        return {};
    }

    return util::Error{Untranslated(strprintf("unhandled setting: %s", name))};
}

util::Result<void> CheckMempoolSizeLimits(NodeContext& node, const UniValue& settings)
{
    // Startup refuses a mempool smaller than maxmempoolMinimumBytes() of the
    // descendant size limit, so check the pair as it would be after the batch.
    const CTxMemPool* pool = MemPool(node);
    if (!pool) return {};
    int64_t max_size_bytes{pool->m_opts.max_size_bytes};
    int64_t descendant_size_vbytes{pool->m_opts.limits.descendant_size_vbytes};
    if (settings.exists("maxmempool")) {
        auto nv{Normalize(*Assert(FindPolicySetting("maxmempool")), settings["maxmempool"])};
        if (!nv) return util::Error{util::ErrorString(nv)};
        max_size_bytes = nv->i * 1'000'000;
    }
    if (settings.exists("limitdescendantsize")) {
        auto nv{Normalize(*Assert(FindPolicySetting("limitdescendantsize")), settings["limitdescendantsize"])};
        if (!nv) return util::Error{util::ErrorString(nv)};
        descendant_size_vbytes = nv->i * 1'000;
    }
    const int64_t min_bytes{maxmempoolMinimumBytes(descendant_size_vbytes)};
    if (max_size_bytes < min_bytes) {
        return util::Error{Untranslated(strprintf("maxmempool must be at least %d MB with limitdescendantsize %d", int64_t(std::ceil(min_bytes / 1'000'000.0)), descendant_size_vbytes / 1'000))};
    }
    return {};
}

} // namespace node
