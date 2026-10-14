// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/scriptshape.h>

#include <policy/settings.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/miniscript.h>
#include <script/script.h>
#include <script/solver.h>
#include <span.h>
#include <util/strencodings.h>

#include <algorithm>
#include <string>
#include <vector>

namespace scriptshape {
namespace {

struct Op {
    opcodetype op;
    std::vector<unsigned char> data;
    bool IsPush() const { return op <= OP_PUSHDATA4; }
    bool IsPushOf(size_t n) const { return IsPush() && data.size() == n; }
};
using Ops = std::vector<Op>;

bool Tokenize(const CScript& script, Ops& ops)
{
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        Op o;
        if (!script.GetOp(pc, o.op, o.data)) return false;
        ops.push_back(std::move(o));
    }
    return true;
}

CScript Rebuild(Ops::const_iterator begin, Ops::const_iterator end)
{
    CScript s;
    for (auto it = begin; it != end; ++it) {
        if (it->IsPush()) {
            s << it->data;
        } else {
            s << it->op;
        }
    }
    return s;
}

//! A small number: OP_0..OP_16, OP_1NEGATE, or a push of at most 5 bytes (timelocks, selectors, thresholds).
bool IsNum(const Op& o)
{
    if (o.op == OP_0 || o.op == OP_1NEGATE || (o.op >= OP_1 && o.op <= OP_16)) return true;
    return o.IsPush() && o.data.size() >= 1 && o.data.size() <= 5;
}

bool IsTimelockOp(const Op& o) { return o.op == OP_CHECKSEQUENCEVERIFY || o.op == OP_CHECKLOCKTIMEVERIFY; }
bool IsHashOp(const Op& o) { return o.op == OP_SHA256 || o.op == OP_HASH160 || o.op == OP_HASH256 || o.op == OP_RIPEMD160; }
bool IsHashPush(const Op& o) { return o.IsPushOf(20) || o.IsPushOf(32); }
bool IsKeyPush(const Op& o, Kind kind)
{
    if (kind == Kind::TAPSCRIPT) return o.IsPushOf(32);
    if (o.IsPushOf(33)) return true;
    return kind == Kind::P2SH && o.IsPushOf(65);
}
//! A push of the single byte 32, as written in `OP_SIZE 32 OP_EQUALVERIFY`.
bool IsPush32(const Op& o) { return o.IsPush() && o.data.size() == 1 && o.data[0] == 32; }

// Keys as opaque bytes: the policy judges shapes, it never signs.
struct ShapeCtx {
    typedef std::vector<unsigned char> Key;
    miniscript::MiniscriptContext m_ctx;
    explicit ShapeCtx(miniscript::MiniscriptContext ctx) : m_ctx{ctx} {}
    bool KeyCompare(const Key& a, const Key& b) const { return a < b; }
    template <typename I>
    std::optional<Key> FromPKBytes(I first, I last) const
    {
        const auto n = last - first;
        if (miniscript::IsTapscript(m_ctx)) {
            if (n != 32) return {};
        } else {
            if (n != 33) return {};
        }
        return Key(first, last);
    }
    template <typename I>
    std::optional<Key> FromPKHBytes(I first, I last) const
    {
        if (last - first != 20) return {};
        return Key(first, last);
    }
    std::vector<unsigned char> ToPKBytes(const Key& k) const { return k; }
    std::vector<unsigned char> ToPKHBytes(const Key& k) const { return k; }
    std::optional<std::string> ToString(const Key& k) const { return HexStr(k); }
    miniscript::MiniscriptContext MsContext() const { return m_ctx; }
};

bool SaneMiniscript(const CScript& script, Kind kind)
{
    const ShapeCtx ctx{kind == Kind::TAPSCRIPT ? miniscript::MiniscriptContext::TAPSCRIPT : miniscript::MiniscriptContext::P2WSH};
    const auto node{miniscript::FromScript(script, ctx)};
    // IsSane() minus the duplicate-key and timelock-mix checks: those make a script hard to use, not a data channel.
    return node && node->IsValidTopLevel() && node->ValidSatisfactions() && node->IsNonMalleable() && node->NeedsSignature();
}

bool MatchCheckSigAddThreshold(const Ops& ops);

//! Sane miniscript, or sane miniscript in its VERIFY form (a `v:` wrapper; what the witness leaves on the stack is a
//! typed item), or a tapscript CHECKSIGADD threshold written with GREATERTHANOREQUAL.
bool SaneCore(Ops::const_iterator begin, Ops::const_iterator end, Kind kind, bool /*followed*/)
{
    if (begin == end) return false;
    if (SaneMiniscript(Rebuild(begin, end), kind)) return true;
    if (kind == Kind::TAPSCRIPT && MatchCheckSigAddThreshold(Ops(begin, end))) return true;
    const Op& last = *(end - 1);
    Ops core(begin, end);
    if (last.op == OP_CHECKSIGVERIFY) core.back().op = OP_CHECKSIG;
    else if (last.op == OP_CHECKMULTISIGVERIFY) core.back().op = OP_CHECKMULTISIG;
    else if (last.op == OP_EQUALVERIFY) core.back().op = OP_EQUAL;
    else if (last.op == OP_VERIFY) core.pop_back();
    else return false;
    return !core.empty() && SaneMiniscript(Rebuild(core.begin(), core.end()), kind);
}

/** Generic rule: timelock and hash checks around a sane miniscript. Returns the shape name or "". */
std::string MatchChecksAroundMiniscript(const Ops& ops, Kind kind)
{
    size_t b{0}, e{ops.size()};
    int locks{0}, hashes{0};
    // leading `<n> CSV|CLTV DROP`
    while (e - b >= 3 && IsNum(ops[b]) && IsTimelockOp(ops[b + 1]) && ops[b + 2].op == OP_DROP) {
        b += 3;
        ++locks;
    }
    // leading hash checks, each with or without the SIZE 32 guard
    while (true) {
        if (e - b >= 6 && ops[b].op == OP_SIZE && IsPush32(ops[b + 1]) && ops[b + 2].op == OP_EQUALVERIFY &&
            IsHashOp(ops[b + 3]) && IsHashPush(ops[b + 4]) && ops[b + 5].op == OP_EQUALVERIFY) {
            b += 6;
            ++hashes;
        } else if (e - b >= 3 && IsHashOp(ops[b]) && IsHashPush(ops[b + 1]) && ops[b + 2].op == OP_EQUALVERIFY) {
            b += 3;
            ++hashes;
        } else {
            break;
        }
    }
    // trailing `<n> CSV|CLTV DROP`
    while (e - b >= 3 && IsNum(ops[e - 3]) && IsTimelockOp(ops[e - 2]) && ops[e - 1].op == OP_DROP) {
        e -= 3;
        ++locks;
    }
    // one trailing hash check
    bool trailing_hash{false};
    if (e - b >= 6 && ops[e - 6].op == OP_SIZE && IsPush32(ops[e - 5]) && ops[e - 4].op == OP_EQUALVERIFY &&
        IsHashOp(ops[e - 3]) && IsHashPush(ops[e - 2]) && (ops[e - 1].op == OP_EQUAL || ops[e - 1].op == OP_EQUALVERIFY)) {
        e -= 6;
        ++hashes;
        trailing_hash = true;
    } else if (e - b >= 3 && IsHashOp(ops[e - 3]) && IsHashPush(ops[e - 2]) && (ops[e - 1].op == OP_EQUAL || ops[e - 1].op == OP_EQUALVERIFY)) {
        e -= 3;
        ++hashes;
        trailing_hash = true;
    }
    if (locks == 0 && hashes == 0) return "";
    // a bare OP_1 behind the checks: anyone can spend once the lock passes or the preimage is shown
    if (e - b == 1 && ops[b].op == OP_1) return "anyone-after-checks";
    // a legacy uncompressed key behind the checks, P2SH only
    if (kind == Kind::P2SH && e - b == 2 && ops[b].IsPushOf(65) && (ops[b + 1].op == OP_CHECKSIG || ops[b + 1].op == OP_CHECKSIGVERIFY)) return "legacy-pk-timelock";
    if (!SaneCore(ops.begin() + b, ops.begin() + e, kind, trailing_hash)) return "";
    return locks && hashes ? "miniscript-timelock-hash" : locks ? "miniscript-timelock" : "miniscript-hash";
}

/** `m <key>... n CHECKMULTISIG` with 33-byte keys, or 65-byte ones in P2SH (legacy wallets): segwit policy never lets an uncompressed key sign. */
bool MatchLegacyMultisig(const Ops& ops, size_t b, size_t e, Kind kind)
{
    if (e - b < 4) return false;
    const Op& m = ops[b];
    const Op& n = ops[e - 2];
    if (ops[e - 1].op != OP_CHECKMULTISIG && ops[e - 1].op != OP_CHECKMULTISIGVERIFY) return false;
    if (m.op < OP_1 || m.op > OP_16 || n.op < OP_1 || n.op > OP_16) return false;
    const size_t nkeys{e - b - 3};
    if (nkeys != size_t(CScript::DecodeOP_N(n.op)) || CScript::DecodeOP_N(m.op) > CScript::DecodeOP_N(n.op)) return false;
    for (size_t i{b + 1}; i < e - 2; ++i) {
        if (!IsKeyPush(ops[i], kind)) return false;
    }
    return true;
}

/**
 * `(<key> CHECKSIGVERIFY)* <key> CHECKSIG (<key> CHECKSIGADD)+ [k GREATERTHANOREQUAL|NUMEQUAL|NUMEQUALVERIFY|EQUAL]`
 * in tapscript; without the comparator the signature count itself is the result (any one signature).
 */
bool MatchCheckSigAddThreshold(const Ops& ops)
{
    size_t b{0};
    while (b + 2 < ops.size() && ops[b].IsPushOf(32) && ops[b + 1].op == OP_CHECKSIGVERIFY) b += 2;
    size_t e{ops.size()};
    if (e - b >= 2) {
        const Op& last = ops[e - 1];
        if ((last.op == OP_GREATERTHANOREQUAL || last.op == OP_NUMEQUAL || last.op == OP_NUMEQUALVERIFY || last.op == OP_EQUAL) && IsNum(ops[e - 2])) e -= 2;
    }
    const size_t n{e - b};
    if (n < 4 || n % 2 != 0) return false;
    if (!ops[b].IsPushOf(32) || ops[b + 1].op != OP_CHECKSIG) return false;
    for (size_t i{b + 2}; i < e; i += 2) {
        if (!ops[i].IsPushOf(32) || ops[i + 1].op != OP_CHECKSIGADD) return false;
    }
    return true;
}

/**
 * Pattern tokens: an opcode name as GetOpName prints it (OP_IF, OP_CHECKSIG, 2, 16, 0); KEY (a key of the
 * context's size), KEY33, H20, H32 (hash pushes), NUM (a small number), N32 (the one-byte push 32), DATA
 * (a push of up to MAX_TEMPLATE_DATA_PUSH bytes, counted as data).
 */
bool MatchPattern(const Ops& ops, const char* pattern, Kind kind, size_t& data_bytes)
{
    size_t i{0};
    const char* p{pattern};
    while (*p) {
        while (*p == ' ') ++p;
        if (!*p) break;
        const char* q{p};
        while (*q && *q != ' ') ++q;
        const std::string tok(p, q);
        p = q;
        if (i >= ops.size()) return false;
        const Op& o = ops[i++];
        if (tok == "KEY") { if (!IsKeyPush(o, kind)) return false; }
        else if (tok == "KEY33") { if (!o.IsPushOf(33)) return false; }
        else if (tok == "H20") { if (!o.IsPushOf(20)) return false; }
        else if (tok == "H32") { if (!o.IsPushOf(32)) return false; }
        else if (tok == "NUM") { if (!IsNum(o)) return false; }
        else if (tok == "N32") { if (!IsPush32(o)) return false; }
        else if (tok == "DATA") { if (!o.IsPush() || o.data.size() > MAX_TEMPLATE_DATA_PUSH) return false; data_bytes += o.data.size(); }
        else { if (o.IsPush() || GetOpName(o.op) != tok) return false; }
    }
    return i == ops.size();
}

struct Template {
    const char* name;
    Kind kind;
    const char* pattern;
};

// Contract templates seen on mainnet in the year before the fork and since. Keys and hashes in them are
// bound by signatures, preimages or keys the spender supplies; the only free field is the tagged leaf's DATA.
const Template TEMPLATES[] = {
    // BOLT-3 to_local and the second-stage HTLC outputs
    {"ln-to-local", Kind::P2WSH, "OP_IF KEY OP_ELSE NUM OP_CHECKSEQUENCEVERIFY OP_DROP KEY OP_ENDIF OP_CHECKSIG"},
    // BOLT-3 anchor: anyone after 16 blocks by design
    {"ln-anchor", Kind::P2WSH, "KEY OP_CHECKSIG OP_IFDUP OP_NOTIF 16 OP_CHECKSEQUENCEVERIFY OP_ENDIF"},
    // LND taproot channel revocation leaf: the local key is dropped, the revocation key signs
    {"ln-taproot-revoke", Kind::TAPSCRIPT, "KEY OP_DROP KEY OP_CHECKSIG"},
    // BOLT-3 offered HTLC, without and with anchors
    {"ln-htlc-offered", Kind::P2WSH, "OP_DUP OP_HASH160 H20 OP_EQUAL OP_IF OP_CHECKSIG OP_ELSE KEY OP_SWAP OP_SIZE N32 OP_EQUAL OP_NOTIF OP_DROP 2 OP_SWAP KEY 2 OP_CHECKMULTISIG OP_ELSE OP_HASH160 H20 OP_EQUALVERIFY OP_CHECKSIG OP_ENDIF OP_ENDIF"},
    {"ln-htlc-offered-anchors", Kind::P2WSH, "OP_DUP OP_HASH160 H20 OP_EQUAL OP_IF OP_CHECKSIG OP_ELSE KEY OP_SWAP OP_SIZE N32 OP_EQUAL OP_NOTIF OP_DROP 2 OP_SWAP KEY 2 OP_CHECKMULTISIG OP_ELSE OP_HASH160 H20 OP_EQUALVERIFY OP_CHECKSIG OP_ENDIF 1 OP_CHECKSEQUENCEVERIFY OP_DROP OP_ENDIF"},
    // BOLT-3 received HTLC, without and with anchors
    {"ln-htlc-received", Kind::P2WSH, "OP_DUP OP_HASH160 H20 OP_EQUAL OP_IF OP_CHECKSIG OP_ELSE KEY OP_SWAP OP_SIZE N32 OP_EQUAL OP_IF OP_HASH160 H20 OP_EQUALVERIFY 2 OP_SWAP KEY 2 OP_CHECKMULTISIG OP_ELSE OP_DROP NUM OP_CHECKLOCKTIMEVERIFY OP_DROP OP_CHECKSIG OP_ENDIF OP_ENDIF"},
    {"ln-htlc-received-anchors", Kind::P2WSH, "OP_DUP OP_HASH160 H20 OP_EQUAL OP_IF OP_CHECKSIG OP_ELSE KEY OP_SWAP OP_SIZE N32 OP_EQUAL OP_IF OP_HASH160 H20 OP_EQUALVERIFY 2 OP_SWAP KEY 2 OP_CHECKMULTISIG OP_ELSE OP_DROP NUM OP_CHECKLOCKTIMEVERIFY OP_DROP OP_CHECKSIG OP_ENDIF 1 OP_CHECKSEQUENCEVERIFY OP_DROP OP_ENDIF"},
    // Phoenix (ACINQ) swap-in v1, CSV and CLTV refund forms
    {"phoenix-swap-in", Kind::P2WSH, "OP_IF NUM OP_CHECKSEQUENCEVERIFY OP_DROP OP_ELSE KEY OP_CHECKSIGVERIFY OP_ENDIF KEY OP_CHECKSIG"},
    {"phoenix-swap-in-cltv", Kind::P2WSH, "OP_IF NUM OP_CHECKLOCKTIMEVERIFY OP_DROP OP_ELSE KEY OP_CHECKSIGVERIFY OP_ENDIF KEY OP_CHECKSIG"},
    // Boltz submarine swap
    {"boltz-swap", Kind::P2WSH, "OP_SIZE N32 OP_EQUAL OP_IF OP_HASH160 H20 OP_EQUALVERIFY KEY OP_ELSE OP_DROP NUM OP_CHECKLOCKTIMEVERIFY OP_DROP KEY OP_ENDIF OP_CHECKSIG"},
    // Swap with a SHA256 preimage and pubkey hashes on both paths
    {"swap-sha256-pkh", Kind::P2WSH, "OP_IF OP_SIZE N32 OP_EQUALVERIFY OP_SHA256 H32 OP_EQUALVERIFY OP_DUP OP_HASH160 H20 OP_ELSE NUM OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 H20 OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG"},
    {"swap-sha256-pkh-2", Kind::P2WSH, "OP_IF OP_SIZE N32 OP_EQUALVERIFY OP_SHA256 H32 OP_EQUALVERIFY OP_DUP OP_HASH160 H20 OP_EQUALVERIFY OP_CHECKSIG OP_ELSE NUM OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 H20 OP_EQUALVERIFY OP_CHECKSIG OP_ENDIF"},
    {"swap-sha256-pkh-csv", Kind::P2WSH, "OP_IF OP_SIZE N32 OP_EQUALVERIFY OP_SHA256 H32 OP_EQUALVERIFY OP_DUP OP_HASH160 H20 OP_ELSE NUM OP_CHECKSEQUENCEVERIFY OP_DROP OP_DUP OP_HASH160 H20 OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG"},
    {"swap-sha256-pkh-nosize", Kind::P2WSH, "OP_IF OP_SHA256 H32 OP_EQUALVERIFY OP_DUP OP_HASH160 H20 OP_ELSE NUM OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 H20 OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG"},
    {"swap-sha256-pkh-nosize-csv", Kind::P2WSH, "OP_IF OP_SHA256 H32 OP_EQUALVERIFY OP_DUP OP_HASH160 H20 OP_ELSE NUM OP_CHECKSEQUENCEVERIFY OP_DROP OP_DUP OP_HASH160 H20 OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG"},
    // Two-party hash-or-CSV swap and its NOTIF sibling
    {"swap-hash-or-csv", Kind::P2WSH, "KEY OP_SWAP KEY OP_CHECKSIG OP_IF OP_SWAP OP_DUP OP_HASH160 H20 OP_EQUAL OP_IF OP_DROP OP_ELSE OP_SWAP OP_CHECKSIG OP_ENDIF OP_ELSE NUM OP_CHECKSEQUENCEVERIFY OP_DROP OP_CHECKSIGVERIFY OP_DUP OP_HASH160 H20 OP_EQUALVERIFY OP_CHECKSIG OP_ENDIF"},
    {"swap-notif", Kind::P2WSH, "KEY OP_CHECKSIG OP_NOTIF KEY OP_CHECKSIG OP_NOTIF OP_SIZE N32 OP_EQUALVERIFY OP_SHA256 H32 OP_EQUALVERIFY OP_ENDIF KEY OP_CHECKSIG OP_ELSE NUM OP_CHECKSEQUENCEVERIFY OP_ENDIF"},
    // HTLCs with a shared CHECKSIG: hash-or-CSV, hash-or-CLTV, SHA256-or-CLTV
    {"htlc-hash160-csv", Kind::P2WSH, "OP_HASH160 H20 OP_EQUAL OP_IF KEY OP_ELSE NUM OP_CHECKSEQUENCEVERIFY OP_DROP KEY OP_ENDIF OP_CHECKSIG"},
    {"htlc-hash160-cltv", Kind::P2WSH, "OP_HASH160 H20 OP_EQUAL OP_IF KEY OP_ELSE NUM OP_CHECKLOCKTIMEVERIFY OP_DROP KEY OP_ENDIF OP_CHECKSIG"},
    {"htlc-sha256-cltv", Kind::P2WSH, "OP_IF OP_SHA256 H32 OP_EQUALVERIFY KEY OP_ELSE NUM OP_CHECKLOCKTIMEVERIFY OP_DROP KEY OP_ENDIF OP_CHECKSIG"},
    // Four-path 2-of-2 / 2-of-2 / key+preimage after CSV / key after a longer CSV
    {"four-path-vhtlc", Kind::P2WSH, "OP_IF KEY OP_CHECKSIGVERIFY KEY OP_CHECKSIG OP_ELSE OP_IF KEY OP_CHECKSIGVERIFY KEY OP_CHECKSIG OP_ELSE OP_IF NUM OP_CHECKSEQUENCEVERIFY OP_DROP KEY OP_CHECKSIGVERIFY OP_SHA256 H32 OP_EQUAL OP_ELSE NUM OP_CHECKSEQUENCEVERIFY OP_DROP KEY OP_CHECKSIG OP_ENDIF OP_ENDIF OP_ENDIF"},
    // Selector-prefixed federation: one key or 3-of-5
    {"selector-federation", Kind::P2WSH, "NUM OP_EQUALVERIFY OP_IF KEY OP_CHECKSIG OP_ELSE 3 KEY KEY KEY KEY KEY 5 OP_CHECKMULTISIG OP_ENDIF"},
    // Keys and a tag: the tag is a data slot and is counted
    {"tagged-2of2", Kind::TAPSCRIPT, "KEY OP_CHECKSIGVERIFY KEY OP_CHECKSIGVERIFY DATA"},
    {"tagged-key", Kind::TAPSCRIPT, "KEY OP_CHECKSIGVERIFY DATA"},
    {"tagged-key", Kind::P2WSH, "KEY OP_CHECKSIGVERIFY DATA"},
    {"key-then-commitment", Kind::TAPSCRIPT, "KEY OP_CHECKSIG OP_IF DATA OP_ENDIF"},
};

/**
 * Custodial index switch: a chain of `OP_DUP <idx> OP_EQUAL OP_IF OP_DROP <branch> OP_ELSE` ending in a final
 * branch and the matching OP_ENDIFs. Branch A pushes two key hashes checked by a common tail
 * `OP_ROT OP_HASH160 OP_EQUALVERIFY OP_OVER OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG` (final branch
 * `<idx> OP_EQUALVERIFY H20 H20`); branch B checks them inline
 * `OP_HASH160 H20 OP_EQUALVERIFY OP_DUP OP_HASH160 H20 OP_EQUALVERIFY OP_CHECKSIG` (final branch
 * `OP_DUP OP_HASH160 H20 OP_EQUALVERIFY OP_CHECKSIG`).
 */
bool MatchIndexSwitch(const Ops& ops)
{
    size_t i{0};
    int depth{0};
    bool a{false}, b{false};
    const size_t n{ops.size()};
    while (i + 5 <= n && ops[i].op == OP_DUP && IsNum(ops[i + 1]) && ops[i + 2].op == OP_EQUAL && ops[i + 3].op == OP_IF && ops[i + 4].op == OP_DROP) {
        i += 5;
        if (i + 3 <= n && ops[i].IsPushOf(20) && ops[i + 1].IsPushOf(20) && ops[i + 2].op == OP_ELSE) {
            a = true;
            i += 3;
        } else if (i + 10 <= n && ops[i].op == OP_HASH160 && ops[i + 1].IsPushOf(20) && ops[i + 2].op == OP_EQUALVERIFY && ops[i + 3].op == OP_DUP &&
                   ops[i + 4].op == OP_HASH160 && ops[i + 5].IsPushOf(20) && ops[i + 6].op == OP_EQUALVERIFY && ops[i + 7].op == OP_CHECKSIG && ops[i + 8].op == OP_ELSE) {
            b = true;
            i += 9;
        } else {
            return false;
        }
        ++depth;
    }
    if (depth == 0 || (a && b)) return false;
    if (a) {
        if (i + 4 > n || !IsNum(ops[i]) || ops[i + 1].op != OP_EQUALVERIFY || !ops[i + 2].IsPushOf(20) || !ops[i + 3].IsPushOf(20)) return false;
        i += 4;
    } else {
        if (i + 5 > n || ops[i].op != OP_DUP || ops[i + 1].op != OP_HASH160 || !ops[i + 2].IsPushOf(20) || ops[i + 3].op != OP_EQUALVERIFY || ops[i + 4].op != OP_CHECKSIG) return false;
        i += 5;
    }
    for (int d{0}; d < depth; ++d) {
        if (i >= n || ops[i].op != OP_ENDIF) return false;
        ++i;
    }
    if (a) {
        static const opcodetype tail[] = {OP_ROT, OP_HASH160, OP_EQUALVERIFY, OP_OVER, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG};
        for (opcodetype t : tail) {
            if (i >= n || ops[i].op != t) return false;
            ++i;
        }
    }
    return i == n;
}

/** Rootstock PowPeg: `OP_NOTIF m-of-n OP_ELSE <n> CSV DROP m2-of-n2 OP_ENDIF`, optionally behind a 32-byte Flyover push that is dropped (counted as data). */
bool MatchPowPeg(const Ops& ops, size_t& data_bytes, Kind kind)
{
    size_t i{0};
    size_t data{0};
    if (ops.size() > 2 && ops[0].IsPushOf(32) && ops[1].op == OP_DROP) {
        data = 32;
        i = 2;
    }
    if (i >= ops.size() || ops[i].op != OP_NOTIF) return false;
    ++i;
    auto multisig_end = [&](size_t from) -> size_t {
        // find the OP_CHECKMULTISIG that closes the multisig starting at `from`
        for (size_t j{from}; j < ops.size(); ++j) {
            if (ops[j].op == OP_CHECKMULTISIG) return j + 1;
            if (!ops[j].IsPush() && !(ops[j].op >= OP_1 && ops[j].op <= OP_16)) return 0;
        }
        return 0;
    };
    size_t e1{multisig_end(i)};
    if (!e1 || !MatchLegacyMultisig(ops, i, e1, kind)) return false;
    i = e1;
    if (i + 3 >= ops.size() || ops[i].op != OP_ELSE || !IsNum(ops[i + 1]) || ops[i + 2].op != OP_CHECKSEQUENCEVERIFY || ops[i + 3].op != OP_DROP) return false;
    i += 4;
    size_t e2{multisig_end(i)};
    if (!e2 || !MatchLegacyMultisig(ops, i, e2, kind)) return false;
    i = e2;
    if (i + 1 != ops.size() || ops[i].op != OP_ENDIF) return false;
    data_bytes += data;
    return true;
}

/** Liquid federation: `m <k>... n CMS OP_IFDUP OP_NOTIF <t> CSV OP_VERIFY m2 <k>... n2 CMS OP_ENDIF`; the federation keys are exempt from the budget. */
bool MatchLiquidFederation(const Ops& ops, Kind kind)
{
    size_t i{0};
    auto multisig_end = [&](size_t from) -> size_t {
        for (size_t j{from}; j < ops.size(); ++j) {
            if (ops[j].op == OP_CHECKMULTISIG) return j + 1;
            if (!ops[j].IsPush() && !(ops[j].op >= OP_1 && ops[j].op <= OP_16)) return 0;
        }
        return 0;
    };
    size_t e1{multisig_end(i)};
    if (!e1 || !MatchLegacyMultisig(ops, i, e1, kind)) return false;
    i = e1;
    if (i + 5 >= ops.size() || ops[i].op != OP_IFDUP || ops[i + 1].op != OP_NOTIF || !IsNum(ops[i + 2]) || ops[i + 3].op != OP_CHECKSEQUENCEVERIFY || ops[i + 4].op != OP_VERIFY) return false;
    i += 5;
    size_t e2{multisig_end(i)};
    if (!e2 || !MatchLegacyMultisig(ops, i, e2, kind)) return false;
    i = e2;
    return i + 1 == ops.size() && ops[i].op == OP_ENDIF;
}

//! A signature-shaped witness item for the script kind: DER with its sighash byte (0x30 <len> 0x02 ...) under P2SH and
//! P2WSH, 64 or 65 bytes (BIP340) in tapscript. A 64-byte preimage is no signature where ECDSA checks it.
bool IsSignature(const std::vector<unsigned char>& item, Kind kind)
{
    const size_t n{item.size()};
    if (kind == Kind::TAPSCRIPT) return n == 64 || n == 65;
    return n >= 9 && n <= 73 && item[0] == 0x30 && size_t(item[1]) + 3 == n && item[2] == 0x02;
}

//! Every witness item must be something a script consumes: a signature, a key, a preimage (any size up to a BIP340
//! signature's, since a hash check without a size guard takes any), a small number or nothing. Which of these the
//! budget treats as a signature is the kind's call (IsSignature); the rest are witness bytes it counts.
bool TypedItem(const std::vector<unsigned char>& item)
{
    const size_t n{item.size()};
    if (n <= 4 || n == 20 || n == 32 || n == 33 || n == 64 || n == 65) return true;
    // DER signature with sighash byte: 0x30 <len> 0x02 ...
    return n >= 9 && n <= 73 && item[0] == 0x30 && size_t(item[1]) + 3 == n && item[2] == 0x02;
}

//! Signatures the script can check: one per CHECKSIG-family opcode, m per m-of-n CHECKMULTISIG (n when m does not
//! parse). Signature-shaped witness items past this are ordinary witness bytes.
size_t SignatureCapacity(const Ops& ops)
{
    const auto small = [](const Op& o) -> size_t {
        if (o.op >= OP_1 && o.op <= OP_16) return CScript::DecodeOP_N(o.op);
        if (o.IsPush() && o.data.size() == 1) return o.data[0];
        return 0;
    };
    size_t cap{0};
    for (size_t i{0}; i < ops.size(); ++i) {
        const auto op{ops[i].op};
        if (op == OP_CHECKSIG || op == OP_CHECKSIGVERIFY || op == OP_CHECKSIGADD) {
            ++cap;
        } else if (op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY) {
            const size_t n{i >= 1 ? small(ops[i - 1]) : 0};
            const size_t m{n && i >= n + 2 ? small(ops[i - n - 2]) : 0};
            cap += m ? m : n ? n : size_t{MAX_PUBKEYS_PER_MULTISIG};
        }
    }
    return cap;
}

struct Match {
    std::string shape;      //!< empty when unknown
    size_t data{0};         //!< template data pushes, counted whole
    bool exempt{false};     //!< federation layouts and anchors: no field budget
};

Match Classify(const Ops& ops, Kind kind, int depth);

/**
 * `OP_IF A OP_ELSE B OP_ENDIF` (or OP_NOTIF) where both branches are known shapes on their own: the
 * selector is a witness item, each branch is a contract path. Fields in the branch not taken stay
 * in the budget.
 */
Match MatchBranches(const Ops& ops, Kind kind, int depth)
{
    Match none;
    if (depth >= 2 || ops.size() < 5 || (ops[0].op != OP_IF && ops[0].op != OP_NOTIF) || ops.back().op != OP_ENDIF) return none;
    int level{0};
    size_t else_pos{0};
    for (size_t i{1}; i + 1 < ops.size(); ++i) {
        if (ops[i].op == OP_IF || ops[i].op == OP_NOTIF) {
            ++level;
        } else if (ops[i].op == OP_ENDIF) {
            if (level == 0) return none;
            --level;
        } else if (ops[i].op == OP_ELSE && level == 0) {
            if (else_pos) return none;
            else_pos = i;
        }
    }
    if (!else_pos || level != 0) return none;
    const Ops a(ops.begin() + 1, ops.begin() + else_pos);
    const Ops b(ops.begin() + else_pos + 1, ops.end() - 1);
    if (a.empty() || b.empty()) return none;
    const Match ma{Classify(a, kind, depth + 1)};
    if (ma.shape.empty()) return none;
    const Match mb{Classify(b, kind, depth + 1)};
    if (mb.shape.empty()) return none;
    Match m;
    m.shape = "branches(" + ma.shape + "," + mb.shape + ")";
    m.data = ma.data + mb.data;
    return m;
}

Match Classify(const Ops& ops, Kind kind, int depth)
{
    Match m;
    if (ops.empty()) return m;
    if (ops.size() == 1 && ops[0].op == OP_1) {
        // OP_TRUE anchor or anyone-can-spend leaf: nothing to prove, nothing to carry
        m.shape = "anchor-true";
        m.exempt = true;
        return m;
    }
    if (ops.size() == 2 && IsNum(ops[0]) && IsTimelockOp(ops[1])) {
        // a bare timelock (the LND taproot anchor leaf): anyone can spend once it passes, nothing to prove or carry
        m.shape = "anyone-after-timelock";
        m.exempt = true;
        return m;
    }
    const CScript script{Rebuild(ops.begin(), ops.end())};
    if (SaneMiniscript(script, kind)) {
        m.shape = "miniscript";
        if (MatchLiquidFederation(ops, kind)) m.shape = "liquid-federation";
        return m;
    }
    if (std::string s = MatchChecksAroundMiniscript(ops, kind); !s.empty()) {
        m.shape = s;
        return m;
    }
    if (kind == Kind::P2SH && MatchLegacyMultisig(ops, 0, ops.size(), kind)) {
        m.shape = "legacy-multisig";
        return m;
    }
    if (kind == Kind::TAPSCRIPT && MatchCheckSigAddThreshold(ops)) {
        m.shape = "checksigadd-threshold";
        return m;
    }
    if (kind != Kind::TAPSCRIPT && MatchIndexSwitch(ops)) {
        m.shape = "index-switch";
        return m;
    }
    if (kind != Kind::TAPSCRIPT && MatchPowPeg(ops, m.data, kind)) {
        m.shape = "powpeg";
        return m;
    }
    for (const Template& t : TEMPLATES) {
        // templates written for P2WSH apply to P2SH redeem scripts as well
        const bool kind_ok{t.kind == kind || (t.kind == Kind::P2WSH && kind == Kind::P2SH)};
        if (kind_ok && MatchPattern(ops, t.pattern, kind, m.data)) {
            m.shape = t.name;
            return m;
        }
    }
    return MatchBranches(ops, kind, depth);
}

} // namespace

Analysis Analyze(const CScript& script, Kind kind, const std::vector<std::vector<unsigned char>>& items, unsigned int allowance)
{
    Analysis a;
    Ops ops;
    if (!Tokenize(script, ops) || ops.empty()) {
        a.shape = "malformed";
        return a;
    }
    const Match m{Classify(ops, kind, 0)};
    a.known = !m.shape.empty();
    a.shape = a.known ? m.shape : "unknown";
    // the anchor and the bare timelock are spent with nothing
    if ((m.shape == "anchor-true" || m.shape == "anyone-after-timelock") && !items.empty()) a.known = false;

    // Signatures prove one field each, as far as the script can check them. Other items (preimages, keys for hashed
    // fields, signature-shaped items past that capacity) prove one each as well while they fit in the free witness
    // bytes, so a hash chain cannot buy proofs with payload; selectors and numbers prove nothing.
    const size_t capacity{SignatureCapacity(ops)};
    size_t witness_bytes{0}, signatures{0};
    for (const auto& item : items) {
        if (!TypedItem(item)) a.items_typed = false;
        if (signatures < capacity && IsSignature(item, kind)) {
            ++signatures;
            ++a.proven;
        } else if (item.size() > 4) {
            witness_bytes += item.size();
            if (witness_bytes <= MAX_FREE_WITNESS_BYTES) ++a.proven;
        }
    }

    // The field budget: keys and hashes in the script, less what the signatures prove, past the allowance, are
    // data. Each signature beyond the first buys one more free field: a k-of-n federation spent on its main path
    // pays nothing, while a copy of the layout that supplies few signatures pays for the keys it leaves unsigned.
    size_t field_bytes{0};
    for (const Op& o : ops) {
        if (IsKeyPush(o, kind) || IsHashPush(o)) {
            ++a.fields;
            field_bytes += o.data.size();
        }
    }
    if (m.shape == "tagged-2of2" || m.shape == "tagged-key" || m.shape == "key-then-commitment") {
        // the DATA push is counted below, not as a field; the keys are the fields
        a.fields = std::min(a.fields, m.shape == "tagged-2of2" ? size_t{2} : size_t{1});
    }
    if (m.shape == "anyone-after-checks") {
        // nothing to prove; the witness carries at most the preimage
        for (const auto& item : items) {
            if (item.size() > 32) a.known = false;
        }
    }
    if (!m.exempt && a.fields > a.proven) {
        const size_t unproven{a.fields - a.proven};
        const size_t free{allowance + (signatures > 0 ? signatures - 1 : 0)};
        if (unproven > free) {
            const size_t avg{(field_bytes + a.fields - 1) / a.fields};
            a.data_bytes += (unproven - free) * avg;
        }
    }
    // Witness items that are not signatures carry chosen bytes (a preimage is whatever hashes to the script's
    // field); past room for two keys or preimages per input they are data, so hash chains satisfied with real
    // preimages pay like any other payload.
    if (witness_bytes > MAX_FREE_WITNESS_BYTES) a.data_bytes += witness_bytes - MAX_FREE_WITNESS_BYTES;
    a.data_bytes += m.data;
    return a;
}

std::optional<Revealed> RevealedScript(const CScript& prev_spk, const CTxIn& txin)
{
    CScript spk{prev_spk};
    bool p2sh{false};
    std::vector<std::vector<unsigned char>> sig_stack;
    if (spk.IsPayToScriptHash()) {
        if (!EvalScript(sig_stack, txin.scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE) || sig_stack.empty()) {
            return std::nullopt;
        }
        spk = CScript(sig_stack.back().begin(), sig_stack.back().end());
        p2sh = true;
    }
    int wver{0};
    std::vector<unsigned char> wprog;
    if (spk.IsWitnessProgram(wver, wprog)) {
        const auto& stack{txin.scriptWitness.stack};
        if (wver == 0 && wprog.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            if (stack.empty()) return std::nullopt;
            Revealed r{CScript(stack.back().begin(), stack.back().end()), Kind::P2WSH, {stack.begin(), stack.end() - 1}};
            return r;
        }
        if (wver == 1 && wprog.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh) {
            size_t n{stack.size()};
            if (n >= 2 && !stack[n - 1].empty() && stack[n - 1][0] == ANNEX_TAG) --n;
            if (n < 2) return std::nullopt; // key path
            const auto& control{stack[n - 1]};
            if (control.empty() || (control[0] & TAPROOT_LEAF_MASK) != TAPROOT_LEAF_TAPSCRIPT) return std::nullopt;
            Revealed r{CScript(stack[n - 2].begin(), stack[n - 2].end()), Kind::TAPSCRIPT, {stack.begin(), stack.begin() + (n - 2)}};
            return r;
        }
        return std::nullopt; // P2WPKH and unknown versions
    }
    if (p2sh) {
        Revealed r{spk, Kind::P2SH, {sig_stack.begin(), sig_stack.end() - 1}};
        return r;
    }
    return std::nullopt; // bare output scripts: keys, pkh, bare multisig
}

size_t FieldBudgetBytes(const CScript& prev_spk, const CTxIn& txin)
{
    const auto revealed{RevealedScript(prev_spk, txin)};
    if (!revealed) return 0;
    const Analysis a{Analyze(revealed->script, revealed->kind, revealed->items, g_unproven_field_allowance)};
    return a.known ? a.data_bytes : 0;
}

} // namespace scriptshape
