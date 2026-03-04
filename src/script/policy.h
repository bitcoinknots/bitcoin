// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_POLICY_H
#define BITCOIN_SCRIPT_POLICY_H

#include <script/parsing.h>
#include <span.h>
#include <util/strencodings.h>

#include <cstdint>
#include <memory>
#include <numeric>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace policy {

inline constexpr size_t MAX_POLICY_DEPTH = 100;
inline constexpr size_t MAX_THRESH_CHILDREN = 20;
inline constexpr size_t MAX_COMBINATIONS = 10000;

enum class PolicyType {
    PK,
    OLDER,
    AFTER,
    SHA256,
    HASH256,
    RIPEMD160,
    HASH160,
    AND,
    OR,
    THRESH,
};

template<typename Key>
struct Policy {
    PolicyType type;
    uint32_t k{0};
    std::vector<Key> keys;
    std::vector<unsigned char> data;
    std::vector<std::shared_ptr<const Policy>> subs;
    std::vector<double> weights;

    bool operator==(const Policy& o) const {
        if (type != o.type || k != o.k || keys != o.keys || data != o.data) return false;
        if (subs.size() != o.subs.size() || weights != o.weights) return false;
        for (size_t i = 0; i < subs.size(); ++i) {
            if (!(*subs[i] == *o.subs[i])) return false;
        }
        return true;
    }

    bool operator<(const Policy& o) const {
        if (type != o.type) return type < o.type;
        if (k != o.k) return k < o.k;
        if (keys != o.keys) return keys < o.keys;
        if (data != o.data) return data < o.data;
        if (subs.size() != o.subs.size()) return subs.size() < o.subs.size();
        for (size_t i = 0; i < subs.size(); ++i) {
            if (*subs[i] < *o.subs[i]) return true;
            if (*o.subs[i] < *subs[i]) return false;
        }
        if (weights != o.weights) return weights < o.weights;
        return false;
    }

    static std::shared_ptr<const Policy> MakePk(Key key) {
        auto p = std::make_shared<Policy>();
        p->type = PolicyType::PK;
        p->keys.push_back(std::move(key));
        return p;
    }

    static std::shared_ptr<const Policy> MakeOlder(uint32_t n) {
        auto p = std::make_shared<Policy>();
        p->type = PolicyType::OLDER;
        p->k = n;
        return p;
    }

    static std::shared_ptr<const Policy> MakeAfter(uint32_t n) {
        auto p = std::make_shared<Policy>();
        p->type = PolicyType::AFTER;
        p->k = n;
        return p;
    }

    static std::shared_ptr<const Policy> MakeHash(PolicyType ht, std::vector<unsigned char> hash) {
        auto p = std::make_shared<Policy>();
        p->type = ht;
        p->data = std::move(hash);
        return p;
    }

    static std::shared_ptr<const Policy> MakeAnd(std::shared_ptr<const Policy> a, std::shared_ptr<const Policy> b) {
        auto p = std::make_shared<Policy>();
        p->type = PolicyType::AND;
        p->subs.push_back(std::move(a));
        p->subs.push_back(std::move(b));
        return p;
    }

    static std::shared_ptr<const Policy> MakeAnd(std::vector<std::shared_ptr<const Policy>> children) {
        auto p = std::make_shared<Policy>();
        p->type = PolicyType::AND;
        p->subs = std::move(children);
        return p;
    }

    static std::shared_ptr<const Policy> MakeOr(std::vector<std::pair<double, std::shared_ptr<const Policy>>> weighted_children) {
        auto p = std::make_shared<Policy>();
        p->type = PolicyType::OR;
        for (auto& [w, child] : weighted_children) {
            p->weights.push_back(w);
            p->subs.push_back(std::move(child));
        }
        return p;
    }

    static std::shared_ptr<const Policy> MakeThresh(uint32_t thresh_k, std::vector<std::shared_ptr<const Policy>> children) {
        auto p = std::make_shared<Policy>();
        p->type = PolicyType::THRESH;
        p->k = thresh_k;
        p->subs = std::move(children);
        return p;
    }
};

namespace detail {

inline bool ParseUint32(Span<const char>& sp, uint32_t& out) {
    uint32_t val = 0;
    if (sp.empty() || sp[0] < '0' || sp[0] > '9') return false;
    if (sp[0] == '0' && sp.size() > 1 && sp[1] >= '0' && sp[1] <= '9') return false;
    while (!sp.empty() && sp[0] >= '0' && sp[0] <= '9') {
        uint64_t next = static_cast<uint64_t>(val) * 10 + (sp[0] - '0');
        if (next > 0xFFFFFFFF) return false;
        val = static_cast<uint32_t>(next);
        sp = sp.subspan(1);
    }
    out = val;
    return true;
}

inline bool Combinations(size_t n, size_t k, std::vector<std::vector<size_t>>& result, size_t max_results = MAX_COMBINATIONS) {
    if (k == 0) {
        result.push_back({});
        return true;
    }
    if (k > n) return false;
    std::vector<size_t> indices(k);
    std::iota(indices.begin(), indices.end(), 0);
    while (true) {
        result.push_back(indices);
        if (result.size() > max_results) return false;
        size_t i = k;
        while (i > 0) {
            --i;
            if (indices[i] != i + n - k) break;
            if (i == 0 && indices[i] == n - k) return true;
        }
        ++indices[i];
        for (size_t j = i + 1; j < k; ++j) {
            indices[j] = indices[j - 1] + 1;
        }
    }
}

} // namespace detail

template<typename Key, typename Ctx>
std::shared_ptr<const Policy<Key>> ParsePolicy(Span<const char>& sp, const Ctx& ctx, size_t depth = 0) {
    if (depth > MAX_POLICY_DEPTH) return nullptr;
    using Pol = Policy<Key>;

    auto parse_key = [&](Span<const char>& in) -> std::optional<Key> {
        auto expr = script::Expr(in);
        std::string key_str(expr.begin(), expr.end());
        return ctx.FromString(key_str.begin(), key_str.end());
    };

    auto parse_hex = [](Span<const char>& in, size_t expected_bytes) -> std::optional<std::vector<unsigned char>> {
        auto expr = script::Expr(in);
        std::string hex_str(expr.begin(), expr.end());
        auto bytes = TryParseHex<unsigned char>(hex_str);
        if (!bytes || bytes->size() != expected_bytes) return std::nullopt;
        return bytes;
    };

    if (script::Func("pk", sp)) {
        auto key = parse_key(sp);
        if (!key) return nullptr;
        return Pol::MakePk(std::move(*key));
    }

    if (script::Func("older", sp)) {
        uint32_t n{0};
        if (!detail::ParseUint32(sp, n)) return nullptr;
        if (n < 1 || n >= 0x80000000UL) return nullptr;
        return Pol::MakeOlder(n);
    }

    if (script::Func("after", sp)) {
        uint32_t n{0};
        if (!detail::ParseUint32(sp, n)) return nullptr;
        if (n < 1 || n >= 0x80000000UL) return nullptr;
        return Pol::MakeAfter(n);
    }

    if (script::Func("sha256", sp)) {
        auto h = parse_hex(sp, 32);
        if (!h) return nullptr;
        return Pol::MakeHash(PolicyType::SHA256, std::move(*h));
    }

    if (script::Func("hash256", sp)) {
        auto h = parse_hex(sp, 32);
        if (!h) return nullptr;
        return Pol::MakeHash(PolicyType::HASH256, std::move(*h));
    }

    if (script::Func("ripemd160", sp)) {
        auto h = parse_hex(sp, 20);
        if (!h) return nullptr;
        return Pol::MakeHash(PolicyType::RIPEMD160, std::move(*h));
    }

    if (script::Func("hash160", sp)) {
        auto h = parse_hex(sp, 20);
        if (!h) return nullptr;
        return Pol::MakeHash(PolicyType::HASH160, std::move(*h));
    }

    if (script::Func("and", sp)) {
        auto left_expr = script::Expr(sp);
        auto left = ParsePolicy<Key, Ctx>(left_expr, ctx, depth + 1);
        if (!left) return nullptr;
        if (!script::Const(",", sp)) return nullptr;
        auto right_expr = script::Expr(sp);
        auto right = ParsePolicy<Key, Ctx>(right_expr, ctx, depth + 1);
        if (!right) return nullptr;
        return Pol::MakeAnd(std::move(left), std::move(right));
    }

    if (script::Func("or", sp)) {
        std::vector<std::pair<double, std::shared_ptr<const Policy<Key>>>> children;
        while (true) {
            double weight = 1.0;
            auto expr = script::Expr(sp);

            Span<const char> probe = expr;
            uint32_t w{0};
            if (detail::ParseUint32(probe, w) && !probe.empty() && probe[0] == '@') {
                weight = static_cast<double>(w);
                probe = probe.subspan(1);
                expr = probe;
            }

            auto child = ParsePolicy<Key, Ctx>(expr, ctx, depth + 1);
            if (!child) return nullptr;
            children.emplace_back(weight, std::move(child));

            if (!script::Const(",", sp)) break;
        }
        if (children.size() < 2) return nullptr;
        return Pol::MakeOr(std::move(children));
    }

    if (script::Func("thresh", sp)) {
        auto k_expr = script::Expr(sp);
        uint32_t thresh_k{0};
        if (!detail::ParseUint32(k_expr, thresh_k)) return nullptr;

        std::vector<std::shared_ptr<const Policy<Key>>> children;
        while (script::Const(",", sp)) {
            auto child_expr = script::Expr(sp);
            auto child = ParsePolicy<Key, Ctx>(child_expr, ctx, depth + 1);
            if (!child) return nullptr;
            children.push_back(std::move(child));
        }
        if (children.empty() || thresh_k == 0 || thresh_k > children.size()) return nullptr;
        if (children.size() > MAX_THRESH_CHILDREN) return nullptr;
        return Pol::MakeThresh(thresh_k, std::move(children));
    }

    return nullptr;
}

} // namespace policy

#endif // BITCOIN_SCRIPT_POLICY_H
