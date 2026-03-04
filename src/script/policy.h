// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_POLICY_H
#define BITCOIN_SCRIPT_POLICY_H

#include <script/interpreter.h>
#include <script/miniscript.h>
#include <script/parsing.h>
#include <span.h>
#include <util/strencodings.h>
#include <util/vector.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <numeric>
#include <optional>
#include <queue>
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

template<typename Key>
using WeightedPolicy = std::pair<double, std::shared_ptr<const Policy<Key>>>;

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

template<typename Key>
std::vector<WeightedPolicy<Key>> EnumeratePolNative(double prob, const Policy<Key>& pol) {
    using Pol = Policy<Key>;
    using WP = WeightedPolicy<Key>;

    switch (pol.type) {
    case PolicyType::OR: {
        std::vector<WP> result;
        double total = 0.0;
        for (double w : pol.weights) total += w;
        for (size_t i = 0; i < pol.subs.size(); ++i) {
            double child_prob = (total > 0) ? prob * pol.weights[i] / total : prob / pol.subs.size();
            result.emplace_back(child_prob, pol.subs[i]);
        }
        return result;
    }
    case PolicyType::THRESH: {
        size_t n = pol.subs.size();
        uint32_t k = pol.k;
        if (k == 1) {
            std::vector<WP> result;
            for (size_t i = 0; i < n; ++i) {
                result.emplace_back(prob / n, pol.subs[i]);
            }
            return result;
        }
        if (k == n) {
            return {{prob, std::make_shared<Pol>(pol)}};
        }
        std::vector<std::vector<size_t>> combos;
        if (!detail::Combinations(n, k, combos)) return {{prob, std::make_shared<Pol>(pol)}};
        std::vector<WP> result;
        double combo_prob = prob / combos.size();
        for (const auto& combo : combos) {
            std::vector<std::shared_ptr<const Pol>> selected;
            for (size_t idx : combo) {
                selected.push_back(pol.subs[idx]);
            }
            if (selected.size() == 1) {
                result.emplace_back(combo_prob, selected[0]);
            } else {
                result.emplace_back(combo_prob, Pol::MakeAnd(std::move(selected)));
            }
        }
        return result;
    }
    case PolicyType::AND: {
        for (size_t i = 0; i < pol.subs.size(); ++i) {
            auto expanded = EnumeratePolNative(1.0, *pol.subs[i]);
            if (expanded.size() > 1) {
                std::vector<WP> result;
                for (auto& [child_prob, child_pol] : expanded) {
                    std::vector<std::shared_ptr<const Pol>> new_children;
                    for (size_t j = 0; j < pol.subs.size(); ++j) {
                        if (j == i) {
                            new_children.push_back(child_pol);
                        } else {
                            new_children.push_back(pol.subs[j]);
                        }
                    }
                    result.emplace_back(prob * child_prob, Pol::MakeAnd(std::move(new_children)));
                }
                return result;
            }
        }
        return {{prob, std::make_shared<Pol>(pol)}};
    }
    default:
        return {{prob, std::make_shared<Pol>(pol)}};
    }
}

template<typename Key>
std::vector<WeightedPolicy<Key>> EnumerateLeaves(const Policy<Key>& pol, size_t max_leaves = 1024) {
    using WP = WeightedPolicy<Key>;

    std::vector<WP> working;
    working.emplace_back(1.0, std::make_shared<Policy<Key>>(pol));

    while (working.size() < max_leaves) {
        int best_idx = -1;
        double best_prob = -1.0;
        std::vector<WP> best_expansion;

        for (size_t i = 0; i < working.size(); ++i) {
            auto expanded = EnumeratePolNative(working[i].first, *working[i].second);
            if (expanded.size() > 1) {
                if (working[i].first > best_prob) {
                    best_prob = working[i].first;
                    best_idx = static_cast<int>(i);
                    best_expansion = std::move(expanded);
                }
            }
        }

        if (best_idx < 0) break;
        if (working.size() - 1 + best_expansion.size() > max_leaves) break;

        working[best_idx] = std::move(working.back());
        working.pop_back();
        working.insert(working.end(), best_expansion.begin(), best_expansion.end());
    }

    return working;
}

template<typename Key>
bool FlattenAnd(const Policy<Key>& pol, std::vector<std::shared_ptr<const Policy<Key>>>& out, size_t depth = 0) {
    if (depth > MAX_POLICY_DEPTH) return false;
    if (pol.type == PolicyType::AND) {
        for (const auto& sub : pol.subs) {
            if (!FlattenAnd(*sub, out, depth + 1)) return false;
        }
    } else {
        out.push_back(std::make_shared<Policy<Key>>(pol));
    }
    return true;
}

template<typename Key>
miniscript::NodeRef<Key> CompileLeaf(const Policy<Key>& leaf, size_t depth = 0);

template<typename Key>
miniscript::NodeRef<Key> CompileAtom(const Policy<Key>& leaf) {
    using namespace miniscript;
    constexpr auto CTX = MiniscriptContext::TAPSCRIPT;

    switch (leaf.type) {
    case PolicyType::PK:
        return MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::WRAP_C,
            Vector(MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::PK_K, std::vector<Key>{leaf.keys[0]})));
    case PolicyType::OLDER:
        return MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::OLDER, leaf.k);
    case PolicyType::AFTER:
        return MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::AFTER, leaf.k);
    case PolicyType::SHA256:
        return MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::SHA256, leaf.data);
    case PolicyType::HASH256:
        return MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::HASH256, leaf.data);
    case PolicyType::RIPEMD160:
        return MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::RIPEMD160, leaf.data);
    case PolicyType::HASH160:
        return MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::HASH160, leaf.data);
    default:
        return {};
    }
}

template<typename Key>
miniscript::NodeRef<Key> CompileLeaf(const Policy<Key>& leaf, size_t depth) {
    if (depth > MAX_POLICY_DEPTH) return {};
    using namespace miniscript;
    constexpr auto CTX = MiniscriptContext::TAPSCRIPT;

    switch (leaf.type) {
    case PolicyType::PK:
    case PolicyType::OLDER:
    case PolicyType::AFTER:
    case PolicyType::SHA256:
    case PolicyType::HASH256:
    case PolicyType::RIPEMD160:
    case PolicyType::HASH160:
        return CompileAtom<Key>(leaf);

    case PolicyType::AND: {
        std::vector<std::shared_ptr<const Policy<Key>>> flat;
        if (!FlattenAnd(leaf, flat, depth)) return {};

        if (flat.empty()) return {};

        std::vector<NodeRef<Key>> compiled;
        for (const auto& child : flat) {
            auto ms = CompileLeaf<Key>(*child, depth + 1);
            if (!ms) return {};
            compiled.push_back(std::move(ms));
        }

        if (compiled.size() == 1) return std::move(compiled[0]);

        auto result = std::move(compiled.back());
        for (int i = static_cast<int>(compiled.size()) - 2; i >= 0; --i) {
            auto v_wrapped = MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::WRAP_V,
                Vector(std::move(compiled[i])));
            result = MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::AND_V,
                Vector(std::move(v_wrapped), std::move(result)));
        }
        return result;
    }

    case PolicyType::THRESH: {
        uint32_t k = leaf.k;
        size_t n = leaf.subs.size();

        bool all_pk = std::all_of(leaf.subs.begin(), leaf.subs.end(),
            [](const auto& sub) { return sub->type == PolicyType::PK; });

        if (all_pk) {
            std::vector<Key> all_keys;
            for (const auto& sub : leaf.subs) {
                all_keys.push_back(sub->keys[0]);
            }
            return MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::MULTI_A, std::move(all_keys), k);
        }

        std::vector<NodeRef<Key>> compiled;
        for (size_t i = 0; i < n; ++i) {
            auto ms = CompileLeaf<Key>(*leaf.subs[i], depth + 1);
            if (!ms) return {};

            if (i == 0) {
                compiled.push_back(std::move(ms));
            } else {
                if (leaf.subs[i]->type == PolicyType::PK) {
                    compiled.push_back(MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::WRAP_S,
                        Vector(std::move(ms))));
                } else {
                    compiled.push_back(MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::WRAP_A,
                        Vector(std::move(ms))));
                }
            }
        }

        return MakeNodeRef<Key>(internal::NoDupCheck{}, CTX, Fragment::THRESH, std::move(compiled), k);
    }

    case PolicyType::OR:
        return {};
    }

    return {};
}

struct HuffmanNode {
    double weight;
    int index;
    int left{-1};
    int right{-1};
};

inline std::vector<std::pair<int, int>> HuffmanTree(const std::vector<double>& weights) {
    size_t n = weights.size();
    if (n == 0) return {};
    if (n == 1) return {{0, 0}};

    std::vector<HuffmanNode> nodes;
    nodes.reserve(2 * n);

    auto cmp = [&](int a, int b) { return nodes[a].weight > nodes[b].weight; };
    std::priority_queue<int, std::vector<int>, decltype(cmp)> pq(cmp);

    for (size_t i = 0; i < n; ++i) {
        nodes.push_back({weights[i], static_cast<int>(i)});
        pq.push(static_cast<int>(i));
    }

    while (pq.size() > 1) {
        int a = pq.top(); pq.pop();
        int b = pq.top(); pq.pop();
        int idx = static_cast<int>(nodes.size());
        nodes.push_back({nodes[a].weight + nodes[b].weight, -1, a, b});
        pq.push(idx);
    }

    std::vector<std::pair<int, int>> result;
    std::vector<std::pair<int, int>> stack{{pq.top(), 0}};
    while (!stack.empty()) {
        auto [ni, d] = stack.back();
        stack.pop_back();
        if (nodes[ni].index >= 0) {
            result.emplace_back(nodes[ni].index, d);
        } else {
            stack.push_back({nodes[ni].right, d + 1});
            stack.push_back({nodes[ni].left, d + 1});
        }
    }

    return result;
}

template<typename Key>
std::optional<std::pair<std::vector<miniscript::NodeRef<Key>>, std::vector<int>>>
CompileTrNative(const Policy<Key>& pol, size_t max_depth = TAPROOT_CONTROL_MAX_NODE_COUNT, size_t max_leaves = 1024) {
    size_t effective_max_leaves = std::min(max_leaves, size_t{1} << std::min(max_depth, size_t{20}));
    auto leaves = EnumerateLeaves(pol, effective_max_leaves);
    if (leaves.empty()) return std::nullopt;

    std::vector<double> leaf_weights;
    std::vector<miniscript::NodeRef<Key>> compiled;

    for (auto& [weight, leaf_pol] : leaves) {
        auto ms = CompileLeaf<Key>(*leaf_pol);
        if (!ms || !ms->IsValid() || !ms->IsNonMalleable() || !ms->CheckTimeLocksMix() || ms->HasBranchingOpcodes()) return std::nullopt;
        leaf_weights.push_back(weight);
        compiled.push_back(std::move(ms));
    }

    auto tree = HuffmanTree(leaf_weights);

    std::vector<miniscript::NodeRef<Key>> scripts;
    std::vector<int> depths;
    for (auto& [leaf_idx, depth] : tree) {
        if (depth < 0 || static_cast<size_t>(depth) > max_depth) return std::nullopt;
        scripts.push_back(std::move(compiled[leaf_idx]));
        depths.push_back(depth);
    }

    return std::make_pair(std::move(scripts), std::move(depths));
}

} // namespace policy

#endif // BITCOIN_SCRIPT_POLICY_H
