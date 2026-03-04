// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/miniscript.h>
#include <script/policy.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <util/string.h>

#include <cmath>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace policy_tests {

struct StringCtx {
    template<typename I>
    std::optional<std::string> FromString(I begin, I end) const {
        std::string s(begin, end);
        if (s.empty()) return std::nullopt;
        return s;
    }
};

static const StringCtx CTX{};

static std::shared_ptr<const policy::Policy<std::string>> Parse(const std::string& str) {
    Span<const char> sp{str.data(), str.size()};
    return policy::ParsePolicy<std::string>(sp, CTX);
}

BOOST_FIXTURE_TEST_SUITE(policy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(parse_basic)
{
    auto pk_a = Parse("pk(A)");
    BOOST_REQUIRE(pk_a);
    BOOST_CHECK(pk_a->type == policy::PolicyType::PK);
    BOOST_CHECK_EQUAL(pk_a->keys.size(), 1U);
    BOOST_CHECK_EQUAL(pk_a->keys[0], "A");

    auto older = Parse("older(144)");
    BOOST_REQUIRE(older);
    BOOST_CHECK(older->type == policy::PolicyType::OLDER);
    BOOST_CHECK_EQUAL(older->k, 144U);

    auto after = Parse("after(500000)");
    BOOST_REQUIRE(after);
    BOOST_CHECK(after->type == policy::PolicyType::AFTER);
    BOOST_CHECK_EQUAL(after->k, 500000U);

    auto and_pol = Parse("and(pk(A),pk(B))");
    BOOST_REQUIRE(and_pol);
    BOOST_CHECK(and_pol->type == policy::PolicyType::AND);
    BOOST_CHECK_EQUAL(and_pol->subs.size(), 2U);
    BOOST_CHECK(and_pol->subs[0]->type == policy::PolicyType::PK);
    BOOST_CHECK(and_pol->subs[1]->type == policy::PolicyType::PK);

    auto or_pol = Parse("or(pk(A),pk(B))");
    BOOST_REQUIRE(or_pol);
    BOOST_CHECK(or_pol->type == policy::PolicyType::OR);
    BOOST_CHECK_EQUAL(or_pol->subs.size(), 2U);
    BOOST_CHECK_EQUAL(or_pol->weights[0], 1.0);
    BOOST_CHECK_EQUAL(or_pol->weights[1], 1.0);

    auto or_weighted = Parse("or(3@pk(A),1@pk(B))");
    BOOST_REQUIRE(or_weighted);
    BOOST_CHECK(or_weighted->type == policy::PolicyType::OR);
    BOOST_CHECK_EQUAL(or_weighted->weights[0], 3.0);
    BOOST_CHECK_EQUAL(or_weighted->weights[1], 1.0);

    auto thresh = Parse("thresh(2,pk(A),pk(B),pk(C))");
    BOOST_REQUIRE(thresh);
    BOOST_CHECK(thresh->type == policy::PolicyType::THRESH);
    BOOST_CHECK_EQUAL(thresh->k, 2U);
    BOOST_CHECK_EQUAL(thresh->subs.size(), 3U);

    auto invalid = Parse("garbage(stuff)");
    BOOST_CHECK(!invalid);
}

BOOST_AUTO_TEST_CASE(decompose_or)
{
    auto or_pol = Parse("or(pk(A),pk(B))");
    BOOST_REQUIRE(or_pol);
    auto entries = policy::EnumeratePolNative(1.0, *or_pol);
    BOOST_CHECK_EQUAL(entries.size(), 2U);

    auto or_weighted = Parse("or(3@pk(A),1@pk(B))");
    BOOST_REQUIRE(or_weighted);
    auto w_entries = policy::EnumeratePolNative(1.0, *or_weighted);
    BOOST_CHECK_EQUAL(w_entries.size(), 2U);
    BOOST_CHECK_CLOSE(w_entries[0].first, 0.75, 0.01);
    BOOST_CHECK_CLOSE(w_entries[1].first, 0.25, 0.01);
}

BOOST_AUTO_TEST_CASE(decompose_and_or)
{
    auto pol = Parse("and(or(pk(A),pk(B)),pk(C))");
    BOOST_REQUIRE(pol);
    auto entries = policy::EnumeratePolNative(1.0, *pol);
    BOOST_CHECK_EQUAL(entries.size(), 2U);
    for (const auto& [prob, sub] : entries) {
        BOOST_CHECK(sub->type == policy::PolicyType::AND);
    }
}

BOOST_AUTO_TEST_CASE(enumerate_leaves_full)
{
    auto or2 = Parse("or(pk(A),pk(B))");
    BOOST_REQUIRE(or2);
    auto leaves2 = policy::EnumerateLeaves(*or2);
    BOOST_CHECK_EQUAL(leaves2.size(), 2U);

    auto and_or = Parse("and(or(pk(A),pk(B)),pk(C))");
    BOOST_REQUIRE(and_or);
    auto leaves_and_or = policy::EnumerateLeaves(*and_or);
    BOOST_CHECK_EQUAL(leaves_and_or.size(), 2U);

    auto nested_or = Parse("or(pk(A),or(pk(B),pk(C)))");
    BOOST_REQUIRE(nested_or);
    auto leaves3 = policy::EnumerateLeaves(*nested_or);
    BOOST_CHECK_EQUAL(leaves3.size(), 3U);

    auto thresh = Parse("thresh(2,pk(A),pk(B),pk(C))");
    BOOST_REQUIRE(thresh);
    auto leaves_thresh = policy::EnumerateLeaves(*thresh);
    BOOST_CHECK_EQUAL(leaves_thresh.size(), 3U);
}

BOOST_AUTO_TEST_CASE(compile_leaf_pk)
{
    auto pk_pol = Parse("pk(A)");
    BOOST_REQUIRE(pk_pol);
    auto node = policy::CompileLeaf<std::string>(*pk_pol);
    BOOST_REQUIRE(node);
    BOOST_CHECK(node->fragment == miniscript::Fragment::WRAP_C);
    BOOST_CHECK_EQUAL(node->subs.size(), 1U);
    BOOST_CHECK(node->subs[0]->fragment == miniscript::Fragment::PK_K);
    BOOST_CHECK(node->IsValid());
}

BOOST_AUTO_TEST_CASE(compile_leaf_and)
{
    auto and_pol = Parse("and(pk(A),pk(B))");
    BOOST_REQUIRE(and_pol);
    auto node = policy::CompileLeaf<std::string>(*and_pol);
    BOOST_REQUIRE(node);
    BOOST_CHECK(node->fragment == miniscript::Fragment::AND_V);
    BOOST_CHECK_EQUAL(node->subs.size(), 2U);
    BOOST_CHECK(node->subs[0]->fragment == miniscript::Fragment::WRAP_V);
    BOOST_CHECK(node->subs[0]->subs[0]->fragment == miniscript::Fragment::WRAP_C);
    BOOST_CHECK(node->subs[0]->subs[0]->subs[0]->fragment == miniscript::Fragment::PK_K);
    BOOST_CHECK(node->subs[1]->fragment == miniscript::Fragment::WRAP_C);
    BOOST_CHECK(node->subs[1]->subs[0]->fragment == miniscript::Fragment::PK_K);
    BOOST_CHECK(node->IsValid());
}

BOOST_AUTO_TEST_CASE(compile_leaf_multi_a)
{
    auto thresh_pol = Parse("thresh(2,pk(A),pk(B),pk(C))");
    BOOST_REQUIRE(thresh_pol);
    auto node = policy::CompileLeaf<std::string>(*thresh_pol);
    BOOST_REQUIRE(node);
    BOOST_CHECK(node->fragment == miniscript::Fragment::MULTI_A);
    BOOST_CHECK(node->IsValid());
}

BOOST_AUTO_TEST_CASE(has_if_fragment_clean)
{
    auto pk_pol = Parse("pk(A)");
    BOOST_REQUIRE(pk_pol);
    auto pk_node = policy::CompileLeaf<std::string>(*pk_pol);
    BOOST_REQUIRE(pk_node);
    BOOST_CHECK(!pk_node->HasBranchingOpcodes());

    auto and_pol = Parse("and(pk(A),pk(B))");
    BOOST_REQUIRE(and_pol);
    auto and_node = policy::CompileLeaf<std::string>(*and_pol);
    BOOST_REQUIRE(and_node);
    BOOST_CHECK(!and_node->HasBranchingOpcodes());
}

BOOST_AUTO_TEST_CASE(huffman_basic)
{
    {
        auto result = policy::HuffmanTree({1.0});
        BOOST_CHECK_EQUAL(result.size(), 1U);
        BOOST_CHECK_EQUAL(result[0].second, 0);
    }

    {
        auto result = policy::HuffmanTree({1.0, 1.0});
        BOOST_CHECK_EQUAL(result.size(), 2U);
        BOOST_CHECK_EQUAL(result[0].second, 1);
        BOOST_CHECK_EQUAL(result[1].second, 1);
    }

    {
        auto result = policy::HuffmanTree({0.5, 0.25, 0.25});
        BOOST_CHECK_EQUAL(result.size(), 3U);
        std::vector<int> depths(3);
        for (const auto& [idx, depth] : result) {
            depths[idx] = depth;
        }
        BOOST_CHECK_EQUAL(depths[0], 1);
        BOOST_CHECK_EQUAL(depths[1], 2);
        BOOST_CHECK_EQUAL(depths[2], 2);
    }

    {
        auto result = policy::HuffmanTree({1.0, 1.0, 1.0, 1.0});
        BOOST_CHECK_EQUAL(result.size(), 4U);
        for (const auto& [idx, depth] : result) {
            BOOST_CHECK_EQUAL(depth, 2);
        }
    }
}

BOOST_AUTO_TEST_CASE(compile_tr_native_full)
{
    {
        auto pol = Parse("or(pk(A),pk(B))");
        BOOST_REQUIRE(pol);
        auto result = policy::CompileTrNative<std::string>(*pol);
        BOOST_REQUIRE(result.has_value());
        auto& [scripts, depths] = *result;
        BOOST_CHECK_EQUAL(scripts.size(), 2U);
        BOOST_CHECK_EQUAL(depths.size(), 2U);
        for (size_t i = 0; i < scripts.size(); ++i) {
            BOOST_CHECK(scripts[i]->IsValid());
            BOOST_CHECK(!scripts[i]->HasBranchingOpcodes());
        }
        BOOST_CHECK(TaprootBuilder::ValidDepths(depths));
    }

    {
        auto pol = Parse("and(or(pk(A),pk(B)),pk(C))");
        BOOST_REQUIRE(pol);
        auto result = policy::CompileTrNative<std::string>(*pol);
        BOOST_REQUIRE(result.has_value());
        auto& [scripts, depths] = *result;
        BOOST_CHECK_EQUAL(scripts.size(), 2U);
        BOOST_CHECK_EQUAL(depths.size(), 2U);
        for (size_t i = 0; i < scripts.size(); ++i) {
            BOOST_CHECK(scripts[i]->IsValid());
            BOOST_CHECK(!scripts[i]->HasBranchingOpcodes());
        }
        BOOST_CHECK(TaprootBuilder::ValidDepths(depths));
    }
}

BOOST_AUTO_TEST_CASE(max_leaves_exceeded)
{
    auto pol = Parse("thresh(2,pk(A),pk(B),pk(C),pk(D),pk(E),pk(F),pk(G),pk(H),pk(I),pk(J))");
    BOOST_REQUIRE(pol);
    auto leaves = policy::EnumerateLeaves(*pol, 2);
    BOOST_CHECK(leaves.size() <= 2U);

    auto leaves_full = policy::EnumerateLeaves(*pol);
    BOOST_CHECK(leaves_full.size() > 2U);
}

BOOST_AUTO_TEST_CASE(reject_invalid_timelock)
{
    BOOST_CHECK(!Parse("older(0)"));
    BOOST_CHECK(!Parse("after(0)"));
    BOOST_CHECK(!Parse("older(2147483648)"));
    BOOST_CHECK(!Parse("after(2147483648)"));
    BOOST_CHECK(Parse("older(1)"));
    BOOST_CHECK(Parse("after(1)"));
    BOOST_CHECK(Parse("older(2147483647)"));
    BOOST_CHECK(Parse("after(2147483647)"));
}

BOOST_AUTO_TEST_CASE(combinations_k_zero)
{
    std::vector<std::vector<size_t>> result;
    BOOST_CHECK(policy::detail::Combinations(5, 0, result));
    BOOST_CHECK_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0].empty());
}

BOOST_AUTO_TEST_CASE(combinations_k_greater_than_n)
{
    std::vector<std::vector<size_t>> result;
    BOOST_CHECK(!policy::detail::Combinations(3, 5, result));
    BOOST_CHECK(result.empty());
}

BOOST_AUTO_TEST_CASE(combinations_overflow_limit)
{
    std::vector<std::vector<size_t>> result;
    BOOST_CHECK(!policy::detail::Combinations(20, 10, result, 5));
}

BOOST_AUTO_TEST_CASE(bolt3_to_local)
{
    auto pol = Parse("or(pk(R),and(pk(L),older(1008)))");
    BOOST_REQUIRE(pol);
    auto result = policy::CompileTrNative<std::string>(*pol);
    BOOST_REQUIRE(result.has_value());
    auto& [scripts, depths] = *result;
    BOOST_CHECK_EQUAL(scripts.size(), 2U);
    for (size_t i = 0; i < scripts.size(); ++i) {
        BOOST_CHECK(scripts[i]->IsValid());
        BOOST_CHECK(!scripts[i]->HasBranchingOpcodes());
    }
    BOOST_CHECK(TaprootBuilder::ValidDepths(depths));
}

BOOST_AUTO_TEST_CASE(cross_product_and_of_ors)
{
    auto pol = Parse("and(or(pk(A),pk(B)),or(pk(C),pk(D)))");
    BOOST_REQUIRE(pol);
    auto result = policy::CompileTrNative<std::string>(*pol);
    BOOST_REQUIRE(result.has_value());
    auto& [scripts, depths] = *result;
    BOOST_CHECK_EQUAL(scripts.size(), 4U);
    for (size_t i = 0; i < scripts.size(); ++i) {
        BOOST_CHECK(scripts[i]->IsValid());
        BOOST_CHECK(!scripts[i]->HasBranchingOpcodes());
    }
    BOOST_CHECK(TaprootBuilder::ValidDepths(depths));
}

BOOST_AUTO_TEST_CASE(thresh_2_of_4)
{
    auto pol = Parse("thresh(2,pk(A),pk(B),pk(C),pk(D))");
    BOOST_REQUIRE(pol);
    auto result = policy::CompileTrNative<std::string>(*pol);
    BOOST_REQUIRE(result.has_value());
    auto& [scripts, depths] = *result;
    BOOST_CHECK_EQUAL(scripts.size(), 6U);
    for (size_t i = 0; i < scripts.size(); ++i) {
        BOOST_CHECK(scripts[i]->IsValid());
        BOOST_CHECK(!scripts[i]->HasBranchingOpcodes());
    }
    BOOST_CHECK(TaprootBuilder::ValidDepths(depths));
}

BOOST_AUTO_TEST_CASE(has_branching_opcodes_positive)
{
    using namespace miniscript;
    constexpr auto CTX = MiniscriptContext::TAPSCRIPT;

    auto pk_a = MakeNodeRef<std::string>(internal::NoDupCheck{}, CTX, Fragment::WRAP_C,
        Vector(MakeNodeRef<std::string>(internal::NoDupCheck{}, CTX, Fragment::PK_K,
            std::vector<std::string>{"A"})));
    auto pk_b = MakeNodeRef<std::string>(internal::NoDupCheck{}, CTX, Fragment::WRAP_C,
        Vector(MakeNodeRef<std::string>(internal::NoDupCheck{}, CTX, Fragment::PK_K,
            std::vector<std::string>{"B"})));

    BOOST_CHECK(!pk_a->HasBranchingOpcodes());

    auto or_i = MakeNodeRef<std::string>(internal::NoDupCheck{}, CTX, Fragment::OR_I,
        Vector(std::move(pk_a), std::move(pk_b)));
    BOOST_CHECK(or_i->HasBranchingOpcodes());
}

BOOST_AUTO_TEST_CASE(recursion_depth_limit)
{
    std::string deep = "pk(A)";
    for (int i = 0; i < 150; ++i) {
        deep = "and(" + deep + ",pk(A))";
    }
    auto pol = Parse(deep);
    BOOST_CHECK(!pol);
}

BOOST_AUTO_TEST_CASE(taptree_depth_limit)
{
    {
        auto pol = Parse("or(pk(A),pk(B))");
        BOOST_REQUIRE(pol);
        auto result = policy::CompileTrNative<std::string>(*pol, 7);
        BOOST_REQUIRE(result.has_value());
        auto& [scripts, depths] = *result;
        for (int d : depths) {
            BOOST_CHECK(d <= 7);
        }
    }

    {
        std::string pol_str = "or(pk(K0)";
        for (int i = 1; i < 128; ++i) {
            pol_str += ",pk(K" + util::ToString(i) + ")";
        }
        pol_str += ")";
        auto pol = Parse(pol_str);
        BOOST_REQUIRE(pol);
        auto result = policy::CompileTrNative<std::string>(*pol, 7);
        BOOST_REQUIRE(result.has_value());
        auto& [scripts, depths] = *result;
        BOOST_CHECK_EQUAL(scripts.size(), 128U);
        for (int d : depths) {
            BOOST_CHECK(d <= 7);
        }
    }

    {
        std::string pol_str = "or(pk(K0)";
        for (int i = 1; i < 129; ++i) {
            pol_str += ",pk(K" + util::ToString(i) + ")";
        }
        pol_str += ")";
        auto pol = Parse(pol_str);
        BOOST_REQUIRE(pol);
        auto result = policy::CompileTrNative<std::string>(*pol, 7);
        BOOST_CHECK(!result.has_value());
    }
}

BOOST_AUTO_TEST_CASE(standard_depth_allows_more_leaves)
{
    std::string pol_str = "or(pk(K0)";
    for (int i = 1; i < 129; ++i) {
        pol_str += ",pk(K" + util::ToString(i) + ")";
    }
    pol_str += ")";
    auto pol = Parse(pol_str);
    BOOST_REQUIRE(pol);
    auto result = policy::CompileTrNative<std::string>(*pol, TAPROOT_CONTROL_MAX_NODE_COUNT);
    BOOST_REQUIRE(result.has_value());
    auto& [scripts, depths] = *result;
    BOOST_CHECK_EQUAL(scripts.size(), 129U);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace policy_tests
