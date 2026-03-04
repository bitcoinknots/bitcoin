// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/policy.h>
#include <test/util/setup_common.h>

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

BOOST_AUTO_TEST_CASE(recursion_depth_limit)
{
    std::string deep = "pk(A)";
    for (int i = 0; i < 150; ++i) {
        deep = "and(" + deep + ",pk(A))";
    }
    auto pol = Parse(deep);
    BOOST_CHECK(!pol);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace policy_tests
