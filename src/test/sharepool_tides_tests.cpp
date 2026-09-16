// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sharepool/tides.h>

#include <arith_uint256.h>
#include <test/data/sharepool_tides.json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <functional>
#include <string>

namespace {
namespace tides = sharepool::tides;

uint256 Number(uint64_t n) { return ArithToUint256(arith_uint256{n}); }

std::vector<unsigned char> Script(unsigned char id)
{
    std::vector<unsigned char> script{0, 20};
    script.resize(22, id);
    return script;
}

tides::LogEntry Entry(uint64_t sequence, unsigned char owner, uint64_t work = 1, uint64_t pool = 1)
{
    return {sequence, Number(sequence), Number(pool), Script(owner), Number(work)};
}

tides::Rewards Calculate(const std::vector<tides::LogEntry>& entries, uint64_t network_work = 1, CAmount reward = 120)
{
    const tides::Cutoff cutoff{Number(1), entries.size(), entries.empty() ? uint256{} : entries.back().proof_id};
    return tides::CalculateRewards(entries, cutoff, Number(network_work), reward, 0, {entries.size(), entries.size()});
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(sharepool_tides_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(eight_blocks_of_work_with_partial_oldest_share)
{
    const std::vector entries{Entry(1, 1, 60), Entry(2, 2, 30)};
    const auto result = Calculate(entries, 10, 80);
    BOOST_CHECK(result.window_work == 80);
    BOOST_CHECK(result.eligible_work == 80);
    BOOST_CHECK(result.weights.at(Script(1)) == 50);
    BOOST_CHECK(result.weights.at(Script(2)) == 30);
    BOOST_CHECK_EQUAL(result.oldest_sequence, 1);
    BOOST_CHECK(result.oldest_work == 50);
    BOOST_CHECK(entries[0].work == Number(60));
}

BOOST_AUTO_TEST_CASE(startup_and_zero_reward)
{
    const std::vector entries{Entry(1, 1, 3), Entry(2, 2, 2)};
    const auto result = Calculate(entries, 100, 100);
    BOOST_CHECK(result.window_work == 800);
    BOOST_CHECK(result.eligible_work == 5);
    BOOST_REQUIRE_EQUAL(result.payouts.size(), 2);
    BOOST_CHECK_EQUAL(result.payouts[0].nValue, 60);
    BOOST_CHECK_EQUAL(result.payouts[1].nValue, 40);
    const auto zero = Calculate(entries, 100, 0);
    BOOST_CHECK(zero.payouts.empty());
    BOOST_CHECK_EQUAL(zero.rounding_residue, 0);
    BOOST_CHECK_THROW(Calculate({}), tides::EmptyWindow);
}

BOOST_AUTO_TEST_CASE(floor_per_address_without_remainder_redistribution)
{
    const std::vector entries{Entry(1, 1), Entry(2, 1), Entry(3, 2)};
    const auto result = Calculate(entries, 1, 2);
    BOOST_REQUIRE_EQUAL(result.payouts.size(), 1);
    const auto script = Script(1);
    BOOST_CHECK(result.payouts[0].scriptPubKey == CScript(script.begin(), script.end()));
    // Two workers at one address earn floor(2 * 2 / 3) = 1 satoshi.
    BOOST_CHECK_EQUAL(result.payouts[0].nValue, 1);
    BOOST_CHECK_EQUAL(result.rounding_residue, 1);
}

BOOST_AUTO_TEST_CASE(repeated_reward_and_retarget_preserve_old_history)
{
    const std::vector entries{Entry(1, 1, 8), Entry(2, 2, 8)};
    const auto first = Calculate(entries);
    const auto repeated = Calculate(entries);
    BOOST_CHECK(first.payouts == repeated.payouts);
    BOOST_REQUIRE_EQUAL(first.payouts.size(), 1);
    BOOST_CHECK(first.weights.count(Script(1)) == 0);
    const auto harder = Calculate(entries, 2);
    BOOST_REQUIRE_EQUAL(harder.payouts.size(), 2);
    BOOST_CHECK_EQUAL(harder.payouts[0].nValue, 60);
    BOOST_CHECK_EQUAL(harder.payouts[1].nValue, 60);
    BOOST_CHECK(Calculate(entries).payouts == first.payouts);
    BOOST_CHECK_EQUAL(entries.size(), 2);
}

BOOST_AUTO_TEST_CASE(job_cutoff_rejects_extra_work_and_wrong_cutoff_proof)
{
    std::vector entries{Entry(1, 1, 8)};
    const tides::Cutoff cutoff{Number(1), 1, Number(1)};
    const auto old = tides::CalculateRewards(entries, cutoff, Number(1), 120, 0, {2, 2});
    entries.push_back(Entry(2, 2, 8));
    BOOST_CHECK_THROW(tides::CalculateRewards(entries, cutoff, Number(1), 120, 0, {2, 2}), std::invalid_argument);
    const auto same_job = tides::CalculateRewards(Span{entries}.first(1), cutoff, Number(1), 120, 0, {2, 2});
    BOOST_CHECK(same_job.payouts == old.payouts);
    entries[0].proof_id = Number(33);
    BOOST_CHECK_THROW(tides::CalculateRewards(Span{entries}.first(1), cutoff, Number(1), 120, 0, {2, 2}), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(invalid_history_is_rejected_even_below_current_window)
{
    const std::vector<std::function<void(tides::LogEntry&)>> mutations{
        [](auto& e) { e.sequence = 2; },
        [](auto& e) { e.proof_id.SetNull(); },
        [](auto& e) { e.proof_id = Number(2); },
        [](auto& e) { e.pool = Number(2); },
        [](auto& e) { e.work.SetNull(); },
        [](auto& e) { e.payout_script = {0x51}; },
    };
    for (const auto& mutate : mutations) {
        std::vector entries{Entry(1, 1, 8), Entry(2, 2, 8)};
        mutate(entries[0]);
        BOOST_CHECK_THROW(Calculate(entries), std::invalid_argument);
    }
}

BOOST_AUTO_TEST_CASE(separate_pool_reward_and_same_address_in_old_history)
{
    const std::vector pool_a{Entry(1, 1, 8)};
    const std::vector pool_b{Entry(1, 1, 8, 2), Entry(2, 2, 8, 2)};
    const auto a = Calculate(pool_a);
    const auto b = tides::CalculateRewards(pool_b, {Number(2), 2, Number(2)}, Number(2), 120, 0, {2, 2});
    BOOST_REQUIRE_EQUAL(a.payouts.size(), 1);
    BOOST_CHECK_EQUAL(a.payouts[0].nValue, 120);
    BOOST_REQUIRE_EQUAL(b.payouts.size(), 2);
    BOOST_CHECK_EQUAL(b.payouts[0].nValue, 60);
    // Membership authorization is upstream; moving new work to another pool
    // cannot relabel this old log or cause B's reward to pay A's window.
    BOOST_CHECK(Calculate(pool_a).payouts == a.payouts);
    BOOST_CHECK_THROW(Calculate(pool_b), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(resource_budgets_fail_without_dropping_work_or_outputs)
{
    const std::vector entries{Entry(1, 1), Entry(2, 2)};
    const tides::Cutoff cutoff{Number(1), 2, Number(2)};
    BOOST_CHECK_THROW(tides::CalculateRewards(entries, cutoff, Number(1), 120, 0, {1, 2}), std::length_error);
    BOOST_CHECK_THROW(tides::CalculateRewards(entries, cutoff, Number(1), 120, 0, {2, 1}), std::length_error);
    BOOST_CHECK_EQUAL(Calculate(entries).payouts.size(), 2);
    BOOST_CHECK(tides::CalculateRewards(entries, cutoff, Number(1), 0, 0, {2, 0}).payouts.empty());
    BOOST_CHECK_THROW(tides::CalculateRewards(entries, cutoff, Number(1), 120, 0, {2, 0}), std::length_error);
}

BOOST_AUTO_TEST_CASE(whole_history_requires_external_authentication)
{
    std::vector entries{Entry(1, 1), Entry(2, 2)};
    const auto original = Calculate(entries);
    // Ending sequence/proof alone is not a commitment to the earlier records.
    // An upstream caller must reject this alteration using the signed snapshot.
    entries[0].payout_script = Script(3);
    BOOST_CHECK(Calculate(entries).payouts != original.payouts);
}

BOOST_AUTO_TEST_CASE(supported_script_shapes_and_near_misses)
{
    const std::vector<std::string> scripts{
        "76a914010101010101010101010101010101010101010188ac",
        "a914010101010101010101010101010101010101010187",
        "00140101010101010101010101010101010101010101",
        "00200101010101010101010101010101010101010101010101010101010101010101",
        "51200101010101010101010101010101010101010101010101010101010101010101",
    };
    for (const auto& hex : scripts) {
        std::vector entries{Entry(1, 1)};
        entries[0].payout_script = ParseHex(hex);
        BOOST_CHECK_EQUAL(Calculate(entries).payouts.size(), 1);
        entries[0].payout_script.push_back(0);
        BOOST_CHECK_THROW(Calculate(entries), std::invalid_argument);
        entries[0].payout_script = ParseHex(hex);
        entries[0].payout_script[0] ^= 0x80;
        BOOST_CHECK_THROW(Calculate(entries), std::invalid_argument);
    }
}

BOOST_AUTO_TEST_CASE(reward_and_network_work_bounds)
{
    const std::vector entries{Entry(1, 1)};
    const tides::Cutoff cutoff{Number(1), 1, Number(1)};
    BOOST_CHECK_THROW(tides::CalculateRewards(entries, cutoff, {}, 120, 0, {1, 1}), std::invalid_argument);
    BOOST_CHECK_THROW(tides::CalculateRewards(entries, cutoff, Number(1), -1, 0, {1, 1}), std::invalid_argument);
    BOOST_CHECK_THROW(tides::CalculateRewards(entries, cutoff, Number(1), MAX_MONEY, 1, {1, 1}), std::invalid_argument);
    BOOST_CHECK_THROW(tides::CalculateRewards(entries, cutoff, Number(1), 1, -1, {1, 1}), std::invalid_argument);
    const auto result = tides::CalculateRewards(entries, cutoff, Number(1), MAX_MONEY - 13, 13, {1, 1});
    BOOST_CHECK_EQUAL(result.payouts[0].nValue, MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(known_answers_match_independent_python_reference)
{
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::sharepool_tides));
    BOOST_REQUIRE(vectors.isObject());
    BOOST_REQUIRE_EQUAL(vectors["cases"].size(), 11);
    for (const auto& test : vectors["cases"].getValues()) {
        BOOST_TEST_CONTEXT(test["name"].get_str()) {
            const auto parse_work = [](const UniValue& value) {
                const tides::Work numeric{value.get_str()};
                auto hex = numeric.str(0, std::ios_base::hex);
                if (hex.size() > 64) throw std::invalid_argument("fixture work exceeds uint256");
                hex.insert(0, 64 - hex.size(), '0');
                return uint256::FromHex(hex).value();
            };
            const auto pool = uint256::FromHex(test["pool_id"].get_str()).value();
            std::vector<tides::LogEntry> entries;
            for (const auto& share : test["shares"].getValues()) {
                entries.push_back({share["sequence"].getInt<uint64_t>(), uint256::FromHex(share["proof_id"].get_str()).value(), pool,
                                   ParseHex(share["payout_script"].get_str()), parse_work(share["work"])});
            }
            BOOST_REQUIRE(!entries.empty());
            const tides::Cutoff cutoff{pool, entries.size(), entries.back().proof_id};
            const auto result = tides::CalculateRewards(entries, cutoff, parse_work(test["network_work"]),
                test["subsidy"].getInt<CAmount>(), test["transaction_fees"].getInt<CAmount>(), {entries.size(), entries.size()});
            const auto& expected = test["expected"];
            BOOST_CHECK_EQUAL(result.window_work.str(), expected["window_work"].get_str());
            BOOST_CHECK_EQUAL(result.eligible_work.str(), expected["eligible_work"].get_str());
            BOOST_CHECK_EQUAL(result.rounding_residue, expected["rounding_residue"].getInt<CAmount>());
            BOOST_CHECK_EQUAL(result.oldest_sequence, expected["oldest_sequence"].getInt<uint64_t>());
            BOOST_CHECK_EQUAL(result.oldest_work.str(), expected["oldest_work"].get_str());
            BOOST_CHECK_EQUAL(result.weights.size(), expected["weights"].size());
            for (const auto& [script, work] : result.weights) {
                BOOST_CHECK_EQUAL(work.str(), expected["weights"][HexStr(script)].get_str());
            }
            BOOST_CHECK_EQUAL(result.payouts.size(), expected["payouts"].size());
            CAmount paid{0};
            for (const auto& output : result.payouts) {
                BOOST_CHECK_EQUAL(output.nValue, expected["payouts"][HexStr(output.scriptPubKey)].getInt<CAmount>());
                paid += output.nValue;
            }
            BOOST_CHECK_EQUAL(paid + result.rounding_residue, test["subsidy"].getInt<CAmount>() + test["transaction_fees"].getInt<CAmount>());
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
