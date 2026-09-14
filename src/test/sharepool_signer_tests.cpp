// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sharepool/signer.h>
#include <consensus/sharepool_hash.h>

#include <kernel/chainparams.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <functional>
#include <limits>

namespace {
struct SignerFixture : BasicTestingSetup {
    CKey key;
    sharepool::signer::Policy policy;
    sharepool::Envelope envelope;

    SignerFixture()
    {
        key.MakeNewKey(true);
        policy.pool = uint256{uint8_t{1}};
        policy.payout_script = {0, 20};
        policy.payout_script.resize(22, 0x42);
        envelope.genesis = CChainParams::RegTest({})->GetConsensus().hashGenesisBlock;
        envelope.rules = sharepool::RulesHash();
        envelope.height = 1;
        envelope.native_parent = envelope.genesis;
        envelope.pool = policy.pool;
        envelope.owner = sharepool::signer::PublicKey(key);
        envelope.payout_script = policy.payout_script;
    }

    sharepool::signer::JobStatement Job() const
    {
        auto binding = envelope;
        binding.version = sharepool::hashonly::VERSION;
        binding.rules = sharepool::hashonly::RulesHash();
        return {binding, uint256{uint8_t{7}}, uint256{uint8_t{8}}};
    }
};

template <typename T> std::vector<unsigned char> Encode(const T& object)
{
    std::vector<unsigned char> raw;
    VectorWriter{raw, 0} << object;
    return raw;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(sharepool_signer_tests, SignerFixture)

BOOST_AUTO_TEST_CASE(native_random_key_owner_signature)
{
    const auto signature = sharepool::signer::SignOwner(policy, key, envelope);
    BOOST_CHECK(XOnlyPubKey{Span{envelope.owner}}.VerifySchnorr(sharepool::OwnerHash(envelope), signature));
    auto tampered = signature;
    tampered[0] ^= 1;
    BOOST_CHECK(!XOnlyPubKey{Span{envelope.owner}}.VerifySchnorr(sharepool::OwnerHash(envelope), tampered));
}

BOOST_AUTO_TEST_CASE(native_policy_rejects_wrong_network_or_binding)
{
    const std::vector<std::function<void(sharepool::Envelope&)>> changes{
        [](auto& e) { e.version = 2; },
        [](auto& e) { e.genesis.SetNull(); },
        [](auto& e) { e.rules.SetNull(); },
        [](auto& e) { e.height = 0; },
        [](auto& e) { e.height = std::numeric_limits<int>::max(); },
        [](auto& e) { e.native_parent.SetNull(); },
        [](auto& e) { e.pool.SetNull(); },
        [](auto& e) { e.owner[0] ^= 1; },
        [](auto& e) { e.payout_script.back() ^= 1; },
    };
    for (const auto& change : changes) {
        auto wrong = envelope;
        change(wrong);
        BOOST_CHECK_THROW(sharepool::signer::SignOwner(policy, key, wrong), std::invalid_argument);
    }
    auto mainnet = envelope;
    mainnet.genesis = CChainParams::Main()->GetConsensus().hashGenesisBlock;
    BOOST_CHECK_THROW(sharepool::signer::SignOwner(policy, key, mainnet), std::invalid_argument);
    CKey empty;
    BOOST_CHECK_THROW(sharepool::signer::SignOwner(policy, empty, envelope), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(native_owner_authorization_is_not_template_attestation)
{
    // The existing consensus OwnerHash authorizes a round and payout identity.
    // Snapshot roots are separately bound by pre-PoW m_mm_rhs and validated by
    // the miner gate and consensus; the signer must not claim to attest to them.
    const auto signature = sharepool::signer::SignOwner(policy, key, envelope);
    auto next = envelope;
    next.shares_root = uint256{uint8_t{9}};
    next.state_root = uint256{uint8_t{10}};
    next.payouts_root = uint256{uint8_t{11}};
    BOOST_CHECK(XOnlyPubKey{Span{next.owner}}.VerifySchnorr(sharepool::OwnerHash(next), signature));
    next.height += 1;
    BOOST_CHECK(!XOnlyPubKey{Span{next.owner}}.VerifySchnorr(sharepool::OwnerHash(next), signature));
}

BOOST_AUTO_TEST_CASE(native_signer_canonical_bounded_decoding)
{
    auto policy_bytes = Encode(policy);
    auto envelope_bytes = Encode(envelope);
    BOOST_CHECK_EQUAL(sharepool::signer::DecodePolicy(policy_bytes).pool, policy.pool);
    BOOST_CHECK_EQUAL(sharepool::signer::DecodeEnvelope(envelope_bytes).genesis, envelope.genesis);
    policy_bytes.push_back(0);
    envelope_bytes.push_back(0);
    BOOST_CHECK_THROW(sharepool::signer::DecodePolicy(policy_bytes), std::exception);
    BOOST_CHECK_THROW(sharepool::signer::DecodeEnvelope(envelope_bytes), std::exception);
    policy_bytes.resize(sharepool::signer::MAX_POLICY_BYTES + 1);
    envelope_bytes.resize(sharepool::signer::MAX_ENVELOPE_BYTES + 1);
    BOOST_CHECK_THROW(sharepool::signer::DecodePolicy(policy_bytes), std::exception);
    BOOST_CHECK_THROW(sharepool::signer::DecodeEnvelope(envelope_bytes), std::exception);
    policy_bytes = Encode(policy);
    policy_bytes.erase(policy_bytes.begin() + 33);
    policy_bytes.insert(policy_bytes.begin() + 33, {0xfd, 22, 0});
    BOOST_CHECK_THROW(sharepool::signer::DecodePolicy(policy_bytes), std::exception);
    policy.version = 0;
    BOOST_CHECK_THROW(sharepool::signer::DecodePolicy(Encode(policy)), std::exception);
    policy.version = 1;
    policy.payout_script = {0x51};
    BOOST_CHECK_THROW(sharepool::signer::DecodePolicy(Encode(policy)), std::exception);
}

BOOST_AUTO_TEST_CASE(native_v4_job_signature_attests_exact_job_and_contents)
{
    const auto statement = Job();
    const auto signature = sharepool::signer::SignJob(policy, key, statement);
    const XOnlyPubKey owner{Span{statement.binding.owner}};
    const auto message = sharepool::hashonly::OwnerHash(statement.binding, statement.job, statement.contents);
    BOOST_CHECK(owner.VerifySchnorr(message, signature));
    const std::vector<std::function<void(sharepool::signer::JobStatement&)>> changes{
        [](auto& s) { s.job = uint256{uint8_t{9}}; },
        [](auto& s) { s.contents = uint256{uint8_t{10}}; },
        [](auto& s) { ++s.binding.height; },
        [](auto& s) { s.binding.native_parent = uint256{uint8_t{11}}; },
        [](auto& s) { s.binding.payout_script.back() ^= 1; },
    };
    for (const auto& change : changes) {
        auto wrong = statement;
        change(wrong);
        BOOST_CHECK(!owner.VerifySchnorr(sharepool::hashonly::OwnerHash(wrong.binding, wrong.job, wrong.contents), signature));
    }
    // A v4 caller cannot accidentally obtain the weaker legacy policy-only
    // signature by routing an exact-job envelope through SignOwner.
    BOOST_CHECK_THROW(sharepool::signer::SignOwner(policy, key, statement.binding), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(native_v4_job_signer_enforces_policy_and_nonzero_digests)
{
    const auto statement = Job();
    const std::vector<std::function<void(sharepool::signer::JobStatement&)>> changes{
        [](auto& s) { s.binding.version = 2; },
        [](auto& s) { s.binding.genesis = CChainParams::Main()->GetConsensus().hashGenesisBlock; },
        [](auto& s) { s.binding.rules = sharepool::RulesHash(); },
        [](auto& s) { s.binding.height = 0; },
        [](auto& s) { s.binding.height = std::numeric_limits<int>::max(); },
        [](auto& s) { s.binding.native_parent.SetNull(); },
        [](auto& s) { s.binding.pool.SetNull(); },
        [](auto& s) { s.binding.owner[0] ^= 1; },
        [](auto& s) { s.binding.payout_script.back() ^= 1; },
        [](auto& s) { s.binding.shares_root = uint256{uint8_t{1}}; },
        [](auto& s) { s.binding.state_root = uint256{uint8_t{1}}; },
        [](auto& s) { s.binding.payouts_root = uint256{uint8_t{1}}; },
        [](auto& s) { s.job.SetNull(); },
        [](auto& s) { s.contents.SetNull(); },
    };
    for (const auto& change : changes) {
        auto wrong = statement;
        change(wrong);
        BOOST_CHECK_THROW(sharepool::signer::SignJob(policy, key, wrong), std::invalid_argument);
    }
    CKey empty;
    BOOST_CHECK_THROW(sharepool::signer::SignJob(policy, empty, statement), std::invalid_argument);
    auto wrong_policy = policy;
    wrong_policy.version = 2;
    BOOST_CHECK_THROW(sharepool::signer::SignJob(wrong_policy, key, statement), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(native_v4_job_signer_decoding_is_canonical_and_bounded)
{
    const auto statement = Job();
    const auto raw = Encode(statement);
    const auto decoded = sharepool::signer::DecodeJob(raw);
    BOOST_CHECK_EQUAL(decoded.job, statement.job);
    BOOST_CHECK_EQUAL(decoded.contents, statement.contents);
    BOOST_CHECK_EQUAL(decoded.binding.rules, sharepool::hashonly::RulesHash());
    auto trailing = raw;
    trailing.push_back(0);
    BOOST_CHECK_THROW(sharepool::signer::DecodeJob(trailing), std::exception);
    for (const size_t length : {size_t{0}, raw.size() - 1, sharepool::signer::MAX_JOB_BYTES + 1}) {
        auto wrong = raw;
        wrong.resize(length);
        BOOST_CHECK_THROW(sharepool::signer::DecodeJob(wrong), std::exception);
    }
    constexpr size_t SCRIPT_LENGTH_OFFSET{1 + 32 + 32 + 4 + 32 + 32 + 32};
    auto noncanonical = raw;
    noncanonical.erase(noncanonical.begin() + SCRIPT_LENGTH_OFFSET);
    noncanonical.insert(noncanonical.begin() + SCRIPT_LENGTH_OFFSET, {0xfd, 22, 0});
    BOOST_CHECK_THROW(sharepool::signer::DecodeJob(noncanonical), std::exception);
}

BOOST_AUTO_TEST_CASE(native_v5_job_signer_requires_matching_profile_and_binds_domain)
{
    auto statement = Job();
    statement.binding.version = sharepool::hashonly::LEDGER_VERSION;
    BOOST_CHECK_THROW(sharepool::signer::SignJob(policy, key, statement), std::invalid_argument);
    statement.binding.rules = sharepool::hashonly::RulesHash(sharepool::hashonly::LEDGER_VERSION);
    const auto signature = sharepool::signer::SignJob(policy, key, statement);
    const XOnlyPubKey owner{Span{statement.binding.owner}};
    BOOST_CHECK(owner.VerifySchnorr(sharepool::hashonly::OwnerHash(statement.binding, statement.job, statement.contents), signature));
    statement.binding.version = sharepool::hashonly::VERSION;
    statement.binding.rules = sharepool::hashonly::RulesHash();
    BOOST_CHECK(!owner.VerifySchnorr(sharepool::hashonly::OwnerHash(statement.binding, statement.job, statement.contents), signature));
}

BOOST_AUTO_TEST_CASE(native_v6_job_signer_binds_profile_and_exact_history_contents)
{
    auto statement = Job();
    statement.binding.version = sharepool::hashonly::TIDES_VERSION;
    BOOST_CHECK_THROW(sharepool::signer::SignJob(policy, key, statement), std::invalid_argument);
    statement.binding.rules = sharepool::hashonly::RulesHash(sharepool::hashonly::TIDES_VERSION);
    const auto signature = sharepool::signer::SignJob(policy, key, statement);
    const XOnlyPubKey owner{Span{statement.binding.owner}};
    BOOST_CHECK(owner.VerifySchnorr(sharepool::hashonly::OwnerHash(statement.binding, statement.job, statement.contents), signature));
    auto changed = statement;
    changed.contents = uint256{uint8_t{77}};
    BOOST_CHECK(!owner.VerifySchnorr(sharepool::hashonly::OwnerHash(changed.binding, changed.job, changed.contents), signature));
    for (const auto version : {sharepool::hashonly::VERSION, sharepool::hashonly::LEDGER_VERSION}) {
        changed = statement;
        changed.binding.version = version;
        changed.binding.rules = sharepool::hashonly::RulesHash(version);
        BOOST_CHECK(!owner.VerifySchnorr(sharepool::hashonly::OwnerHash(changed.binding, changed.job, changed.contents), signature));
    }
}

BOOST_AUTO_TEST_CASE(v8_job_signer_attests_assigned_work_and_rejects_legacy_field_reuse)
{
    namespace ho = sharepool::hashonly;
    auto statement = Job();
    statement.binding.version = ho::VARIABLE_TIDES_VERSION;
    statement.binding.rules = ho::RulesHash(ho::VARIABLE_TIDES_VERSION);
    const XOnlyPubKey owner{Span{statement.binding.owner}};
    for (const uint8_t bits : {uint8_t{0}, uint8_t{37}, uint8_t{255}}) {
        statement.binding.share_work_bits = bits;
        const auto signature = sharepool::signer::SignJob(policy, key, statement);
        BOOST_CHECK(owner.VerifySchnorr(ho::OwnerHash(statement.binding, statement.job, statement.contents), signature));
        DataStream stream;
        stream << statement;
        const auto parsed = sharepool::signer::DecodeJob({UCharCast(stream.data()), stream.size()});
        BOOST_CHECK_EQUAL(parsed.binding.share_work_bits, bits);
        auto changed = statement;
        changed.binding.share_work_bits ^= 1;
        BOOST_CHECK(!owner.VerifySchnorr(ho::OwnerHash(changed.binding, changed.job, changed.contents), signature));
    }
    for (const uint8_t version : {uint8_t{4}, uint8_t{5}, uint8_t{6}, uint8_t{7}}) {
        statement.binding.version = version;
        statement.binding.rules = ho::RulesHash(version);
        statement.binding.share_work_bits = 1;
        BOOST_CHECK_THROW(sharepool::signer::SignJob(policy, key, statement), std::invalid_argument);
        BOOST_CHECK_THROW(GetSerializeSize(statement), std::ios_base::failure);
    }
}

BOOST_AUTO_TEST_SUITE_END()
