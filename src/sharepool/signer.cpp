// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sharepool/signer.h>
#include <consensus/sharepool_hash.h>

#include <kernel/chainparams.h>
#include <random.h>
#include <streams.h>

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace sharepool::signer {
namespace {
void CheckPolicy(const Policy& policy)
{
    if (policy.version != 1 || policy.pool.IsNull() || !IsPayoutScript(policy.payout_script)) {
        throw std::invalid_argument("invalid sharepool signer policy");
    }
}

template <typename T> T Decode(Span<const unsigned char> raw, size_t maximum)
{
    if (raw.empty() || raw.size() > maximum) throw std::invalid_argument("signer input byte bound");
    DataStream stream{raw};
    T decoded;
    stream >> decoded;
    DataStream canonical;
    canonical << decoded;
    if (!stream.empty() || !std::equal(raw.begin(), raw.end(), UCharCast(canonical.data()), UCharCast(canonical.data()) + canonical.size())) {
        throw std::invalid_argument("noncanonical signer input");
    }
    return decoded;
}
} // namespace

Policy DecodePolicy(Span<const unsigned char> raw)
{
    auto policy = Decode<Policy>(raw, MAX_POLICY_BYTES);
    CheckPolicy(policy);
    return policy;
}

Envelope DecodeEnvelope(Span<const unsigned char> raw)
{
    return Decode<Envelope>(raw, MAX_ENVELOPE_BYTES);
}

std::array<unsigned char, 32> PublicKey(const CKey& key)
{
    if (!key.IsValid() || !key.IsCompressed()) throw std::invalid_argument("invalid signer key");
    const XOnlyPubKey public_key{key.GetPubKey()};
    std::array<unsigned char, 32> result{};
    std::copy(public_key.begin(), public_key.end(), result.begin());
    return result;
}

Signature SignOwner(const Policy& policy, const CKey& key, const Envelope& envelope)
{
    CheckPolicy(policy);
    const auto genesis = CChainParams::RegTest({})->GetConsensus().hashGenesisBlock;
    const bool hash_only = envelope.version == 2 && envelope.rules == hashonly::RulesHash() &&
        envelope.shares_root.IsNull() && envelope.state_root.IsNull() && envelope.payouts_root.IsNull();
    const bool legacy = envelope.version == 1 && envelope.rules == RulesHash();
    if ((!hash_only && !legacy) || envelope.genesis != genesis ||
        envelope.height == 0 || envelope.height >= static_cast<uint32_t>(std::numeric_limits<int>::max()) ||
        envelope.native_parent.IsNull() || envelope.pool != policy.pool ||
        envelope.payout_script != policy.payout_script || envelope.owner != PublicKey(key)) {
        throw std::invalid_argument("envelope violates local regtest signer policy");
    }
    uint256 auxiliary;
    GetStrongRandBytes(auxiliary);
    Signature signature{};
    const auto message = hash_only ? hashonly::OwnerHash(envelope) : OwnerHash(envelope);
    if (!key.SignSchnorr(message, signature, nullptr, auxiliary) ||
        !XOnlyPubKey{Span{envelope.owner}}.VerifySchnorr(message, signature)) {
        throw std::runtime_error("owner signature failed verification");
    }
    return signature;
}
} // namespace sharepool::signer
