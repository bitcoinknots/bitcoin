// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SHAREPOOL_SIGNER_H
#define BITCOIN_SHAREPOOL_SIGNER_H

#include <consensus/sharepool.h>
#include <key.h>

namespace sharepool::signer {
inline constexpr size_t MAX_POLICY_BYTES{68};
inline constexpr size_t MAX_ENVELOPE_BYTES{297}; // V8 adds one assigned-work byte.
inline constexpr size_t MAX_JOB_BYTES{MAX_ENVELOPE_BYTES + 64};

struct JobStatement {
    Envelope binding;
    uint256 job;
    uint256 contents;
    SERIALIZE_METHODS(JobStatement, obj) { READWRITE(obj.binding, obj.job, obj.contents); }
};

/** Immutable local signing policy. The only supported network is native regtest. */
struct Policy {
    uint8_t version{1};
    uint256 pool;
    std::vector<unsigned char> payout_script;

    template <typename Stream> void Serialize(Stream& s) const { s << version << pool << payout_script; }
    template <typename Stream> void Unserialize(Stream& s)
    {
        s >> version >> pool;
        ReadBoundedVector(s, payout_script, 34);
    }
};

Policy DecodePolicy(Span<const unsigned char> raw);
Envelope DecodeEnvelope(Span<const unsigned char> raw);
JobStatement DecodeJob(Span<const unsigned char> raw);
/** Attests exact job/content digests; native UTXO and completeness validation remain caller-owned. */
Signature SignJob(const Policy& policy, const CKey& key, const JobStatement& statement);
std::array<unsigned char, 32> PublicKey(const CKey& key);
/**
 * Signs only OwnerHash, after checking the exact compiled regtest domain and local
 * policy. The caller must validate the native tip and whole template separately.
 * This does not authorize an arbitrary digest or attest to snapshot completeness.
 */
Signature SignOwner(const Policy& policy, const CKey& key, const Envelope& envelope);
} // namespace sharepool::signer

#endif // BITCOIN_SHAREPOOL_SIGNER_H
