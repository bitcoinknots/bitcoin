// Copyright (c) 2026-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/check.h>

#include <cstdint>
#include <optional>
#include <vector>

namespace {
//! Build the precomputed data the hardfork sighash needs.
PrecomputedTransactionData MakeTxdata(const CMutableTransaction& tx, std::vector<CTxOut> spent)
{
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::move(spent), /*force=*/true);
    return txdata;
}
} // namespace

FUZZ_TARGET(unified_sighash)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};

    const std::optional<CMutableTransaction> opt_tx{ConsumeDeserializable<CMutableTransaction>(provider, TX_WITH_WITNESS)};
    if (!opt_tx) return;
    const CMutableTransaction& tx{*opt_tx};
    if (tx.vin.empty()) return;

    // One spent output per input, or the sighash cannot be computed at all.
    std::vector<CTxOut> spent;
    spent.reserve(tx.vin.size());
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        spent.emplace_back(ConsumeMoney(provider), ConsumeScript(provider));
    }

    const unsigned int in_pos{provider.ConsumeIntegralInRange<unsigned int>(0, tx.vin.size() - 1)};
    const int32_t hash_type{provider.ConsumeIntegral<int32_t>()};
    const SigVersion sigversion{provider.ConsumeBool() ? SigVersion::BASE : SigVersion::WITNESS_V0};
    const CScript script_code{ConsumeScript(provider)};

    const PrecomputedTransactionData txdata{MakeTxdata(tx, spent)};

    uint256 hash;
    const bool ok{SignatureHashUnified(hash, script_code, tx, in_pos, hash_type, sigversion, txdata)};

    // Only canonical hash types may be accepted.
    const int32_t output_type{hash_type & 0x1f};
    // Defined only for signatures that opted in, and only for a real output
    // type with no undefined bits set.
    const bool canonical{(hash_type & SIGHASH_UNIFIED) &&
                         !(hash_type & ~(0x1f | SIGHASH_ANYONECANPAY | SIGHASH_UNIFIED)) &&
                         (output_type == SIGHASH_ALL || output_type == SIGHASH_NONE || output_type == SIGHASH_SINGLE)};
    if (!canonical) {
        Assert(!ok);
        return;
    }
    // SIGHASH_SINGLE without a matching output is the only other refusal.
    if (!ok) {
        Assert(output_type == SIGHASH_SINGLE && in_pos >= tx.vout.size());
        return;
    }

    // Deterministic, and independent of which PrecomputedTransactionData object
    // carries the data.
    uint256 again;
    Assert(SignatureHashUnified(again, script_code, tx, in_pos, hash_type, sigversion, txdata));
    Assert(again == hash);
    const PrecomputedTransactionData fresh{MakeTxdata(tx, spent)};
    uint256 from_fresh;
    Assert(SignatureHashUnified(from_fresh, script_code, tx, in_pos, hash_type, sigversion, fresh));
    Assert(from_fresh == hash);

    // The two script types never share a message, so a signature made for one
    // can never be replayed as the other.
    const SigVersion other{sigversion == SigVersion::BASE ? SigVersion::WITNESS_V0 : SigVersion::BASE};
    uint256 other_hash;
    Assert(SignatureHashUnified(other_hash, script_code, tx, in_pos, hash_type, other, txdata));
    Assert(other_hash != hash);

    // The scriptCode is committed to.
    CScript altered{script_code};
    altered << OP_NOP;
    uint256 altered_hash;
    Assert(SignatureHashUnified(altered_hash, altered, tx, in_pos, hash_type, sigversion, txdata));
    Assert(altered_hash != hash);

    // This input's own value is committed to, always, including under
    // ANYONECANPAY where the aggregate commitments are absent.
    if (spent[in_pos].nValue < MAX_MONEY) {
        std::vector<CTxOut> bumped{spent};
        bumped[in_pos].nValue += 1;
        uint256 bumped_hash;
        Assert(SignatureHashUnified(bumped_hash, script_code, tx, in_pos, hash_type, sigversion, MakeTxdata(tx, bumped)));
        Assert(bumped_hash != hash);
    }

    // Other inputs' values are committed to unless ANYONECANPAY was asked for.
    if (tx.vin.size() > 1) {
        const size_t other_pos{(in_pos + 1) % tx.vin.size()};
        if (spent[other_pos].nValue < MAX_MONEY) {
            std::vector<CTxOut> bumped{spent};
            bumped[other_pos].nValue += 1;
            uint256 bumped_hash;
            Assert(SignatureHashUnified(bumped_hash, script_code, tx, in_pos, hash_type, sigversion, MakeTxdata(tx, bumped)));
            if (hash_type & SIGHASH_ANYONECANPAY) {
                Assert(bumped_hash == hash);
            } else {
                Assert(bumped_hash != hash);
            }
        }
    }
}
