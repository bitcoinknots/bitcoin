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
    static constexpr SigVersion ALL_VERSIONS[]{SigVersion::BASE, SigVersion::WITNESS_V0,
                                               SigVersion::TAPROOT, SigVersion::TAPSCRIPT};
    const SigVersion sigversion{ALL_VERSIONS[provider.ConsumeIntegralInRange<size_t>(0, 3)]};
    const bool taproot{sigversion == SigVersion::TAPROOT || sigversion == SigVersion::TAPSCRIPT};
    const CScript script_code{ConsumeScript(provider)};

    // Taproot draws its extra context from the interpreter rather than the
    // transaction, so the fuzzer supplies it the same way.
    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = provider.ConsumeBool();
    if (execdata.m_annex_present) execdata.m_annex_hash = ConsumeUInt256(provider);
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash = ConsumeUInt256(provider);
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = provider.ConsumeIntegral<uint32_t>();
    const ScriptExecutionData* const ed{taproot ? &execdata : nullptr};

    const PrecomputedTransactionData txdata{MakeTxdata(tx, spent)};

    uint256 hash;
    const bool ok{SignatureHashUnified(hash, script_code, tx, in_pos, hash_type, sigversion, txdata, ed)};

    const int32_t output_type{hash_type & 0x1f};
    // Defined for every signature that opted in, and for no other.
    if (!(hash_type & SIGHASH_UNIFIED)) {
        Assert(!ok);
        return;
    }
    if (!ok) {
        // Taproot and tapscript keep BIP341's reading, which refuses a hash type
        // it does not define. Everywhere else SIGHASH_SINGLE without a matching
        // output is the only refusal left.
        const bool undefined_for_bip341{taproot &&
            ((hash_type & ~(0x1f | SIGHASH_ANYONECANPAY | SIGHASH_UNIFIED)) ||
             (output_type != SIGHASH_ALL && output_type != SIGHASH_NONE &&
              output_type != SIGHASH_SINGLE))};
        Assert(undefined_for_bip341 ||
               (output_type == SIGHASH_SINGLE && in_pos >= tx.vout.size()));
        return;
    }

    // Deterministic, and independent of which PrecomputedTransactionData object
    // carries the data.
    uint256 again;
    Assert(SignatureHashUnified(again, script_code, tx, in_pos, hash_type, sigversion, txdata, ed));
    Assert(again == hash);
    const PrecomputedTransactionData fresh{MakeTxdata(tx, spent)};
    uint256 from_fresh;
    Assert(SignatureHashUnified(from_fresh, script_code, tx, in_pos, hash_type, sigversion, fresh, ed));
    Assert(from_fresh == hash);

    // No two script types ever share a message, so a signature made for one can
    // never be replayed as another.
    for (const SigVersion other : ALL_VERSIONS) {
        if (other == sigversion) continue;
        const bool other_taproot{other == SigVersion::TAPROOT || other == SigVersion::TAPSCRIPT};
        uint256 other_hash;
        // Taproot and tapscript keep BIP341's reading, so a hash type the
        // legacy reading accepts may have no message there at all. That is a
        // stronger separation than a differing hash, not a weaker one.
        if (!SignatureHashUnified(other_hash, script_code, tx, in_pos, hash_type, other, txdata,
                                  other_taproot ? &execdata : nullptr)) {
            Assert(other_taproot);
            continue;
        }
        Assert(other_hash != hash);
    }

    if (taproot) {
        // Each piece of the taproot tail is committed to, so none of it can be
        // changed in flight. The leaf hash and codeseparator position only
        // enter the message for tapscript.
        ScriptExecutionData flipped{execdata};
        flipped.m_annex_present = !execdata.m_annex_present;
        if (flipped.m_annex_present) flipped.m_annex_hash = execdata.m_tapleaf_hash;
        uint256 flipped_hash;
        Assert(SignatureHashUnified(flipped_hash, script_code, tx, in_pos, hash_type, sigversion, txdata, &flipped));
        Assert(flipped_hash != hash);

        if (sigversion == SigVersion::TAPSCRIPT) {
            ScriptExecutionData other_leaf{execdata};
            std::vector<unsigned char> leaf_bytes{execdata.m_tapleaf_hash.begin(), execdata.m_tapleaf_hash.end()};
            leaf_bytes[0] ^= 0xff;
            other_leaf.m_tapleaf_hash = uint256{leaf_bytes};
            uint256 leaf_hash;
            Assert(SignatureHashUnified(leaf_hash, script_code, tx, in_pos, hash_type, sigversion, txdata, &other_leaf));
            Assert(leaf_hash != hash);

            ScriptExecutionData other_cs{execdata};
            other_cs.m_codeseparator_pos = ~execdata.m_codeseparator_pos;
            uint256 cs_hash;
            Assert(SignatureHashUnified(cs_hash, script_code, tx, in_pos, hash_type, sigversion, txdata, &other_cs));
            Assert(cs_hash != hash);
        }

        // Missing context is refused rather than treated as absent.
        ScriptExecutionData uninitialized;
        uint256 unused;
        Assert(!SignatureHashUnified(unused, script_code, tx, in_pos, hash_type, sigversion, txdata, &uninitialized));
        Assert(!SignatureHashUnified(unused, script_code, tx, in_pos, hash_type, sigversion, txdata, nullptr));
    }

    // The scriptCode is committed to, for the types whose message carries it.
    if (!taproot) {
        CScript altered{script_code};
        altered << OP_NOP;
        uint256 altered_hash;
        Assert(SignatureHashUnified(altered_hash, altered, tx, in_pos, hash_type, sigversion, txdata));
        Assert(altered_hash != hash);
    }

    // This input's own value is committed to, always, including under
    // ANYONECANPAY where the aggregate commitments are absent.
    if (spent[in_pos].nValue < MAX_MONEY) {
        std::vector<CTxOut> bumped{spent};
        bumped[in_pos].nValue += 1;
        uint256 bumped_hash;
        Assert(SignatureHashUnified(bumped_hash, script_code, tx, in_pos, hash_type, sigversion, MakeTxdata(tx, bumped), ed));
        Assert(bumped_hash != hash);
    }

    // Other inputs' values are committed to unless ANYONECANPAY was asked for.
    if (tx.vin.size() > 1) {
        const size_t other_pos{(in_pos + 1) % tx.vin.size()};
        if (spent[other_pos].nValue < MAX_MONEY) {
            std::vector<CTxOut> bumped{spent};
            bumped[other_pos].nValue += 1;
            uint256 bumped_hash;
            Assert(SignatureHashUnified(bumped_hash, script_code, tx, in_pos, hash_type, sigversion, MakeTxdata(tx, bumped), ed));
            if (hash_type & SIGHASH_ANYONECANPAY) {
                Assert(bumped_hash == hash);
            } else {
                Assert(bumped_hash != hash);
            }
        }
    }
}
