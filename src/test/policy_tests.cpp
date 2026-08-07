// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/validation.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(policy_tests, BasicTestingSetup)

namespace {
constexpr unsigned int NEUTRAL{DEFAULT_WEIGHT_PER_SCRIPTSIG_BYTE};  // 4, ie 1.0 vB/B
constexpr unsigned int DISCOUNT{1};                                 // 0.25 vB/B
constexpr unsigned int SURCHARGE{8};                                // 2.0 vB/B

//! Build a coins view holding one P2PKH output, and a tx spending it with the
//! given scriptSig.
struct ScriptSigFixture {
    CCoinsView dummy;
    CCoinsViewCache view{&dummy};
    CMutableTransaction tx;

    explicit ScriptSigFixture(const CScript& script_sig)
    {
        const CScript spk{CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x01) << OP_EQUALVERIFY << OP_CHECKSIG};
        const COutPoint outpoint{Txid::FromUint256(uint256::ONE), 0};

        Coin coin;
        coin.out.nValue = 10000;
        coin.out.scriptPubKey = spk;
        coin.nHeight = 1;
        view.AddCoin(outpoint, std::move(coin), false);

        tx.vin.resize(1);
        tx.vin[0].prevout = outpoint;
        tx.vin[0].scriptSig = script_sig;
        tx.vout.resize(1);
        tx.vout[0].nValue = 9000;
        tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    }

    int32_t Extra(unsigned int data_cost, unsigned int scriptsig_cost) const
    {
        return CalculateExtraTxWeight(CTransaction(tx), view, data_cost, scriptsig_cost);
    }
    size_t SigSize() const { return tx.vin[0].scriptSig.size(); }
};
} // namespace

// A plain signature-and-pubkey scriptSig carries no data bytes, so every byte
// is repriced.
BOOST_AUTO_TEST_CASE(calculate_extra_tx_weight_scriptsig)
{
    const ScriptSigFixture f{CScript() << std::vector<unsigned char>(72, 0x30) << std::vector<unsigned char>(33, 0x02)};
    const int64_t sigsize = f.SigSize();

    // Default is a no-op, matching pre-existing behavior exactly.
    BOOST_CHECK_EQUAL(f.Extra(DEFAULT_WEIGHT_PER_DATA_BYTE, NEUTRAL), 0);

    // 0.25 vB/B: each scriptSig byte drops from 4 weight to 1.
    BOOST_CHECK_EQUAL(f.Extra(DEFAULT_WEIGHT_PER_DATA_BYTE, DISCOUNT), -3 * sigsize);

    // 2.0 vB/B: each byte rises from 4 weight to 8.
    BOOST_CHECK_EQUAL(f.Extra(DEFAULT_WEIGHT_PER_DATA_BYTE, SURCHARGE), 4 * sigsize);
}

// Embedded data must be priced at the dearer of the two costs, so that a
// scriptSig discount can never be used to smuggle in cheaper data.
BOOST_AUTO_TEST_CASE(calculate_extra_tx_weight_scriptsig_datacarrier)
{
    // `<data> OP_DROP` is what DatacarrierBytes() counts. The counted span runs
    // from the push opcode to just past the OP_DROP, so it covers the push
    // opcode, the payload, and the OP_DROP itself.
    constexpr int64_t kData{40};
    const ScriptSigFixture f{CScript() << std::vector<unsigned char>(kData, 0xab) << OP_DROP << std::vector<unsigned char>(72, 0x30)};
    const int64_t sigsize = f.SigSize();
    const int64_t data_bytes = kData + 2;
    const int64_t plain_bytes = sigsize - data_bytes;
    BOOST_REQUIRE(plain_bytes > 0);

    // Neutral scriptSig cost: unchanged datacarrier behavior.
    BOOST_CHECK_EQUAL(f.Extra(DEFAULT_WEIGHT_PER_DATA_BYTE, NEUTRAL), 0);

    // Discounted scriptSig, datacarrier at consensus cost: the data bytes stay
    // at 4 weight/byte, only the rest is discounted.
    BOOST_CHECK_EQUAL(f.Extra(DEFAULT_WEIGHT_PER_DATA_BYTE, DISCOUNT), -3 * plain_bytes);

    // Discounted scriptSig, surcharged datacarrier: the surcharge wins on data
    // bytes and the discount still applies to the rest.
    BOOST_CHECK_EQUAL(f.Extra(SURCHARGE, DISCOUNT), 4 * data_bytes - 3 * plain_bytes);

    // Surcharging both keeps the higher of the two on data bytes.
    BOOST_CHECK_EQUAL(f.Extra(SURCHARGE, NEUTRAL), 4 * data_bytes);
}

// Witness spends have no scriptSig to reprice.
BOOST_AUTO_TEST_CASE(calculate_extra_tx_weight_scriptsig_empty)
{
    const ScriptSigFixture f{CScript()};
    BOOST_CHECK_EQUAL(f.Extra(DEFAULT_WEIGHT_PER_DATA_BYTE, DISCOUNT), 0);
    BOOST_CHECK_EQUAL(f.Extra(DEFAULT_WEIGHT_PER_DATA_BYTE, SURCHARGE), 0);
}

BOOST_AUTO_TEST_SUITE_END()
