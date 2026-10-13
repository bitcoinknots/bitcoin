// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/args.h>
#include <consensus/amount.h>
#include <key.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <script/solver.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(spend_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(max_signed_input_size_uses_external_outpoint)
{
    const CKey key{GenerateRandomKey()};
    FillableSigningProvider provider;
    BOOST_REQUIRE(provider.AddKey(key));

    const CTxOut txout{COIN, GetScriptForDestination(PKHash{key.GetPubKey()})};
    const COutPoint outpoint{Txid{}, 0};
    CCoinControl coin_control;
    coin_control.Select(outpoint).SetTxOut(txout);

    const int low_r{CalculateMaximumSignedInputSize(txout, COutPoint{}, &provider, /*can_grind_r=*/true, &coin_control)};
    const int high_r{CalculateMaximumSignedInputSize(txout, outpoint, &provider, /*can_grind_r=*/true, &coin_control)};
    BOOST_CHECK_EQUAL(high_r, low_r + 1);
}

BOOST_FIXTURE_TEST_CASE(SubtractFee, TestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    // Check that a subtract-from-recipient transaction slightly less than the
    // coinbase input amount does not create a change output (because it would
    // be uneconomical to add and spend the output), and make sure it pays the
    // leftover input amount which would have been change to the recipient
    // instead of the miner.
    auto check_tx = [&wallet](CAmount leftover_input_amount) {
        CRecipient recipient{PubKeyDestination({}), 50 * COIN - leftover_input_amount, /*subtract_fee=*/true};
        CCoinControl coin_control;
        coin_control.m_feerate.emplace(10000);
        coin_control.fOverrideFeeRate = true;
        // We need to use a change type with high cost of change so that the leftover amount will be dropped to fee instead of added as a change output
        coin_control.m_change_type = OutputType::LEGACY;
        auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control);
        BOOST_CHECK(res);
        const auto& txr = *res;
        BOOST_CHECK_EQUAL(txr.tx->vout.size(), 1);
        BOOST_CHECK_EQUAL(txr.tx->vout[0].nValue, recipient.nAmount + leftover_input_amount - txr.fee);
        BOOST_CHECK_GT(txr.fee, 0);
        return txr.fee;
    };

    // Send full input amount to recipient, check that only nonzero fee is
    // subtracted (to_reduce == fee).
    const CAmount fee{check_tx(0)};

    // Send slightly less than full input amount to recipient, check leftover
    // input amount is paid to recipient not the miner (to_reduce == fee - 123)
    BOOST_CHECK_EQUAL(fee, check_tx(123));

    // Send full input minus fee amount to recipient, check leftover input
    // amount is paid to recipient not the miner (to_reduce == 0)
    BOOST_CHECK_EQUAL(fee, check_tx(fee));

    // Send full input minus more than the fee amount to recipient, check
    // leftover input amount is paid to recipient not the miner (to_reduce ==
    // -123). This overpays the recipient instead of overpaying the miner more
    // than double the necessary fee.
    BOOST_CHECK_EQUAL(fee, check_tx(fee + 123));
}

BOOST_FIXTURE_TEST_CASE(wallet_duplicated_preset_inputs_test, TestChain100Setup)
{
    // Verify that the wallet's Coin Selection process does not include pre-selected inputs twice in a transaction.

    // Add 4 spendable UTXO, 50 BTC each, to the wallet (total balance 200 BTC)
    for (int i = 0; i < 4; i++) CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    LOCK(wallet->cs_wallet);
    auto available_coins = AvailableCoins(*wallet);
    std::vector<COutput> coins = available_coins.All();
    // Preselect the first 3 UTXO (150 BTC total)
    std::set<COutPoint> preset_inputs = {coins[0].outpoint, coins[1].outpoint, coins[2].outpoint};

    // Try to create a tx that spends more than what preset inputs + wallet selected inputs are covering for.
    // The wallet can cover up to 200 BTC, and the tx target is 299 BTC.
    std::vector<CRecipient> recipients{{*Assert(wallet->GetNewDestination(OutputType::BECH32, "dummy")),
                                           /*nAmount=*/299 * COIN, /*fSubtractFeeFromAmount=*/true}};
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    for (const auto& outpoint : preset_inputs) {
        coin_control.Select(outpoint);
    }

    // Attempt to send 299 BTC from a wallet that only has 200 BTC. The wallet should exclude
    // the preset inputs from the pool of available coins, realize that there is not enough
    // money to fund the 299 BTC payment, and fail with "Insufficient funds".
    //
    // Even with SFFO, the wallet can only afford to send 200 BTC.
    // If the wallet does not properly exclude preset inputs from the pool of available coins
    // prior to coin selection, it may create a transaction that does not fund the full payment
    // amount or, through SFFO, incorrectly reduce the recipient's amount by the difference
    // between the original target and the wrongly counted inputs (in this case 99 BTC)
    // so that the recipient's amount is no longer equal to the user's selected target of 299 BTC.

    // First case, use 'subtract_fee_from_outputs=true'
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));

    // Second case, don't use 'subtract_fee_from_outputs'.
    recipients[0].fSubtractFeeFromAmount = false;
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));
}

BOOST_FIXTURE_TEST_CASE(multisig_fee_uses_change_and_reselects, TestChain100Setup)
{
    m_node.args->ForceSetArg("-minrelaymultisigexcesskeyfee", "1000");
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const std::vector<CPubKey> keys{coinbaseKey.GetPubKey(), GenerateRandomKey().GetPubKey(), GenerateRandomKey().GetPubKey()};
    const CScript multisig{GetScriptForMultisig(1, keys)};
    const COutPoint external{Txid{}, 1};

    CCoinControl control;
    control.m_allow_other_inputs = false;
    control.m_feerate.emplace(1000);
    control.fOverrideFeeRate = true;
    control.destChange = PubKeyDestination(coinbaseKey.GetPubKey());
    control.Select(external).SetTxOut(CTxOut{1'000'000, GetScriptForDestination(WitnessV0ScriptHash{multisig})});
    control.m_external_provider.scripts.emplace(CScriptID{multisig}, multisig);
    for (const auto& key : keys) control.m_external_provider.pubkeys.emplace(key.GetID(), key);

    std::vector<CRecipient> recipients{{PubKeyDestination(coinbaseKey.GetPubKey()), 100'000, false}};
    auto with_change{CreateTransaction(*wallet, recipients, std::nullopt, control, /*sign=*/false)};
    BOOST_REQUIRE(with_change);
    BOOST_CHECK_EQUAL(with_change->fee, 1000);
    BOOST_REQUIRE(with_change->change_pos);
    BOOST_CHECK_EQUAL(with_change->tx->vout[*with_change->change_pos].nValue, 899'000);

    // The preset input alone covers the payment and ordinary fee, but not the
    // key floor. Coin selection must retry and add a wallet coin.
    recipients[0].nAmount = 999'500;
    control.m_allow_other_inputs = true;
    auto reselected{CreateTransaction(*wallet, recipients, std::nullopt, control, /*sign=*/false)};
    BOOST_REQUIRE(reselected);
    BOOST_CHECK_EQUAL(reselected->fee, 1000);
    BOOST_CHECK_GT(reselected->tx->vin.size(), 1U);

    control.m_allow_other_inputs = false;
    auto insufficient{CreateTransaction(*wallet, recipients, std::nullopt, control, /*sign=*/false)};
    BOOST_REQUIRE(!insufficient);
    BOOST_CHECK(util::ErrorString(insufficient).original.find("Internal bug") == std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(taproot_unsigned_fee_reserve_and_hint, TestChain100Setup)
{
    m_node.args->ForceSetArg("-minrelaymultisigexcesskeyfee", "1000");
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    const std::vector<CPubKey> keys{coinbaseKey.GetPubKey(), GenerateRandomKey().GetPubKey(), GenerateRandomKey().GetPubKey()};
    CScript leaf{CScript() << ToByteVector(XOnlyPubKey{keys[0]}) << OP_CHECKSIG};
    leaf << ToByteVector(XOnlyPubKey{keys[1]}) << OP_CHECKSIGADD;
    leaf << ToByteVector(XOnlyPubKey{keys[2]}) << OP_CHECKSIGADD << OP_1 << OP_NUMEQUAL;
    TaprootBuilder builder;
    builder.Add(0, leaf, TAPROOT_LEAF_TAPSCRIPT).Finalize(XOnlyPubKey{keys[0]});
    const auto output{builder.GetOutput()};
    const COutPoint external{Txid{}, 2};

    CCoinControl control;
    control.m_allow_other_inputs = false;
    control.m_feerate.emplace(1000);
    control.fOverrideFeeRate = true;
    control.destChange = PubKeyDestination(coinbaseKey.GetPubKey());
    control.Select(external).SetTxOut(CTxOut{1'000'000, GetScriptForDestination(output)});
    control.m_external_provider.tr_trees.emplace(output, builder);
    for (const auto& key : keys) control.m_external_provider.pubkeys.emplace(key.GetID(), key);
    const std::vector<CRecipient> recipients{{PubKeyDestination(coinbaseKey.GetPubKey()), 100'000, false}};

    auto reserved{CreateTransaction(*wallet, recipients, std::nullopt, control, /*sign=*/false)};
    BOOST_REQUIRE(reserved);
    BOOST_CHECK_EQUAL(reserved->fee, 1000);

    // Funding can specify its intended total key fee without a signed witness.
    control.m_multisig_fee = 0;
    auto hinted_key_path{CreateTransaction(*wallet, recipients, std::nullopt, control, /*sign=*/false)};
    BOOST_REQUIRE(hinted_key_path);
    BOOST_CHECK_LT(hinted_key_path->fee, 1000);
    control.m_multisig_fee = 2000;
    auto hinted_script_path{CreateTransaction(*wallet, recipients, std::nullopt, control, /*sign=*/false)};
    BOOST_REQUIRE(hinted_script_path);
    BOOST_CHECK_EQUAL(hinted_script_path->fee, 2000);
    control.m_multisig_fee = -1;
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, std::nullopt, control, /*sign=*/false));
    control.m_multisig_fee.reset();

    CScriptWitness witness;
    witness.stack.emplace_back(64, 1); // selected key path: no recovery leaf exposed
    control.Select(external).SetScriptWitness(witness);
    auto key_path{CreateTransaction(*wallet, recipients, std::nullopt, control, /*sign=*/false)};
    BOOST_REQUIRE(key_path);
    BOOST_CHECK_LT(key_path->fee, 1000);

    const auto spend_data{builder.GetSpendData()};
    witness.stack = {{}, {}, std::vector<unsigned char>(64, 1), std::vector<unsigned char>(leaf.begin(), leaf.end()), *spend_data.scripts.begin()->second.begin()};
    control.Select(external).SetScriptWitness(witness);
    auto script_path{CreateTransaction(*wallet, recipients, std::nullopt, control, /*sign=*/false)};
    BOOST_REQUIRE(script_path);
    BOOST_CHECK_EQUAL(script_path->fee, 1000);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
