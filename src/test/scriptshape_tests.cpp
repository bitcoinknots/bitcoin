// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <policy/scriptshape.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
#include <test/data/scriptshape_vectors.json.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

using namespace scriptshape;

BOOST_FIXTURE_TEST_SUITE(scriptshape_tests, BasicTestingSetup)

namespace {

using Item = std::vector<unsigned char>;
using Items = std::vector<Item>;

Item Key33(unsigned char i) { Item k(33, i); k[0] = 0x02; return k; }
Item Key32(unsigned char i) { return Item(32, i); }
Item Hash20(unsigned char i) { return Item(20, i); }
Item Hash32(unsigned char i) { return Item(32, i); }
//! A DER-shaped ECDSA signature with a sighash byte, 71 bytes.
Item Der() { Item s(71, 0x11); s[0] = 0x30; s[1] = 68; s[2] = 0x02; return s; }
Item Schnorr() { return Item(64, 0x22); }

Kind KindOf(const std::string& k)
{
    if (k == "p2sh") return Kind::P2SH;
    if (k == "tapscript") return Kind::TAPSCRIPT;
    return Kind::P2WSH;
}

} // namespace

// Real mainnet inputs, two per shape (trimmed to the revealed
// script and the items it consumes). Shapes 27 to 29 are spam and must be unknown; the rest are the
// template list and must be known with every witness item typed.
BOOST_AUTO_TEST_CASE(mainnet_vectors)
{
    const UniValue tests = read_json(json_tests::scriptshape_vectors);
    BOOST_CHECK_EQUAL(tests.size(), 65U);
    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& t = tests[idx];
        const std::string name{t["name"].get_str()};
        const auto script_bytes{ParseHex(t["script"].get_str())};
        const CScript script(script_bytes.begin(), script_bytes.end());
        Items items;
        for (const UniValue& it : t["items"].getValues()) items.push_back(ParseHex(it.get_str()));
        const Analysis a{Analyze(script, KindOf(t["kind"].get_str()), items, DEFAULT_UNPROVEN_FIELD_ALLOWANCE)};
        BOOST_CHECK_MESSAGE(a.known == t["known"].get_bool(), name << ": known=" << a.known << " shape=" << a.shape << " txid " << t["txid"].get_str());
        if (t.exists("expect_shape")) {
            BOOST_CHECK_MESSAGE(a.shape == t["expect_shape"].get_str(), name << ": shape " << a.shape << " expected " << t["expect_shape"].get_str());
        }
        if (t["known"].get_bool()) {
            BOOST_CHECK_MESSAGE(a.items_typed, name << ": untyped witness item, txid " << t["txid"].get_str());
            if (t.exists("data_bytes")) {
                BOOST_CHECK_MESSAGE(a.data_bytes == t["data_bytes"].getInt<size_t>(), name << ": data_bytes " << a.data_bytes);
            } else if (name.find("emergency") != std::string::npos) {
                // the Liquid emergency path leaves the 15 federation keys unsigned: priced, like any copy of the layout
                BOOST_CHECK_MESSAGE(a.data_bytes > 0, name << ": data_bytes " << a.data_bytes);
            } else if (t["shape"].getInt<int>() != 14) {
                // every legit template carries no free bytes; the tagged leaf (14) carries its tag
                BOOST_CHECK_MESSAGE(a.data_bytes == 0, name << ": data_bytes " << a.data_bytes << " fields " << a.fields << " proven " << a.proven);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(multisig_budget)
{
    // m-of-n P2WSH with m signatures: unproven keys past the allowance are charged at 33 bytes each
    const auto multisig = [](int m, int n) {
        CScript s;
        s << CScript::EncodeOP_N(m);
        for (int i = 0; i < n; ++i) s << Key33(i + 1);
        s << CScript::EncodeOP_N(n) << OP_CHECKMULTISIG;
        return s;
    };
    const auto sigs = [](int m) { Items it{Item{}}; for (int i = 0; i < m; ++i) it.push_back(Der()); return it; };

    Analysis a{Analyze(multisig(2, 3), Kind::P2WSH, sigs(2), 5)};
    BOOST_CHECK(a.known);
    BOOST_CHECK_EQUAL(a.shape, "miniscript");
    BOOST_CHECK_EQUAL(a.fields, 3U);
    BOOST_CHECK_EQUAL(a.proven, 2U);
    BOOST_CHECK_EQUAL(a.data_bytes, 0U);

    a = Analyze(multisig(1, 6), Kind::P2WSH, sigs(1), 5);
    BOOST_CHECK(a.known);
    BOOST_CHECK_EQUAL(a.data_bytes, 0U); // 5 unproven, at the allowance

    a = Analyze(multisig(1, 7), Kind::P2WSH, sigs(1), 5);
    BOOST_CHECK_EQUAL(a.data_bytes, 33U);

    a = Analyze(multisig(1, 15), Kind::P2WSH, sigs(1), 5);
    BOOST_CHECK(a.known); // the bpub reveal is sane miniscript; the budget prices it
    BOOST_CHECK_EQUAL(a.data_bytes, 9U * 33U);

    a = Analyze(multisig(1, 15), Kind::P2WSH, sigs(1), 10);
    BOOST_CHECK_EQUAL(a.data_bytes, 4U * 33U); // #422's allowance, for comparison

    a = Analyze(multisig(1, 15), Kind::P2WSH, sigs(1), 3);
    BOOST_CHECK_EQUAL(a.data_bytes, 11U * 33U);

    // each signature beyond the first frees one more field: large legit multisig spent on its main path pays nothing
    BOOST_CHECK_EQUAL(Analyze(multisig(8, 15), Kind::P2WSH, sigs(8), 5).data_bytes, 0U);
    BOOST_CHECK_EQUAL(Analyze(multisig(3, 9), Kind::P2WSH, sigs(3), 5).data_bytes, 0U);
    BOOST_CHECK_EQUAL(Analyze(multisig(2, 8), Kind::P2WSH, sigs(2), 5).data_bytes, 0U);
    BOOST_CHECK_EQUAL(Analyze(multisig(2, 9), Kind::P2WSH, sigs(2), 5).data_bytes, 33U);
    // at allowance 1: 2-of-3 and 3-of-5 are free, 1-of-3 and 2-of-5 pay one key, 1-of-2 is free
    BOOST_CHECK_EQUAL(Analyze(multisig(2, 3), Kind::P2WSH, sigs(2), 1).data_bytes, 0U);
    BOOST_CHECK_EQUAL(Analyze(multisig(3, 5), Kind::P2WSH, sigs(3), 1).data_bytes, 0U);
    BOOST_CHECK_EQUAL(Analyze(multisig(1, 2), Kind::P2WSH, sigs(1), 1).data_bytes, 0U);
    BOOST_CHECK_EQUAL(Analyze(multisig(1, 3), Kind::P2WSH, sigs(1), 1).data_bytes, 33U);
    BOOST_CHECK_EQUAL(Analyze(multisig(2, 5), Kind::P2WSH, sigs(2), 1).data_bytes, 33U);

    // multi_a(1, 8) in tapscript: 8 keys, one signature, 7 empty items
    CScript multi_a;
    multi_a << Key32(1) << OP_CHECKSIG;
    for (int i = 2; i <= 8; ++i) multi_a << Key32(i) << OP_CHECKSIGADD;
    multi_a << OP_1 << OP_NUMEQUAL;
    Items items(7, Item{});
    items.push_back(Schnorr());
    a = Analyze(multi_a, Kind::TAPSCRIPT, items, 5);
    BOOST_CHECK(a.known);
    BOOST_CHECK_EQUAL(a.fields, 8U);
    BOOST_CHECK_EQUAL(a.proven, 1U);
    BOOST_CHECK_EQUAL(a.data_bytes, 2U * 32U);
}

BOOST_AUTO_TEST_CASE(input_hook)
{
    CScript one_of_15;
    one_of_15 << OP_1;
    for (int i = 0; i < 15; ++i) one_of_15 << Key33(i + 1);
    one_of_15 << OP_15 << OP_CHECKMULTISIG;
    CTxIn txin;
    txin.scriptWitness.stack = {Item{}, Der(), Item(one_of_15.begin(), one_of_15.end())};
    const CScript spk{GetScriptForDestination(WitnessV0ScriptHash(one_of_15))};
    const auto revealed{RevealedScript(spk, txin)};
    BOOST_REQUIRE(revealed.has_value());
    BOOST_CHECK(revealed->kind == Kind::P2WSH);
    BOOST_CHECK_EQUAL(revealed->items.size(), 2U);
    BOOST_CHECK_EQUAL(FieldBudgetBytes(spk, txin), 9U * 33U);

    // a key spend reveals nothing
    CTxIn keyspend;
    keyspend.scriptWitness.stack = {Der(), Key33(1)};
    BOOST_CHECK(!RevealedScript(GetScriptForDestination(WitnessV0KeyHash(CKeyID{})), keyspend).has_value());
}

BOOST_AUTO_TEST_CASE(spam_shapes_unknown)
{
    // bpub's dummy-push fallback from the #422 review: 13 dropped items, a 1-of-15, and a dead branch of CHECKSIGs
    CScript fallback;
    for (int i = 0; i < 13; ++i) fallback << OP_DROP;
    fallback << OP_1;
    for (int i = 0; i < 15; ++i) fallback << Key33(i + 1);
    fallback << OP_15 << OP_CHECKMULTISIG << OP_IF << OP_1 << OP_ELSE;
    for (int i = 0; i < 13; ++i) fallback << OP_CHECKSIG;
    fallback << OP_ENDIF;
    Items items(13, Item(65, 0xaa));
    items.push_back(Item{});
    items.push_back(Der());
    Analysis a{Analyze(fallback, Kind::P2WSH, items, 5)};
    BOOST_CHECK(!a.known);

    // or_i(pk, sha256): a hash branch nobody can satisfy with a signature is not sane miniscript
    CScript or_i;
    or_i << OP_IF << Key33(1) << OP_CHECKSIG << OP_ELSE << OP_SIZE << Item{32} << OP_EQUALVERIFY << OP_SHA256 << Hash32(9) << OP_EQUAL << OP_ENDIF;
    a = Analyze(or_i, Kind::P2WSH, {Der(), Item{1}}, 5);
    BOOST_CHECK(!a.known);

    // dead pushes before a key: `<data> OP_DROP <key> CHECKSIG` is Knots' datacarrier case, never a shape
    CScript dead;
    dead << Item(30, 0x55) << OP_DROP << Key32(1) << OP_CHECKSIG;
    a = Analyze(dead, Kind::TAPSCRIPT, {Schnorr()}, 5);
    BOOST_CHECK(!a.known);

    // a bare inscription: key check then pushes dropped in pairs
    CScript bare;
    bare << Key32(1) << OP_CHECKSIG << Item{'o', 'r', 'd'} << OP_1 << Item(10, 'x') << OP_0 << Item(255, 0x77) << Item(255, 0x77) << OP_2DROP << OP_2DROP << OP_2DROP;
    a = Analyze(bare, Kind::TAPSCRIPT, {Schnorr()}, 5);
    BOOST_CHECK(!a.known);

    // witness stuffing: a plain key check with 80-byte items the script never reads
    CScript pk;
    pk << Key33(1) << OP_CHECKSIG;
    Items stuffed(99, Item(80, 0x99));
    stuffed.push_back(Der());
    a = Analyze(pk, Kind::P2WSH, stuffed, 5);
    BOOST_CHECK(a.known);
    BOOST_CHECK(!a.items_typed);
}

BOOST_AUTO_TEST_CASE(ark_and_generic_rules)
{
    // Bark (connorslab/bark-xbt lib.rs): delayed_sign, timelock_sign, delay_timelock_sign, hash_and_sign(_v0), hash_delay_sign(_v0)
    CScript delayed_sign;
    delayed_sign << CScriptNum(700) << OP_CHECKSEQUENCEVERIFY << OP_DROP << Key32(1) << OP_CHECKSIG;
    Analysis a{Analyze(delayed_sign, Kind::TAPSCRIPT, {Schnorr()}, 5)};
    BOOST_CHECK(a.known);
    BOOST_CHECK_EQUAL(a.shape, "miniscript-timelock");
    BOOST_CHECK_EQUAL(a.data_bytes, 0U);

    CScript timelock_sign;
    timelock_sign << CScriptNum(980000) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << Key32(1) << OP_CHECKSIG;
    a = Analyze(timelock_sign, Kind::TAPSCRIPT, {Schnorr()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript-timelock");

    CScript both;
    both << CScriptNum(980000) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << CScriptNum(700) << OP_CHECKSEQUENCEVERIFY << OP_DROP << Key32(1) << OP_CHECKSIG;
    a = Analyze(both, Kind::TAPSCRIPT, {Schnorr()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript-timelock");

    // with the SIZE guard this is and_v(v:hash160(H), pk(K)), sane miniscript as written
    CScript hash_and_sign;
    hash_and_sign << OP_SIZE << Item{32} << OP_EQUALVERIFY << OP_HASH160 << Hash20(7) << OP_EQUALVERIFY << Key32(1) << OP_CHECKSIG;
    a = Analyze(hash_and_sign, Kind::TAPSCRIPT, {Schnorr(), Hash32(3)}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript");
    BOOST_CHECK_EQUAL(a.data_bytes, 0U);

    CScript hash_and_sign_v0;
    hash_and_sign_v0 << OP_HASH160 << Hash20(7) << OP_EQUALVERIFY << Key32(1) << OP_CHECKSIG;
    a = Analyze(hash_and_sign_v0, Kind::TAPSCRIPT, {Schnorr(), Hash32(3)}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript-hash");

    CScript hash_delay_sign;
    hash_delay_sign << CScriptNum(700) << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_SIZE << Item{32} << OP_EQUALVERIFY << OP_HASH160 << Hash20(7) << OP_EQUALVERIFY << Key32(1) << OP_CHECKSIG;
    a = Analyze(hash_delay_sign, Kind::TAPSCRIPT, {Schnorr(), Hash32(3)}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript-timelock-hash");

    // Arkade (arkade-os/arkd closure.go): CSV-prefixed two-key multisig, and the CHECKSIGADD form
    CScript csv_multisig;
    csv_multisig << CScriptNum(144) << OP_CHECKSEQUENCEVERIFY << OP_DROP << Key32(1) << OP_CHECKSIGVERIFY << Key32(2) << OP_CHECKSIG;
    a = Analyze(csv_multisig, Kind::TAPSCRIPT, {Schnorr(), Schnorr()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript-timelock");

    CScript csa;
    csa << Key32(1) << OP_CHECKSIG << Key32(2) << OP_CHECKSIGADD << OP_2 << OP_NUMEQUAL;
    a = Analyze(csa, Kind::TAPSCRIPT, {Schnorr(), Schnorr()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript");

    // key then timelock, and a trailing hash check without the SIZE guard
    CScript key_then_csv;
    key_then_csv << Key32(1) << OP_CHECKSIG << CScriptNum(144) << OP_CHECKSEQUENCEVERIFY << OP_DROP;
    a = Analyze(key_then_csv, Kind::TAPSCRIPT, {Schnorr()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript-timelock");

    CScript key_then_hash;
    key_then_hash << Key32(1) << OP_CHECKSIGVERIFY << OP_HASH160 << Hash20(7) << OP_EQUAL;
    a = Analyze(key_then_hash, Kind::TAPSCRIPT, {Hash32(3), Schnorr()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript-hash");

    // the tagged leaf: two keys and a 66-byte tag counted as data
    CScript tagged;
    tagged << Key32(1) << OP_CHECKSIGVERIFY << Key32(2) << OP_CHECKSIGVERIFY << Item(66, 'a');
    a = Analyze(tagged, Kind::TAPSCRIPT, {Schnorr(), Schnorr()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "tagged-2of2");
    BOOST_CHECK_EQUAL(a.data_bytes, 66U);

    // OP_TRUE anchor: known only with an empty witness
    CScript anchor;
    anchor << OP_1;
    a = Analyze(anchor, Kind::P2WSH, {}, 5);
    BOOST_CHECK(a.known);
    BOOST_CHECK_EQUAL(a.shape, "anchor-true");
    a = Analyze(anchor, Kind::P2WSH, {Item(80, 0x99)}, 5);
    BOOST_CHECK(!a.known);
    a = Analyze(anchor, Kind::TAPSCRIPT, {}, 5); // the test framework's MiniWallet spends such a leaf
    BOOST_CHECK(a.known);

    // legacy P2SH multisig with uncompressed keys, and the same shape refused in P2WSH
    CScript legacy;
    legacy << OP_2 << Key33(1) << Item(65, 0x04) << Key33(3) << OP_3 << OP_CHECKMULTISIG;
    a = Analyze(legacy, Kind::P2SH, {Item{}, Der(), Der()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "legacy-multisig");
    a = Analyze(legacy, Kind::P2WSH, {Item{}, Der(), Der()}, 5);
    BOOST_CHECK(!a.known);
}

BOOST_AUTO_TEST_CASE(branches_and_federations)
{
    // OP_IF A OP_ELSE B OP_ENDIF with two known branches: a P2SH HTLC with a timelock-first refund and a hash-first claim
    CScript htlc;
    htlc << OP_IF << CScriptNum(980000) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << Key33(1) << OP_CHECKSIG
         << OP_ELSE << OP_SIZE << Item{32} << OP_EQUALVERIFY << OP_HASH160 << Hash20(7) << OP_EQUALVERIFY << Key33(2) << OP_CHECKSIG << OP_ENDIF;
    Analysis a{Analyze(htlc, Kind::P2SH, {Der(), Item{1}}, 5)};
    BOOST_CHECK(a.known);
    BOOST_CHECK_EQUAL(a.shape, "branches(miniscript-timelock,miniscript)");
    BOOST_CHECK_EQUAL(a.data_bytes, 0U);

    // timelock-first 2-of-2, or a single key after a longer delay
    CScript two_paths;
    two_paths << OP_IF << OP_1 << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_2 << Key33(1) << Key33(2) << OP_2 << OP_CHECKMULTISIG
              << OP_ELSE << CScriptNum(300) << OP_CHECKSEQUENCEVERIFY << OP_DROP << Key33(3) << OP_CHECKSIG << OP_ENDIF;
    a = Analyze(two_paths, Kind::P2WSH, {Item{}, Der(), Der(), Item{1}}, 5);
    BOOST_CHECK(a.known);

    // a branch that is a data push is not a known shape, so the whole script is not
    CScript padded;
    padded << OP_IF << Key33(1) << OP_CHECKSIG << OP_ELSE << Item(80, 0xaa) << OP_DROP << OP_1 << OP_ENDIF;
    a = Analyze(padded, Kind::P2WSH, {Der(), Item{1}}, 5);
    BOOST_CHECK(!a.known);

    // CHECKSIGADD thresholds written with GREATERTHANOREQUAL, behind a timelock and behind a CHECKSIGVERIFY
    CScript thresh_csv;
    thresh_csv << OP_1 << OP_CHECKSEQUENCEVERIFY << OP_DROP << Key32(1) << OP_CHECKSIG;
    for (int i = 2; i <= 6; ++i) thresh_csv << Key32(i) << OP_CHECKSIGADD;
    thresh_csv << OP_3 << OP_GREATERTHANOREQUAL;
    a = Analyze(thresh_csv, Kind::TAPSCRIPT, {Item{}, Item{}, Schnorr(), Schnorr(), Schnorr(), Item{}}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript-timelock");
    BOOST_CHECK_EQUAL(a.data_bytes, 0U);

    CScript thresh_csv_prefix;
    thresh_csv_prefix << Key32(9) << OP_CHECKSIGVERIFY << Key32(1) << OP_CHECKSIG << Key32(2) << OP_CHECKSIGADD << Key32(3) << OP_CHECKSIGADD << OP_2 << OP_GREATERTHANOREQUAL;
    a = Analyze(thresh_csv_prefix, Kind::TAPSCRIPT, {Item{}, Schnorr(), Schnorr(), Schnorr()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "checksigadd-threshold");

    // Rootstock PowPeg: 5-of-9 or 3-of-4 after a delay, spent by the federation; the unsigned keys are not a data slot
    CScript powpeg;
    powpeg << OP_NOTIF << OP_5;
    for (int i = 1; i <= 9; ++i) powpeg << Key33(i);
    powpeg << OP_9 << OP_CHECKMULTISIG << OP_ELSE << CScriptNum(3) << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_3;
    for (int i = 10; i <= 13; ++i) powpeg << Key33(i);
    powpeg << OP_4 << OP_CHECKMULTISIG << OP_ENDIF;
    Items fed{Item{}};
    for (int i = 0; i < 5; ++i) fed.push_back(Der());
    fed.push_back(Item{});
    a = Analyze(powpeg, Kind::P2WSH, fed, 5);
    BOOST_CHECK_EQUAL(a.shape, "powpeg");
    BOOST_CHECK_EQUAL(a.fields, 13U);
    BOOST_CHECK_EQUAL(a.data_bytes, 0U);
    // the Flyover form carries a 32-byte commitment that is dropped: counted
    CScript flyover;
    flyover << Hash32(5) << OP_DROP;
    flyover.insert(flyover.end(), powpeg.begin(), powpeg.end());
    a = Analyze(flyover, Kind::P2WSH, fed, 5);
    BOOST_CHECK_EQUAL(a.shape, "powpeg");
    BOOST_CHECK_EQUAL(a.data_bytes, 32U);

    // a copy of the Liquid layout with fake keys, spent on the emergency path with two signatures, pays for the 15 keys it
    // leaves unsigned; the real federation spends the main path with 11 signatures and pays nothing
    CScript liquid;
    liquid << OP_11;
    for (int i = 1; i <= 15; ++i) liquid << Key33(i);
    liquid << OP_15 << OP_CHECKMULTISIG << OP_IFDUP << OP_NOTIF << CScriptNum(4032) << OP_CHECKSEQUENCEVERIFY << OP_VERIFY << OP_2;
    for (int i = 16; i <= 18; ++i) liquid << Key33(i);
    liquid << OP_3 << OP_CHECKMULTISIG << OP_ENDIF;
    Items emergency(12, Item{}); // the dummy and 11 empty signatures fail the first multisig
    emergency.push_back(Der());
    emergency.push_back(Der());
    a = Analyze(liquid, Kind::P2WSH, emergency, 5);
    BOOST_CHECK_EQUAL(a.shape, "liquid-federation");
    BOOST_CHECK_EQUAL(a.fields, 18U);
    BOOST_CHECK_EQUAL(a.proven, 2U);
    BOOST_CHECK_EQUAL(a.data_bytes, (16U - 6U) * 33U);
    Items main{Item{}};
    for (int i = 0; i < 11; ++i) main.push_back(Der());
    a = Analyze(liquid, Kind::P2WSH, main, 5);
    BOOST_CHECK_EQUAL(a.data_bytes, 0U);

    // preimage chains: the preimages are chosen bytes, so witness bytes past two keys' worth count as data
    CScript chain;
    for (int i = 1; i <= 4; ++i) chain << OP_SHA256 << Hash32(i) << OP_EQUALVERIFY;
    chain << Key33(9) << OP_CHECKSIG;
    a = Analyze(chain, Kind::P2WSH, {Der(), Hash32(11), Hash32(12), Hash32(13), Hash32(14)}, 5);
    BOOST_CHECK(a.known);
    BOOST_CHECK_EQUAL(a.data_bytes, 4U * 32U - 66U);
    CScript pkh_chain;
    for (int i = 1; i <= 3; ++i) pkh_chain << OP_HASH160 << Hash20(i) << OP_EQUALVERIFY;
    pkh_chain << Key33(9) << OP_CHECKSIG;
    a = Analyze(pkh_chain, Kind::P2WSH, {Der(), Key33(1), Key33(2), Key33(3)}, 5);
    BOOST_CHECK_EQUAL(a.data_bytes, 3U * 33U - 66U);
    // one preimage, or two keys and a selector, stay free
    a = Analyze(chain, Kind::P2WSH, {Der(), Hash32(11), Item{1}}, 5);
    BOOST_CHECK_EQUAL(a.data_bytes, 0U);

    // the shared-CHECKSIG HTLC templates
    CScript htlc_cltv;
    htlc_cltv << OP_HASH160 << Hash20(1) << OP_EQUAL << OP_IF << Key33(1) << OP_ELSE << CScriptNum(980000) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << Key33(2) << OP_ENDIF << OP_CHECKSIG;
    a = Analyze(htlc_cltv, Kind::P2WSH, {Der(), Hash32(3)}, 5);
    BOOST_CHECK_EQUAL(a.shape, "htlc-hash160-cltv");
}

BOOST_AUTO_TEST_CASE(pre_fork_shapes)
{
    // shapes the year before the fork surfaced
    Item junk(33, 0x00); // a key push that is not a valid public key: an unproven field, not an unknown shape
    CScript fake23;
    fake23 << OP_2 << Key33(1) << junk << Key33(3) << OP_3 << OP_CHECKMULTISIG;
    Analysis a{Analyze(fake23, Kind::P2WSH, {Item{}, Der(), Der()}, 5)};
    BOOST_CHECK_EQUAL(a.shape, "miniscript");
    BOOST_CHECK_EQUAL(a.data_bytes, 0U);

    CScript cltv_hash_pkh;
    cltv_hash_pkh << CScriptNum(950000) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_SHA256 << Hash32(1) << OP_EQUALVERIFY << OP_DUP << OP_HASH160 << Hash20(2) << OP_EQUALVERIFY << OP_CHECKSIG;
    a = Analyze(cltv_hash_pkh, Kind::P2WSH, {Der(), Key33(2), Hash32(9)}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript-timelock-hash");

    CScript two_hashes;
    two_hashes << OP_SHA256 << Hash32(1) << OP_EQUALVERIFY << OP_SHA256 << Hash32(2) << OP_EQUALVERIFY << Key33(3) << OP_CHECKSIG;
    a = Analyze(two_hashes, Kind::P2WSH, {Der(), Hash32(8), Hash32(9)}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript-hash");
    BOOST_CHECK_EQUAL(a.data_bytes, 0U);

    CScript delayed_anyone;
    delayed_anyone << Item{2} << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_1;
    a = Analyze(delayed_anyone, Kind::P2WSH, {}, 5);
    BOOST_CHECK_EQUAL(a.shape, "anyone-after-checks");
    BOOST_CHECK(a.known);
    a = Analyze(delayed_anyone, Kind::P2WSH, {Item(80, 0x99)}, 5);
    BOOST_CHECK(!a.known);
    CScript hashlock_anyone;
    hashlock_anyone << OP_SHA256 << Hash32(1) << OP_EQUALVERIFY << OP_1;
    a = Analyze(hashlock_anyone, Kind::TAPSCRIPT, {Hash32(7)}, 5);
    BOOST_CHECK(a.known);

    CScript any_sig;
    any_sig << Key32(1) << OP_CHECKSIG << Key32(2) << OP_CHECKSIGADD;
    a = Analyze(any_sig, Kind::TAPSCRIPT, {Item{}, Schnorr()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "checksigadd-threshold");
    CScript equal_thresh;
    equal_thresh << Key32(1) << OP_CHECKSIG << Key32(2) << OP_CHECKSIGADD << OP_2 << OP_EQUAL;
    a = Analyze(equal_thresh, Kind::TAPSCRIPT, {Schnorr(), Schnorr()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "checksigadd-threshold");

    CScript commitment;
    commitment << Key32(1) << OP_CHECKSIG << OP_IF << Hash32(5) << OP_ENDIF;
    a = Analyze(commitment, Kind::TAPSCRIPT, {Schnorr()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "key-then-commitment");
    BOOST_CHECK_EQUAL(a.data_bytes, 32U);

    CScript tagged_branch;
    tagged_branch << OP_IF << Key33(1) << OP_CHECKSIGVERIFY << Hash32(5) << OP_ELSE << Item{2} << OP_CHECKSEQUENCEVERIFY << OP_DROP << Key33(2) << OP_CHECKSIG << OP_ENDIF;
    a = Analyze(tagged_branch, Kind::P2WSH, {Der(), Item{1}}, 5);
    BOOST_CHECK_EQUAL(a.shape, "branches(tagged-key,miniscript-timelock)");
    BOOST_CHECK_EQUAL(a.data_bytes, 32U);

    CScript verify_branches;
    verify_branches << OP_IF << Key33(1) << OP_CHECKSIGVERIFY << OP_HASH160 << Hash20(2) << OP_EQUALVERIFY
                    << OP_ELSE << CScriptNum(950000) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << Key33(3) << OP_CHECKSIGVERIFY << OP_ENDIF;
    a = Analyze(verify_branches, Kind::P2WSH, {Item{1}, Hash32(9), Der(), Item{1}}, 5);
    BOOST_CHECK(a.known);

    CScript dup_key;
    dup_key << Key32(1) << OP_CHECKSIGVERIFY << Key32(1) << OP_CHECKSIG;
    a = Analyze(dup_key, Kind::TAPSCRIPT, {Schnorr(), Schnorr()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "miniscript");

    CScript legacy_pk;
    legacy_pk << CScriptNum(950000) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << Item(65, 0x04) << OP_CHECKSIG;
    a = Analyze(legacy_pk, Kind::P2SH, {Der()}, 5);
    BOOST_CHECK_EQUAL(a.shape, "legacy-pk-timelock");
    a = Analyze(legacy_pk, Kind::P2WSH, {Der()}, 5);
    BOOST_CHECK(!a.known);
}

BOOST_AUTO_TEST_CASE(items_typed_by_kind_and_signature_capacity)
{
    // A HASH160 chain satisfied with 64-byte preimages. In P2WSH a 64-byte item is no signature: it is a preimage,
    // counted as witness bytes past the free 66, so the chain pays for what it carries.
    CScript chain;
    for (int i = 0; i < 17; ++i) chain << OP_HASH160 << Hash20(i + 1) << OP_EQUALVERIFY;
    chain << Key33(1) << OP_CHECKSIG;
    Items pre64{Der()};
    for (int i = 0; i < 17; ++i) pre64.push_back(Item(64, 0x33));
    Analysis a{Analyze(chain, Kind::P2WSH, pre64, 5)};
    BOOST_CHECK(a.known);
    BOOST_CHECK(a.items_typed);
    BOOST_CHECK_EQUAL(a.proven, 2U); // the signature, and the first preimage within the free bytes
    BOOST_CHECK(a.data_bytes >= 17 * 64 - MAX_FREE_WITNESS_BYTES);

    // The same chain in tapscript, where 64 bytes is a signature by size: the script can check one, the rest are
    // witness bytes.
    CScript tchain;
    for (int i = 0; i < 17; ++i) tchain << OP_HASH160 << Hash20(i + 1) << OP_EQUALVERIFY;
    tchain << Key32(1) << OP_CHECKSIG;
    Items pre64t{Schnorr()};
    for (int i = 0; i < 17; ++i) pre64t.push_back(Item(64, 0x33));
    a = Analyze(tchain, Kind::TAPSCRIPT, pre64t, 5);
    BOOST_CHECK(a.known);
    BOOST_CHECK(a.items_typed);
    BOOST_CHECK_EQUAL(a.proven, 2U);
    BOOST_CHECK(a.data_bytes >= 17 * 64 - MAX_FREE_WITNESS_BYTES);

    // A second signature-shaped item beyond what the script checks buys nothing and is counted past the free bytes
    CScript pk;
    pk << Key33(1) << OP_CHECKSIG;
    a = Analyze(pk, Kind::P2WSH, {Der(), Der()}, 5);
    BOOST_CHECK_EQUAL(a.proven, 1U);
    BOOST_CHECK_EQUAL(a.data_bytes, 71U - MAX_FREE_WITNESS_BYTES);

    // 65-byte pushes are keys in P2SH only: the PowPeg layout with uncompressed slots is known there, with every slot
    // a field, and unknown in P2WSH, where such a slot can never sign.
    CScript powpeg;
    powpeg << OP_NOTIF << OP_1;
    for (int i = 0; i < 15; ++i) powpeg << Item(65, 0x04);
    powpeg << Key33(1) << OP_16 << OP_CHECKMULTISIG << OP_ELSE << CScriptNum(100) << OP_CHECKSEQUENCEVERIFY << OP_DROP
           << OP_1 << Key33(1) << OP_1 << OP_CHECKMULTISIG << OP_ENDIF;
    a = Analyze(powpeg, Kind::P2WSH, {Item{}, Der(), Item{}}, 5);
    BOOST_CHECK(!a.known);
    a = Analyze(powpeg, Kind::P2SH, {Item{}, Der(), Item{}}, 5);
    BOOST_CHECK(a.known);
    BOOST_CHECK_EQUAL(a.shape, "powpeg");
    BOOST_CHECK_EQUAL(a.fields, 17U);
    BOOST_CHECK(a.data_bytes > 0);

    // LND taproot channel leaves: the anchor is a bare timelock spent with nothing, the revocation leaf drops the
    // local key before the revocation key signs
    CScript anchor;
    anchor << OP_16 << OP_CHECKSEQUENCEVERIFY;
    a = Analyze(anchor, Kind::TAPSCRIPT, {}, 5);
    BOOST_CHECK(a.known);
    BOOST_CHECK_EQUAL(a.shape, "anyone-after-timelock");
    BOOST_CHECK_EQUAL(a.data_bytes, 0U);
    a = Analyze(anchor, Kind::TAPSCRIPT, {Item(40, 0x11)}, 5);
    BOOST_CHECK(!a.known);
    CScript revoke;
    revoke << Key32(1) << OP_DROP << Key32(2) << OP_CHECKSIG;
    a = Analyze(revoke, Kind::TAPSCRIPT, {Schnorr()}, 5);
    BOOST_CHECK(a.known);
    BOOST_CHECK_EQUAL(a.shape, "ln-taproot-revoke");
    BOOST_CHECK_EQUAL(a.fields, 2U);
    BOOST_CHECK_EQUAL(a.data_bytes, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
