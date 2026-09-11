// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/sharepool.h>
#include <consensus/validation.h>
#include <key.h>
#include <pow.h>
#include <script/script.h>
#include <sharepool/signer.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <versionbits.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <memory>
#include <vector>

namespace {
/** A bounded, real-signature seed reaches validation beyond random decoding. */
struct SharePoolFuzzContext {
    Consensus::Params consensus{Params().GetConsensus()};
    std::array<CBlockIndex, 5> indexes;
    std::array<uint256, 5> hashes;
    sharepool::Manifest seed;
    std::vector<unsigned char> encoded_seed;

    SharePoolFuzzContext()
    {
        consensus.SharePoolHeight = 1;
        consensus.Blake2bHeight = 1;
        for (size_t i{0}; i < indexes.size(); ++i) {
            hashes[i] = uint256{static_cast<uint8_t>(i + 1)};
            indexes[i].phashBlock = &hashes[i];
            indexes[i].nHeight = i;
            indexes[i].nTime = 1000 + i * 600;
            indexes[i].nBits = sharepool::SHARE_BITS;
            indexes[i].m_header_v2 = i > 0;
            if (i) {
                indexes[i].pprev = &indexes[i - 1];
                indexes[i].BuildSkip();
            }
        }
        CKey key;
        std::array<unsigned char, 32> secret{};
        secret.back() = 1; // Public fixture key; never production signing.
        key.Set(secret.begin(), secret.end(), true);
        const XOnlyPubKey pubkey{key.GetPubKey()};
        auto owner = [&](uint32_t height) {
            sharepool::Envelope envelope;
            envelope.genesis = consensus.hashGenesisBlock;
            envelope.rules = sharepool::RulesHash();
            envelope.height = height;
            envelope.native_parent = hashes[height - 1];
            envelope.pool = uint256{uint8_t{3}};
            std::copy(pubkey.begin(), pubkey.end(), envelope.owner.begin());
            envelope.payout_script = {OP_0, 20};
            envelope.payout_script.resize(22, 0x61);
            return envelope;
        };
        auto sign = [&](const sharepool::Envelope& envelope) {
            sharepool::Signature signature{};
            const bool signed_ok = key.SignSchnorr(sharepool::OwnerHash(envelope), signature, nullptr, {});
            assert(signed_ok);
            return signature;
        };
        seed.current = owner(2);
        seed.has_parent = 1;
        seed.parent = owner(1);
        indexes[1].m_mm_rhs = sharepool::EnvelopeHash(seed.parent);
        sharepool::Share share;
        share.origin = owner(2);
        share.authorization = sign(share.origin);
        auto& header = share.header;
        header.m_header_v2 = true;
        header.nVersion = VERSIONBITS_TOP_BITS;
        header.m_height = 2;
        header.hashPrevBlock = hashes[1];
        header.hashMerkleRoot = uint256{uint8_t{7}};
        header.m_txcount = 1;
        header.nTime = indexes[1].nTime + 1;
        header.nBits = GetNextWorkRequired(&indexes[1], &header, consensus);
        header.m_mm_rhs = sharepool::EnvelopeHash(share.origin);
        bool solved{false};
        for (uint32_t nonce{0}; nonce < 256; ++nonce) {
            header.nNonce = nonce;
            if (UintToArith256(header.GetHash()) <= arith_uint256{}.SetCompact(sharepool::SHARE_BITS)) {
                solved = true;
                break;
            }
        }
        assert(solved);
        seed.shares = {share};
        seed.current.shares_root = sharepool::SharesRoot(seed.shares);
        seed.current.state_root = sharepool::StateRoot({{2, header.GetHash()}});
        seed.current.payouts_root = sharepool::PayoutsRoot(sharepool::CalculatePayouts(seed, 100003));
        seed.authorization = sign(seed.current);
        encoded_seed = sharepool::EncodeManifest(seed);
    }

    CBlock Block(Span<const unsigned char> bytes, const sharepool::Envelope& envelope) const
    {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript{} << int64_t{2} << OP_0;
        coinbase.vout = sharepool::CalculatePayouts(seed, 100003);
        const auto carriers = sharepool::CarrierOutputs(bytes);
        coinbase.vout.insert(coinbase.vout.end(), carriers.begin(), carriers.end());
        CBlock block;
        block.m_header_v2 = true;
        block.nVersion = VERSIONBITS_TOP_BITS;
        block.m_height = 2;
        block.hashPrevBlock = hashes[1];
        block.nTime = indexes[1].nTime + 1;
        block.nBits = sharepool::SHARE_BITS;
        block.m_txcount = 1;
        block.vtx = {MakeTransactionRef(std::move(coinbase))};
        block.hashMerkleRoot = BlockMerkleRoot(block);
        block.m_mm_rhs = sharepool::EnvelopeHash(envelope);
        return block;
    }

    void Check(const CBlock& block) const
    {
        BlockValidationState state_a, state_b, state_without_reward;
        const bool result = CheckSharePoolBlock(block, state_a, consensus, &indexes[1], 100003);
        // Neither parsing nor validation may mutate context or depend on call order.
        assert(result == CheckSharePoolBlock(block, state_b, consensus, &indexes[1], 100003));
        assert(state_a.GetRejectReason() == state_b.GetRejectReason());
        const bool without_reward = CheckSharePoolBlock(block, state_without_reward, consensus, &indexes[1]);
        assert(!result || without_reward);
    }
};

std::unique_ptr<SharePoolFuzzContext> g_context;

void InitializeSharePool()
{
    static const auto testing_setup = MakeNoLogFileContext<>(ChainType::REGTEST);
    g_context = std::make_unique<SharePoolFuzzContext>();
    BlockValidationState state;
    assert(CheckSharePoolBlock(g_context->Block(g_context->encoded_seed, g_context->seed.current),
                              state, g_context->consensus, &g_context->indexes[1], 100003));
}
} // namespace

FUZZ_TARGET(sharepool, .init = InitializeSharePool)
{
    // Bounds include exactly one oversized input to exercise early rejection.
    if (buffer.size() > sharepool::MAX_MANIFEST + 1) return;
    const auto raw = Span{buffer.data(), buffer.size()};
    if (raw.size() <= sharepool::signer::MAX_POLICY_BYTES + 1) {
        try {
            const auto policy = sharepool::signer::DecodePolicy(raw);
            DataStream encoded;
            encoded << policy;
            assert(encoded.size() == raw.size());
            assert(std::equal(raw.begin(), raw.end(), UCharCast(encoded.data())));
            assert(sharepool::IsPayoutScript(policy.payout_script));
        } catch (const std::ios_base::failure&) {
        } catch (const std::invalid_argument&) {
        }
    }
    if (raw.size() <= sharepool::signer::MAX_ENVELOPE_BYTES + 1) {
        try {
            const auto envelope = sharepool::signer::DecodeEnvelope(raw);
            DataStream encoded;
            encoded << envelope;
            assert(encoded.size() == raw.size());
            assert(std::equal(raw.begin(), raw.end(), UCharCast(encoded.data())));
        } catch (const std::ios_base::failure&) {
        } catch (const std::invalid_argument&) {
        }
    }
    try {
        auto manifest = sharepool::DecodeManifest(raw);
        const auto encoded = sharepool::EncodeManifest(manifest);
        assert(std::equal(encoded.begin(), encoded.end(), raw.begin(), raw.end()));
        for (const auto& output : sharepool::CarrierOutputs(encoded)) assert(output.scriptPubKey.size() <= 83);
        for (const CAmount reward : {CAmount{0}, CAmount{1}, CAmount{100003}, MAX_MONEY}) {
            const auto payouts = sharepool::CalculatePayouts(manifest, reward);
            CAmount total{0};
            for (const auto& payout : payouts) {
                assert(MoneyRange(payout.nValue));
                assert(payout.nValue <= MAX_MONEY - total);
                total += payout.nValue;
            }
            assert(total == reward);
            std::reverse(manifest.shares.begin(), manifest.shares.end());
            assert(payouts == sharepool::CalculatePayouts(manifest, reward));
        }
        g_context->Check(g_context->Block(encoded, manifest.current));
    } catch (const std::ios_base::failure&) {
        // Truncation, nonminimal CompactSize and all advertised vector bounds.
    }

    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    auto mutated = g_context->encoded_seed;
    // Always bounded: mutations retain a useful signed seed for deep paths.
    LIMITED_WHILE(provider.remaining_bytes() > 0, 32) {
        const auto offset = provider.ConsumeIntegralInRange<size_t>(0, mutated.size() - 1);
        mutated[offset] ^= provider.ConsumeIntegral<unsigned char>();
    }
    auto block = g_context->Block(mutated, g_context->seed.current);
    g_context->Check(block);
    // Fuzz carrier framing independently of manifest serialization.
    CMutableTransaction coinbase{*block.vtx[0]};
    if (!buffer.empty()) {
        const size_t output = buffer[0] % coinbase.vout.size();
        const size_t offset = buffer.back() % coinbase.vout[output].scriptPubKey.size();
        coinbase.vout[output].scriptPubKey[offset] ^= buffer[buffer.size() / 2];
        block.vtx[0] = MakeTransactionRef(std::move(coinbase));
    }
    g_context->Check(block);
}
