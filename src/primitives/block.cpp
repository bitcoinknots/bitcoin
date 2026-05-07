// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <crypto/blake2b.h>
#include <hash.h>
#include <streams.h>
#include <tinyformat.h>

uint256 CBlockHeader::GetHash() const
{
    if (!m_header_v2) {  // SHA256d
        // Historical algorithm and common case.
        Assume(AreHeaderV2FieldsNull());
        return (HashWriter{} << *this).GetHash();
    }

    // BLAKE2b

    static constexpr uint128 zeros{};

    // The pooling miner doesn't know m_xor_key (only the hash of it) until it finds a block
    auto xor_key_hash = TaggedHash("Bitcoin block hash PoW XOR key");
    xor_key_hash << m_xor_key;
    Assert(xor_key_hash.BytesWritten() == 0x40 + 0x10);  // TaggedHash adds 0x40 bytes extra

    uint256 xor_key_mask;
    if (!m_xor_key.IsNull()) {
        xor_key_mask = (TaggedHash("Bitcoin block hash PoW XOR mask") << m_xor_key).GetSHA256();
        const unsigned int xor_key_mask_clear_bytes = m_xor_key_mask_clear_bits / 8;
        std::fill_n(xor_key_mask.begin(), xor_key_mask_clear_bytes, uint8_t{0});
        xor_key_mask.begin()[xor_key_mask_clear_bytes] &= 0xffU >> (m_xor_key_mask_clear_bits % 8);
    }

    const uint256 prevblock_ordered_sane{hashPrevBlock.ReversedBytes()};
    uint256 prevblock_hidden = (TaggedHash("Bitcoin prevblock header, hashed") << prevblock_ordered_sane).GetSHA256();

    // These fields are invisible to the mining machine
    // This means the hasher cannot brick itself at some future block version, time, or difficulty
    auto h1 = TaggedHash("Bitcoin block header 1");
    h1 << GetCompleteVersion();
    h1 << prevblock_ordered_sane;
    h1 << m_height;
    h1 << hashMerkleRoot;
    h1 << GetTimeOnWire();
    h1 << (uint8_t)0;  // Reserved for extended 40-bit time
    h1 << nBits;
    h1 << (uint32_t)m_txcount;
    h1 << m_flags;
    h1 << m_xor_key_mask_clear_bits;
    h1 << xor_key_hash.GetSHA256();
    Assert(h1.BytesWritten() == 0x40 + 119);

    auto h2 = TaggedHash("Merge-mining hook");
    h2 << h1.GetSHA256();
    h2 << zeros << zeros;
    h2 << m_mm_rhs;
    Assert(h2.BytesWritten() == 0x40 + 0x60);

    const uint256 h2_hash{h2.GetSHA256()};

    // These fields get sent to mining machines over Sv1
    DataStream ss;
    ss << (uint32_t)0;   // Final 3 bytes are part of Sv1 "coinb1" (first is implied by hasher)
    ss << h2_hash;       // Remainder of Sv1 "coinb1"
    ss << m_extranonce;  // Sv1 "extranonce"
    Assert(ss.size() == 52);

    uint256 hash;
    Assert(0 == blake2b_nokey((void*)hash.begin(), hash.size(), (void*)ss.data(), ss.size()));

    // Presumably the actual mining ASIC hardware sees these
    ss.clear();
    switch (m_flags & 3) {
        case 3:
            ss << zeros << zeros;
            [[fallthrough]];
        case 2:
            ss << zeros << zeros << zeros;
            ss << h2_hash << nNonce << m_nonce2 << m_time_offset << m_nonce3 << hash;
            break;
        case 0:
        {
            std::fill_n(prevblock_hidden.begin(), 6, uint8_t{0});
            ss << prevblock_hidden << nNonce << m_nonce2 << m_time_offset << m_nonce3 << hash;
            break;
        }
        case 1:
            ss << nNonce << m_nonce2 << m_nonce3 << m_time_offset << hash << h2_hash;
            break;
    }

    Assert(0 == blake2b_nokey((void*)hash.begin(), hash.size(), (void*)ss.data(), ss.size()));

    uint256 final_hash;
    auto out = final_hash.end();
    for (size_t i = 0; i < hash.size(); ++i) {
        *--out = hash.begin()[i] ^ xor_key_mask.begin()[i];
    }

    return final_hash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        GetCompleteVersion(),
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
