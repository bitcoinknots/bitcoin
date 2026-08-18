// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

#include <concepts>
#include <type_traits>
#include <utility>

// A compressed CBlockHeader, which leaves out the prevhash
struct CompressedHeader {
    // header
    bool m_header_v2{false};
    int32_t nVersion{0};
    uint256 hashMerkleRoot;
    uint32_t nTime{0};
    uint32_t nBits{0};
    // Direct PoW/ASIC grinding:
    uint32_t nNonce{0};
    uint32_t m_nonce2{0};
    uint64_t m_nonce3{0};
    // Sv1 extranonce:
    uint128 m_extranonce{};
    // Header 1 effectively-nonce, reserved:
    uint16_t m_reserved1{0};
    uint8_t m_reserved{0};

    uint8_t m_xor_key_mask_clear_bits{0};
    uint128 m_xor_key{};
    uint256 m_mm_rhs;

    CompressedHeader()
    {
        hashMerkleRoot.SetNull();
    }

    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader : public CompressedHeader
{
public:
    // header
    uint256 hashPrevBlock;
    int32_t m_height;

    CBlockHeader()
    {
        SetNull();
    }

    template <typename T> requires std::same_as<std::remove_cvref_t<T>, CompressedHeader>
    CBlockHeader(T&& compressed_header, const uint256& hash_prev_block, const int32_t height)
    : CompressedHeader(std::forward<T>(compressed_header)),
      hashPrevBlock(hash_prev_block),
      m_height(m_header_v2 ? height : 0)
    {
    }

    SERIALIZE_METHODS(CBlockHeader, obj) {
        constexpr uint32_t v2_flag{0x80000000UL};
        uint32_t v;
        SER_WRITE(obj, v = (obj.m_header_v2 ? v2_flag : (uint32_t)0) | (uint32_t)obj.nVersion);
        READWRITE(v, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce);
        SER_READ(obj, obj.m_header_v2 = v & v2_flag);
        SER_READ(obj, obj.nVersion = v & ~v2_flag);
        if (obj.m_header_v2) {
            READWRITE(obj.m_nonce2, obj.m_nonce3, obj.m_extranonce, obj.m_reserved1, obj.m_reserved, obj.m_xor_key_mask_clear_bits, obj.m_xor_key, obj.m_height, obj.m_mm_rhs);
        } else {
            SER_READ(obj, obj.m_nonce2 = 0);
            SER_READ(obj, obj.m_nonce3 = 0);
            SER_READ(obj, obj.m_extranonce.SetNull());
            SER_READ(obj, obj.m_reserved1 = 0);
            SER_READ(obj, obj.m_reserved = 0);
            SER_READ(obj, obj.m_xor_key_mask_clear_bits = 0);
            SER_READ(obj, obj.m_xor_key.SetNull());
            SER_READ(obj, obj.m_height = 0);
            SER_READ(obj, obj.m_mm_rhs.SetNull());
        }
    }

    void SetNull()
    {
        m_header_v2 = false;
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        m_nonce2 = 0;
        m_nonce3 = 0;
        m_extranonce.SetNull();
        m_reserved1 = 0;
        m_reserved = 0;
        m_xor_key_mask_clear_bits = 0;
        m_xor_key.SetNull();
        m_height = 0;
        m_mm_rhs.SetNull();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    bool AreHeaderV2FieldsNull() const {
        if (m_header_v2) return false;
        if (m_nonce2) return false;
        if (m_nonce3) return false;
        if (!m_extranonce.IsNull()) return false;
        if (m_reserved1) return false;
        if (m_reserved) return false;
        if (m_xor_key_mask_clear_bits) return false;
        if (!m_xor_key.IsNull()) return false;
        if (!m_mm_rhs.IsNull()) return false;
        if (m_height) return false;
        return true;
    }

    uint256 GetHash() const;
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // Memory-only flags for caching expensive checks
    mutable bool fChecked;                            // CheckBlock()
    mutable bool m_checked_witness_commitment{false}; // CheckWitnessCommitment()
    mutable bool m_checked_merkle_root{false};        // CheckMerkleRoot()

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITE(AsBase<CBlockHeader>(obj), obj.vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        m_checked_witness_commitment = false;
        m_checked_merkle_root = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        return static_cast<const CBlockHeader&>(*this);
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    /** Historically CBlockLocator's version field has been written to network
     * streams as the negotiated protocol version and to disk streams as the
     * client version, but the value has never been used.
     *
     * Hard-code to the highest protocol version ever written to a network stream.
     * SerParams can be used if the field requires any meaning in the future,
     **/
    static constexpr int DUMMY_VERSION = 70016;

    std::vector<uint256> vHave;

    CBlockLocator() = default;

    explicit CBlockLocator(std::vector<uint256>&& have) : vHave(std::move(have)) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = DUMMY_VERSION;
        READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
