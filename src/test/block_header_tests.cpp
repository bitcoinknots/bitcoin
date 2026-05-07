// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/block_header_v2.json.h>

#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(block_header_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(v2_test_vectors)
{
    UniValue data;
    BOOST_REQUIRE(data.read(json_tests::block_header_v2));
    BOOST_REQUIRE(data.isObject());
    for (const UniValue& test : data["headers"].getValues()) {
        const UniValue& fields{test["fields"]};
        CBlockHeader header;
        header.m_header_v2 = true;
        header.nVersion = fields["nVersion"].getInt<int32_t>();
        header.hashPrevBlock = *uint256::FromHex(fields["hashPrevBlock"].get_str());
        header.hashMerkleRoot = *uint256::FromHex(fields["hashMerkleRoot"].get_str());
        header.nTime = fields["nTime"].getInt<uint32_t>();
        header.nBits = fields["nBits"].getInt<uint32_t>();
        header.nNonce = fields["nNonce"].getInt<uint32_t>();
        header.m_nonce2 = fields["m_nonce2"].getInt<uint32_t>();
        header.m_nonce3 = fields["m_nonce3"].getInt<uint32_t>();
        const auto extranonce{ParseHex(fields["m_extranonce"].get_str())};
        BOOST_REQUIRE_EQUAL(extranonce.size(), header.m_extranonce.size());
        std::reverse_copy(extranonce.begin(), extranonce.end(), header.m_extranonce.begin());
        header.m_time_offset = fields["m_time_offset"].getInt<uint32_t>();
        header.m_txcount = fields["m_txcount"].getInt<uint16_t>();
        header.m_flags = fields["m_flags"].getInt<uint8_t>();
        header.m_xor_key_mask_clear_bits = fields["m_xor_key_mask_clear_bits"].getInt<uint8_t>();
        const auto xor_key{ParseHex(fields["m_xor_key"].get_str())};
        BOOST_REQUIRE_EQUAL(xor_key.size(), header.m_xor_key.size());
        std::reverse_copy(xor_key.begin(), xor_key.end(), header.m_xor_key.begin());
        header.m_height = fields["m_height"].getInt<int32_t>();
        header.m_mm_rhs = *uint256::FromHex(fields["m_mm_rhs"].get_str());
        BOOST_CHECK_EQUAL(header.m_flags & 3, test["asic_profile"].getInt<uint8_t>());

        DataStream encoded;
        encoded << header;
        BOOST_CHECK_EQUAL(encoded.size(), 164U);
        BOOST_CHECK_EQUAL(HexStr(encoded), test["serialized"].get_str());
        BOOST_CHECK_EQUAL(header.GetHash().GetHex(), test["block_hash"].get_str());

        CBlockHeader decoded;
        encoded >> decoded;
        BOOST_CHECK_EQUAL(decoded.nTime, header.nTime);
        BOOST_CHECK_EQUAL(decoded.GetHash().GetHex(), test["block_hash"].get_str());
    }
}

BOOST_AUTO_TEST_SUITE_END()
