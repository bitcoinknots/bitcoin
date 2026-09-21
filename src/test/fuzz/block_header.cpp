// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace {
//! Serialized size of a legacy header, and of a version 2 (BLAKE2b) header.
constexpr size_t HEADER_V1_SIZE{80};
constexpr size_t HEADER_V2_SIZE{164};
} // namespace

FUZZ_TARGET(block_header)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const std::optional<CBlockHeader> block_header = ConsumeDeserializable<CBlockHeader>(fuzzed_data_provider);
    if (!block_header) {
        return;
    }
    {
        const uint256 hash = block_header->GetHash();
        constexpr uint256 u256_max{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        assert(hash != u256_max);
        assert(block_header->GetBlockTime() == block_header->nTime);
        assert(block_header->IsNull() == (block_header->nBits == 0));
        // Hashing is a pure function of the header.
        assert(block_header->GetHash() == hash);
    }
    {
        // The version word carries the v2 marker in its high bit, and nVersion
        // never retains it.
        const uint32_t complete_version{block_header->GetCompleteVersion()};
        assert(block_header->m_header_v2 == ((complete_version & CompressedHeader::VERSION_HEADER_V2_FLAG) != 0));
        assert((static_cast<uint32_t>(block_header->nVersion) & CompressedHeader::VERSION_HEADER_V2_FLAG) == 0);

        // Re-serializing must reproduce the exact same bytes. The wire time is
        // derived from nTime and m_time_offset rather than stored directly, so a
        // mismatch here would mean a header that changes when it is relayed.
        DataStream stream;
        stream << *block_header;
        assert(stream.size() == (block_header->m_header_v2 ? HEADER_V2_SIZE : HEADER_V1_SIZE));
        const std::vector<std::byte> original{stream.begin(), stream.end()};

        CBlockHeader deserialized;
        stream >> deserialized;
        assert(stream.empty());

        DataStream reserialized;
        reserialized << deserialized;
        assert(std::equal(reserialized.begin(), reserialized.end(), original.begin(), original.end()));
        assert(deserialized.GetHash() == block_header->GetHash());

        // A legacy header must keep the historical algorithm: double-SHA256 over
        // its own 80 serialized bytes, and none of the v2 fields set.
        if (!block_header->m_header_v2) {
            assert(block_header->AreHeaderV2FieldsNull());
            assert(block_header->GetHash() == Hash(original));
        }
    }
    {
        // Exercise every ASIC profile, including the zero-padded 128- and
        // 160-byte stage-2 inputs, which the fuzzer would otherwise reach only
        // by chance.
        CBlockHeader profile_header{*block_header};
        profile_header.m_header_v2 = true;
        for (uint8_t profile{0}; profile < 4; ++profile) {
            profile_header.m_flags = (profile_header.m_flags & ~uint8_t{3}) | profile;
            (void)profile_header.GetHash();
        }
    }
    {
        CBlockHeader mut_block_header = *block_header;
        mut_block_header.SetNull();
        assert(mut_block_header.IsNull());
        assert(mut_block_header.AreHeaderV2FieldsNull());
        CBlock block{*block_header};
        assert(block.GetBlockHeader().GetHash() == block_header->GetHash());
        (void)block.ToString();
        block.SetNull();
        assert(block.GetBlockHeader().GetHash() == mut_block_header.GetHash());
    }
    {
        std::optional<CBlockLocator> block_locator = ConsumeDeserializable<CBlockLocator>(fuzzed_data_provider);
        if (block_locator) {
            (void)block_locator->IsNull();
            block_locator->SetNull();
            assert(block_locator->IsNull());
        }
    }
}
