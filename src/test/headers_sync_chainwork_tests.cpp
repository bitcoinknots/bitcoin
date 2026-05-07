// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <headerssync.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <vector>

#include <boost/test/unit_test.hpp>

struct HeadersGeneratorSetup : public RegTestingSetup {
    /** Search for a nonce to meet (regtest) proof of work */
    void FindProofOfWork(CBlockHeader& starting_header);
    /**
     * Generate headers in a chain that build off a given starting hash, using
     * the given nVersion, advancing time by 1 second from the starting
     * prev_time, and with a fixed merkle root hash.
     */
    void GenerateHeaders(std::vector<CBlockHeader>& headers, size_t count,
            const uint256& starting_hash, const int nVersion, int prev_time,
            const uint256& merkle_root, const uint32_t nBits);
};

void HeadersGeneratorSetup::FindProofOfWork(CBlockHeader& starting_header)
{
    while (!CheckProofOfWork(starting_header.GetHash(), starting_header.nBits, Params().GetConsensus())) {
        ++(starting_header.nNonce);
    }
}

void HeadersGeneratorSetup::GenerateHeaders(std::vector<CBlockHeader>& headers,
        size_t count, const uint256& starting_hash, const int nVersion, int prev_time,
        const uint256& merkle_root, const uint32_t nBits)
{
    uint256 prev_hash = starting_hash;

    while (headers.size() < count) {
        headers.emplace_back();
        CBlockHeader& next_header = headers.back();;
        next_header.nVersion = nVersion;
        next_header.hashPrevBlock = prev_hash;
        next_header.hashMerkleRoot = merkle_root;
        next_header.nTime = prev_time+1;
        next_header.nBits = nBits;

        FindProofOfWork(next_header);
        prev_hash = next_header.GetHash();
        prev_time = next_header.nTime;
    }
    return;
}

BOOST_FIXTURE_TEST_SUITE(headers_sync_chainwork_tests, HeadersGeneratorSetup)

// In this test, we construct two sets of headers from genesis, one with
// sufficient proof of work and one without.
// 1. We deliver the first set of headers and verify that the headers sync state
//    updates to the REDOWNLOAD phase successfully.
// 2. Then we deliver the second set of headers and verify that they fail
//    processing (presumably due to commitments not matching).
// 3. Finally, we verify that repeating with the first set of headers in both
//    phases is successful.
BOOST_AUTO_TEST_CASE(headers_sync_state)
{
    std::vector<CBlockHeader> first_chain;
    std::vector<CBlockHeader> second_chain;

    std::unique_ptr<HeadersSyncState> hss;

    const int target_blocks = 15000;
    arith_uint256 chain_work = target_blocks*2;

    // Generate headers for two different chains (using differing merkle roots
    // to ensure the headers are different).
    GenerateHeaders(first_chain, target_blocks-1, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(0), Params().GenesisBlock().nBits);

    GenerateHeaders(second_chain, target_blocks-2, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(1), Params().GenesisBlock().nBits);

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    std::vector<CBlockHeader> headers_batch;

    // Feed the first chain to HeadersSyncState, by delivering 1 header
    // initially and then the rest.
    headers_batch.insert(headers_batch.end(), std::next(first_chain.begin()), first_chain.end());

    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders({first_chain.front()}, true);
    // Pretend the first header is still "full", so we don't abort.
    auto result = hss->ProcessNextHeaders(headers_batch, true);

    // This chain should look valid, and we should have met the proof-of-work
    // requirement.
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    // Try to sneakily feed back the second chain.
    result = hss->ProcessNextHeaders(second_chain, true);
    BOOST_CHECK(!result.success); // foiled!
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Now try again, this time feeding the first chain twice.
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(!result.request_more);
    // All headers should be ready for acceptance:
    BOOST_CHECK(result.pow_validated_headers.size() == first_chain.size());
    // Nothing left for the sync logic to do:
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Finally, verify that just trying to process the second chain would not
    // succeed (too little work)
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);
     // Pretend just the first message is "full", so we don't abort.
    (void)hss->ProcessNextHeaders({second_chain.front()}, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);

    headers_batch.clear();
    headers_batch.insert(headers_batch.end(), std::next(second_chain.begin(), 1), second_chain.end());
    // Tell the sync logic that the headers message was not full, implying no
    // more headers can be requested. For a low-work-chain, this should causes
    // the sync to end with no headers for acceptance.
    result = hss->ProcessNextHeaders(headers_batch, false);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(!result.request_more);
    // Nevertheless, no validation errors should have been detected with the
    // chain:
    BOOST_CHECK(result.success);
}

// End-to-end: a peer serving the PoW-change fork block presyncs successfully,
// while a peer claiming the same target drop before activation is rejected.
// HeadersSyncState does not itself verify proof of work, so the headers here
// are unmined; only nBits and connectivity matter to this path.
BOOST_AUTO_TEST_CASE(headers_sync_powchange_fork)
{
    const auto mainnet = CreateChainParams(*m_node.args, ChainType::MAIN);
    Consensus::Params params = mainnet->GetConsensus();
    BOOST_CHECK(!params.fPowAllowMinDifficultyBlocks);

    // Must be in the past: m_max_commitments is derived from wall clock minus
    // the chain_start time, so a future timestamp starves the commitment budget.
    const int64_t block_time = 1700000000;
    const uint32_t tip_nbits = 0x1702905c;

    uint256 start_hash{uint256::ONE};
    CBlockIndex chain_start;
    chain_start.nHeight = 800000;
    chain_start.nBits = tip_nbits;
    chain_start.nTime = block_time - 6000;
    chain_start.phashBlock = &start_hash;
    BOOST_CHECK((chain_start.nHeight + 1) % params.DifficultyAdjustmentInterval() != 0);
    params.Blake2bHeight = chain_start.nHeight + 2;

    arith_uint256 shifted;
    shifted.SetCompact(tip_nbits);
    shifted <<= params.Blake2bTargetShift;
    const uint32_t fork_nbits = shifted.GetCompact();

    const uint256 connect_hash{chain_start.GetBlockHeader().GetHash()};

    auto build_chain = [&](uint32_t first_nbits, uint32_t second_nbits) {
        std::vector<CBlockHeader> headers(2);
        headers[0].nVersion = 4;
        headers[0].hashPrevBlock = connect_hash;
        headers[0].nTime = block_time - 1200;
        headers[0].nBits = first_nbits;
        headers[1].nVersion = 4;
        headers[1].hashPrevBlock = headers[0].GetHash();
        headers[1].nTime = block_time - 600;
        headers[1].nBits = second_nbits;
        headers[1].m_header_v2 = true;
        headers[1].m_height = params.Blake2bHeight;
        return headers;
    };

    const arith_uint256 minimum_required_work{UintToArith256(params.nMinimumChainWork)};

    auto presyncs = [&](const std::vector<CBlockHeader>& headers) {
        HeadersSyncState hss(/*id=*/0, params, &chain_start, minimum_required_work);
        const auto result = hss.ProcessNextHeaders(headers, /*full_headers_message=*/true);
        return result.success && hss.GetState() == HeadersSyncState::State::PRESYNC;
    };

    BOOST_CHECK_NE(fork_nbits, tip_nbits);
    BOOST_CHECK(presyncs(build_chain(tip_nbits, fork_nbits)));
    BOOST_CHECK(!presyncs(build_chain(fork_nbits, fork_nbits)));

    arith_uint256 too_easy;
    too_easy.SetCompact(fork_nbits);
    too_easy <<= 4;
    BOOST_CHECK(!presyncs(build_chain(tip_nbits, too_easy.GetCompact())));
}

// The one-time target shift must not be granted again after activation.
BOOST_AUTO_TEST_CASE(headers_sync_powchange_repeated_shift)
{
    const auto mainnet = CreateChainParams(*m_node.args, ChainType::MAIN);
    Consensus::Params params = mainnet->GetConsensus();
    const int64_t block_time = 1700000000;
    const uint32_t tip_nbits = 0x1702905c;

    uint256 start_hash{uint256::ONE};
    CBlockIndex chain_start;
    chain_start.nHeight = 800000;
    chain_start.nBits = tip_nbits;
    chain_start.nTime = block_time - 6000;
    chain_start.phashBlock = &start_hash;
    params.Blake2bHeight = chain_start.nHeight + 1;

    std::vector<CBlockHeader> headers;
    uint256 prev{chain_start.GetBlockHeader().GetHash()};
    uint32_t nbits = tip_nbits;
    for (int i = 0; i < 2; ++i) {
        arith_uint256 target;
        target.SetCompact(nbits);
        target <<= params.Blake2bTargetShift;
        const arith_uint256 limit = UintToArith256(params.powLimit);
        if (target > limit) target = limit;
        nbits = target.GetCompact();

        CBlockHeader header;
        header.nVersion = 4;
        header.hashPrevBlock = prev;
        header.nTime = block_time + i * 600;
        header.nBits = nbits;
        header.m_header_v2 = true;
        header.m_height = chain_start.nHeight + i + 1;
        headers.push_back(header);
        prev = header.GetHash();
    }

    HeadersSyncState hss(0, params, &chain_start, UintToArith256(params.nMinimumChainWork));
    const auto result = hss.ProcessNextHeaders(headers, true);
    BOOST_CHECK(!result.success);
}

BOOST_AUTO_TEST_SUITE_END()
