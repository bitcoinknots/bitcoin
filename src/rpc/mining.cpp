// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chain.h>
#include <chainparams.h>
#include <datum.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <deploymentinfo.h>
#include <deploymentstatus.h>
#include <interfaces/mining.h>
#include <key_io.h>
#include <net.h>
#include <node/context.h>
#include <node/miner.h>
#include <node/warnings.h>
#include <policy/ephemeral_policy.h>
#include <pow.h>
#include <rpc/blockchain.h>
#include <rpc/mining.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <templatediversity.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/check.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <memory>
#include <stdint.h>

using interfaces::BlockRef;
using interfaces::BlockTemplate;
using interfaces::Mining;
using node::BlockAssembler;
using node::DatumTracker;
using node::GetMinimumTime;
using node::NodeContext;
using node::RegenerateCommitments;
using node::StripDatumPort;
using node::UpdateTime;
using util::ToString;

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is -1.
 * If 'height' is -1, compute the estimate from current chain tip.
 * If 'height' is a valid block height, compute the estimate at the time when a given block was found.
 */
static UniValue GetNetworkHashPS(int lookup, int height, const CChain& active_chain) {
    if (lookup < -1 || lookup == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid nblocks. Must be a positive number or -1.");
    }

    if (height < -1 || height > active_chain.Height()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block does not exist at specified height");
    }

    const CBlockIndex* pb = active_chain.Tip();

    if (height >= 0) {
        pb = active_chain[height];
    }

    if (pb == nullptr || !pb->nHeight)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup == -1)
        lookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    const CBlockIndex* pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;

    return workDiff.getdouble() / timeDiff;
}

static RPCHelpMan getnetworkhashps()
{
    return RPCHelpMan{"getnetworkhashps",
                "\nReturns the estimated network hashes per second based on the last n blocks.\n"
                "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
                "Pass in [height] to estimate the network speed at the time when a certain block was found.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::Default{120}, "The number of previous blocks to calculate estimate from, or -1 for blocks since last difficulty change."},
                    {"height", RPCArg::Type::NUM, RPCArg::Default{-1}, "To estimate at the time of the given height."},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "Hashes per second estimated"},
                RPCExamples{
                    HelpExampleCli("getnetworkhashps", "")
            + HelpExampleRpc("getnetworkhashps", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return GetNetworkHashPS(self.Arg<int>("nblocks"), self.Arg<int>("height"), chainman.ActiveChain());
},
    };
}

static bool GenerateBlock(ChainstateManager& chainman, CBlock&& block, uint64_t& max_tries, std::shared_ptr<const CBlock>& block_out, bool process_new_block)
{
    block_out.reset();
    block.hashMerkleRoot = BlockMerkleRoot(block);

    while (max_tries > 0 && block.nNonce < std::numeric_limits<uint32_t>::max() && !CheckProofOfWork(block.GetHash(), block.nBits, chainman.GetConsensus()) && !chainman.m_interrupt) {
        ++block.nNonce;
        --max_tries;
    }
    if (max_tries == 0 || chainman.m_interrupt) {
        return false;
    }
    if (block.nNonce == std::numeric_limits<uint32_t>::max()) {
        return true;
    }

    block_out = std::make_shared<const CBlock>(std::move(block));

    if (!process_new_block) return true;

    if (!chainman.ProcessNewBlock(block_out, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
    }

    return true;
}

static UniValue generateBlocks(ChainstateManager& chainman, Mining& miner, const CScript& coinbase_output_script, int nGenerate, uint64_t nMaxTries)
{
    UniValue blockHashes(UniValue::VARR);
    while (nGenerate > 0 && !chainman.m_interrupt) {
        std::unique_ptr<BlockTemplate> block_template(miner.createNewBlock({ .coinbase_output_script = coinbase_output_script }));
        CHECK_NONFATAL(block_template);

        std::shared_ptr<const CBlock> block_out;
        if (!GenerateBlock(chainman, CBlock{block_template->getBlock()}, nMaxTries, block_out, /*process_new_block=*/true)) {
            break;
        }

        if (block_out) {
            --nGenerate;
            blockHashes.push_back(block_out->GetHash().GetHex());
        }
    }
    return blockHashes;
}

static bool getScriptFromDescriptor(const std::string& descriptor, CScript& script, std::string& error)
{
    FlatSigningProvider key_provider;
    const auto descs = Parse(descriptor, key_provider, error, /* require_checksum = */ false);
    if (descs.empty()) return false;
    if (descs.size() > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Multipath descriptor not accepted");
    }
    const auto& desc = descs.at(0);
    if (desc->IsRange()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?");
    }

    FlatSigningProvider provider;
    std::vector<CScript> scripts;
    if (!desc->Expand(0, key_provider, scripts, provider)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot derive script without private keys");
    }

    // Combo descriptors can have 2 or 4 scripts, so we can't just check scripts.size() == 1
    CHECK_NONFATAL(scripts.size() > 0 && scripts.size() <= 4);

    if (scripts.size() == 1) {
        script = scripts.at(0);
    } else if (scripts.size() == 4) {
        // For uncompressed keys, take the 3rd script, since it is p2wpkh
        script = scripts.at(2);
    } else {
        // Else take the 2nd script, since it is p2pkh
        script = scripts.at(1);
    }

    return true;
}

static RPCHelpMan generatetodescriptor()
{
    return RPCHelpMan{
        "generatetodescriptor",
        "Mine to a specified descriptor and return the block hashes.",
        {
            {"num_blocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated."},
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor to send the newly generated bitcoin to."},
            {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES}, "How many iterations to try."},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "hashes of blocks generated",
            {
                {RPCResult::Type::STR_HEX, "", "blockhash"},
            }
        },
        RPCExamples{
            "\nGenerate 11 blocks to mydesc\n" + HelpExampleCli("generatetodescriptor", "11 \"mydesc\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto num_blocks{self.Arg<int>("num_blocks")};
    const auto max_tries{self.Arg<uint64_t>("maxtries")};

    CScript coinbase_output_script;
    std::string error;
    if (!getScriptFromDescriptor(self.Arg<std::string>("descriptor"), coinbase_output_script, error)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);
    ChainstateManager& chainman = EnsureChainman(node);

    return generateBlocks(chainman, miner, coinbase_output_script, num_blocks, max_tries);
},
    };
}

static RPCHelpMan generate()
{
    return RPCHelpMan{"generate", "has been replaced by the -generate cli option. Refer to -help for more information.", {}, {}, RPCExamples{""}, [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, self.ToString());
    }};
}

static RPCHelpMan generatetoaddress()
{
    return RPCHelpMan{"generatetoaddress",
        "Mine to a specified address and return the block hashes.",
         {
             {"nblocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated."},
             {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to send the newly generated bitcoin to."},
             {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES}, "How many iterations to try."},
         },
         RPCResult{
             RPCResult::Type::ARR, "", "hashes of blocks generated",
             {
                 {RPCResult::Type::STR_HEX, "", "blockhash"},
             }},
         RPCExamples{
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
            + "If you are using the " CLIENT_NAME " wallet, you can get a new address to send the newly generated bitcoin to with:\n"
            + HelpExampleCli("getnewaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int num_blocks{request.params[0].getInt<int>()};
    const uint64_t max_tries{request.params[2].isNull() ? DEFAULT_MAX_TRIES : request.params[2].getInt<int>()};

    CTxDestination destination = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);
    ChainstateManager& chainman = EnsureChainman(node);

    CScript coinbase_output_script = GetScriptForDestination(destination);

    return generateBlocks(chainman, miner, coinbase_output_script, num_blocks, max_tries);
},
    };
}

static RPCHelpMan generateblock()
{
    return RPCHelpMan{"generateblock",
        "Mine a set of ordered transactions to a specified address or descriptor and return the block hash.",
        {
            {"output", RPCArg::Type::STR, RPCArg::Optional::NO, "The address or descriptor to send the newly generated bitcoin to."},
            {"transactions", RPCArg::Type::ARR, RPCArg::Optional::NO, "An array of hex strings which are either txids or raw transactions.\n"
                "Txids must reference transactions currently in the mempool.\n"
                "All transactions must be valid and in valid order, otherwise the block will be rejected.",
                {
                    {"rawtx/txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""},
                },
            },
            {"submit", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to submit the block before the RPC call returns or to return it as hex."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hash", "hash of generated block"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "hex of generated block, only present when submit=false"},
            }
        },
        RPCExamples{
            "\nGenerate a block to myaddress, with txs rawtx and mempool_txid\n"
            + HelpExampleCli("generateblock", R"("myaddress" '["rawtx", "mempool_txid"]')")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto address_or_descriptor = request.params[0].get_str();
    CScript coinbase_output_script;
    std::string error;

    if (!getScriptFromDescriptor(address_or_descriptor, coinbase_output_script, error)) {
        const auto destination = DecodeDestination(address_or_descriptor);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address or descriptor");
        }

        coinbase_output_script = GetScriptForDestination(destination);
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);
    const CTxMemPool& mempool = EnsureMemPool(node);

    std::vector<CTransactionRef> txs;
    const auto raw_txs_or_txids = request.params[1].get_array();
    for (size_t i = 0; i < raw_txs_or_txids.size(); i++) {
        const auto& str{raw_txs_or_txids[i].get_str()};

        CMutableTransaction mtx;
        if (auto hash{uint256::FromHex(str)}) {
            const auto tx{mempool.get(*hash)};
            if (!tx) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Transaction %s not in mempool.", str));
            }

            txs.emplace_back(tx);

        } else if (DecodeHexTx(mtx, str)) {
            txs.push_back(MakeTransactionRef(std::move(mtx)));

        } else {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Transaction decode failed for %s. Make sure the tx has at least one input.", str));
        }
    }

    const bool process_new_block{request.params[2].isNull() ? true : request.params[2].get_bool()};
    CBlock block;

    ChainstateManager& chainman = EnsureChainman(node);
    {
        LOCK(chainman.GetMutex());
        {
            std::unique_ptr<BlockTemplate> block_template{miner.createNewBlock({.use_mempool = false, .coinbase_output_script = coinbase_output_script})};
            CHECK_NONFATAL(block_template);

            block = block_template->getBlock();
        }

        CHECK_NONFATAL(block.vtx.size() == 1);

        // Add transactions
        block.vtx.insert(block.vtx.end(), txs.begin(), txs.end());
        RegenerateCommitments(block, chainman);

        BlockValidationState state;
        if (!TestBlockValidity(state, chainman.GetParams(), chainman.ActiveChainstate(), block, chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false)) {
            throw JSONRPCError(RPC_VERIFY_ERROR, strprintf("TestBlockValidity failed: %s", state.ToString()));
        }
    }

    std::shared_ptr<const CBlock> block_out;
    uint64_t max_tries{DEFAULT_MAX_TRIES};

    if (!GenerateBlock(chainman, std::move(block), max_tries, block_out, process_new_block) || !block_out) {
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to make block.");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("hash", block_out->GetHash().GetHex());
    if (!process_new_block) {
        DataStream block_ser;
        block_ser << TX_WITH_WITNESS(*block_out);
        obj.pushKV("hex", HexStr(block_ser));
    }
    return obj;
},
    };
}

static RPCHelpMan getmininginfo()
{
    return RPCHelpMan{"getmininginfo",
                "\nReturns a json object containing mining-related information.",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "blocks", "The current block"},
                        {RPCResult::Type::NUM, "currentblocksize", /*optional=*/true, "The block size (including reserved weight for block header, txs count and coinbase tx) of the last assembled block (only present if a block was ever assembled, and blockmaxsize is configured)"},
                        {RPCResult::Type::NUM, "currentblockweight", /*optional=*/true, "The block weight (including reserved weight for block header, txs count and coinbase tx) of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "currentblocktx", /*optional=*/true, "The number of block transactions (excluding coinbase) of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::STR_HEX, "bits", "The current nBits, compact representation of the block difficulty target"},
                        {RPCResult::Type::NUM, "difficulty", /*optional=*/true, "The proof-of-work difficulty as a multiple of the minimum difficulty (only for SHA256d blocks)"},
                        {RPCResult::Type::NUM, "difficulty_blake2b", /*optional=*/true, "The expected average number of BLAKE2b hashes needed to find the tip block (only for header-v2 blocks)"},
                        {RPCResult::Type::STR_HEX, "target", "The current target"},
                        {RPCResult::Type::NUM, "networkhashps", "The network hashes per second"},
                        {RPCResult::Type::NUM, "pooledtx", "The size of the mempool"},
                        {RPCResult::Type::STR, "chain", "current network name (" LIST_CHAIN_NAMES ")"},
                        {RPCResult::Type::STR_HEX, "signet_challenge", /*optional=*/true, "The block challenge (aka. block script), in hexadecimal (only present if the current network is a signet)"},
                        {RPCResult::Type::OBJ, "next", "The next block",
                        {
                            {RPCResult::Type::NUM, "height", "The next height"},
                            {RPCResult::Type::STR_HEX, "bits", "The next target nBits"},
                            {RPCResult::Type::NUM, "difficulty", /*optional=*/true, "The proof-of-work difficulty as a multiple of the minimum difficulty (only for SHA256d blocks)"},
                            {RPCResult::Type::NUM, "difficulty_blake2b", /*optional=*/true, "The expected average number of BLAKE2b hashes needed to find the next block (only for header-v2 blocks)"},
                            {RPCResult::Type::STR_HEX, "target", "The next target"}
                        }},
                        (IsDeprecatedRPCEnabled("warnings") ?
                            RPCResult{RPCResult::Type::STR, "warnings", "any network and blockchain warnings (DEPRECATED)"} :
                            RPCResult{RPCResult::Type::ARR, "warnings", "any network and blockchain warnings (run with `-deprecatedrpc=warnings` to return the latest warning as a single string)",
                            {
                                {RPCResult::Type::STR, "", "warning"},
                            }
                            }
                        ),
                    }},
                RPCExamples{
                    HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CTxMemPool& mempool = EnsureMemPool(node);
    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();
    CBlockIndex& tip{*CHECK_NONFATAL(active_chain.Tip())};

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("blocks",           active_chain.Height());
    if (BlockAssembler::m_last_block_size) obj.pushKV("currentblocksize", *BlockAssembler::m_last_block_size);
    if (BlockAssembler::m_last_block_weight) obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
    if (BlockAssembler::m_last_block_num_txs) obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);
    obj.pushKV("bits", strprintf("%08x", tip.nBits));
    PushDifficulty(obj, tip);
    obj.pushKV("target", GetTarget(tip, chainman.GetConsensus().powLimit).GetHex());
    obj.pushKV("networkhashps",    getnetworkhashps().HandleRequest(request));
    obj.pushKV("pooledtx",         (uint64_t)mempool.size());
    obj.pushKV("chain", chainman.GetParams().GetChainTypeString());

    UniValue next(UniValue::VOBJ);
    CBlockIndex next_index;
    NextEmptyBlockIndex(tip, chainman.GetConsensus(), next_index);

    next.pushKV("height", next_index.nHeight);
    next.pushKV("bits", strprintf("%08x", next_index.nBits));
    PushDifficulty(next, next_index);
    next.pushKV("target", GetTarget(next_index, chainman.GetConsensus().powLimit).GetHex());
    obj.pushKV("next", next);

    if (chainman.GetParams().GetChainType() == ChainType::SIGNET) {
        const std::vector<uint8_t>& signet_challenge =
            chainman.GetConsensus().signet_challenge;
        obj.pushKV("signet_challenge", HexStr(signet_challenge));
    }
    obj.pushKV("warnings", node::GetWarningsForRpc(*CHECK_NONFATAL(node.warnings), IsDeprecatedRPCEnabled("warnings")));
    return obj;
},
    };
}


// NOTE: Unlike wallet RPC (which use BTC values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
static RPCHelpMan prioritisetransaction()
{
    return RPCHelpMan{"prioritisetransaction",
                "Accepts the transaction into mined blocks at a higher (or lower) priority\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id."},
                    {"priority_delta", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The priority to add or subtract.\n"
            "                  The transaction selection algorithm considers the tx as it would have a higher priority.\n"
            "                  (priority of a transaction is calculated: coinage * value_in_satoshis / txsize)\n"},
                    {"fee_delta", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  Note, that this value is not a fee rate. It is a value to modify absolute fee of the TX.\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Returns true"},
                RPCExamples{
                    HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000")
            + HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);

    uint256 hash(ParseHashV(request.params[0], "txid"));
    double priority_delta = 0;
    CAmount nAmount = 0;

    if (!request.params[1].isNull()) {
        priority_delta = request.params[1].get_real();
    }
    if (!request.params[2].isNull()) {
        nAmount = request.params[2].getInt<int64_t>();
    }

    CTxMemPool& mempool = EnsureAnyMemPool(request.context);

    // Non-0 fee dust transactions are not allowed for entry, and modification not allowed afterwards
    const auto& tx = mempool.get(hash);
    if (mempool.m_opts.require_standard && tx && !GetDust(*tx, mempool.m_opts.dust_relay_feerate).empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Priority is not supported for transactions with dust outputs.");
    }

    mempool.PrioritiseTransaction(hash, priority_delta, nAmount);
    return true;
},
    };
}

static RPCHelpMan getprioritisedtransactions()
{
    return RPCHelpMan{"getprioritisedtransactions",
        "Returns a map of all user-created (see prioritisetransaction) fee deltas by txid, and whether the tx is present in mempool.",
        {},
        RPCResult{
            RPCResult::Type::OBJ_DYN, "", "prioritisation keyed by txid",
            {
                {RPCResult::Type::OBJ, "<transactionid>", "", {
                    {RPCResult::Type::NUM, "fee_delta", "transaction fee delta in satoshis"},
                    {RPCResult::Type::BOOL, "in_mempool", "whether this transaction is currently in mempool"},
                    {RPCResult::Type::NUM, "modified_fee", /*optional=*/true, "modified fee in satoshis. Only returned if in_mempool=true"},
                    {RPCResult::Type::NUM, "priority_delta", /*optional=*/true, "transaction coin-age priority delta"},
                }}
            },
        },
        RPCExamples{
            HelpExampleCli("getprioritisedtransactions", "")
            + HelpExampleRpc("getprioritisedtransactions", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            NodeContext& node = EnsureAnyNodeContext(request.context);
            CTxMemPool& mempool = EnsureMemPool(node);
            UniValue rpc_result{UniValue::VOBJ};
            for (const auto& delta_info : mempool.GetPrioritisedTransactions()) {
                UniValue result_inner{UniValue::VOBJ};
                result_inner.pushKV("fee_delta", delta_info.delta);
                result_inner.pushKV("in_mempool", delta_info.in_mempool);
                if (delta_info.in_mempool) {
                    result_inner.pushKV("modified_fee", *delta_info.modified_fee);
                }
                result_inner.pushKV("priority_delta", delta_info.priority_delta);
                rpc_result.pushKV(delta_info.txid.GetHex(), std::move(result_inner));
            }
            return rpc_result;
        },
    };
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const BlockValidationState& state)
{
    if (state.IsValid())
        return UniValue::VNULL;

    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    if (state.IsInvalid())
    {
        std::string strRejectReason = state.GetRejectReason();
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

static std::string gbt_vb_name(const Consensus::DeploymentPos pos) {
    const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
    std::string s = vbinfo.name;
    if (!vbinfo.gbt_force) {
        s.insert(s.begin(), '!');
    }
    return s;
}

static UniValue TemplateToJSON(const Consensus::Params&, const ChainstateManager&, const BlockTemplate*, const CBlockIndex*, const std::set<std::string>& setClientRules, unsigned int nTransactionsUpdatedLast);

static RPCHelpMan getblocktemplate()
{
    return RPCHelpMan{"getblocktemplate",
        "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
        "It returns data needed to construct a block to work on.\n"
        "For full specification, see BIPs 22, 23, 9, and 145:\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki#getblocktemplate_changes\n"
        "    https://github.com/bitcoin/bips/blob/master/bip-0145.mediawiki\n",
        {
            {"template_request", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Format of the template",
            {
                {"mode", RPCArg::Type::STR, /* treat as named arg */ RPCArg::Optional::OMITTED, "This must be set to \"template\", \"proposal\" (see BIP 23), or omitted"},
                {"blockmaxsize", RPCArg::Type::NUM, RPCArg::DefaultHint{"set by -blockmaxsize"}, "limit returned block to specified size (disables template cache)"},
                {"blockmaxweight", RPCArg::Type::NUM, RPCArg::DefaultHint{"set by -blockmaxweight"}, "limit returned block to specified weight (disables template cache)"},
                {"blockreservedsigops", RPCArg::Type::NUM, RPCArg::Default{node::BlockCreateOptions{}.coinbase_output_max_additional_sigops}, "reserve specified number of sigops in returned block for generation transaction (disables template cache)"},
                {"blockreservedsize", RPCArg::Type::NUM, RPCArg::Default{node::BlockCreateOptions{}.block_reserved_size}, "reserve specified size in returned block for generation transaction (disables template cache)"},
                {"blockreservedweight", RPCArg::Type::NUM, RPCArg::Default{node::BlockCreateOptions{}.block_reserved_weight}, "reserve specified weight in returned block for generation transaction (disables template cache)"},
                {"capabilities", RPCArg::Type::ARR, /* treat as named arg */ RPCArg::Optional::OMITTED, "A list of strings",
                {
                    {"str", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "client side supported feature, 'longpoll', 'coinbasevalue', 'proposal', 'skip_validity_test', 'serverlist', 'workid'"},
                }},
                {"rules", RPCArg::Type::ARR, RPCArg::Optional::NO, "A list of strings",
                {
                    {"segwit", RPCArg::Type::STR, RPCArg::Optional::NO, "(literal) indicates client side segwit support"},
                    {"blake2b", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "(literal) indicates client side BLAKE2b header support"},
                    {"str", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "other client side supported softfork deployment"},
                }},
                {"longpollid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "delay processing request until the result would vary significantly from the \"longpollid\" of a prior template"},
                {"minfeerate", RPCArg::Type::NUM, RPCArg::DefaultHint{"set by -blockmintxfee"}, "only include transactions with a minimum sats/vbyte (disables template cache)"},
                {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "proposed block data to check, encoded in hexadecimal; valid only for mode=\"proposal\""},
            },
            },
        },
        {
            RPCResult{"If the proposal was accepted with mode=='proposal'", RPCResult::Type::NONE, "", ""},
            RPCResult{"If the proposal was not accepted with mode=='proposal'", RPCResult::Type::STR, "", "According to BIP22"},
            RPCResult{"Otherwise", RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "version", "The preferred block version"},
                {RPCResult::Type::ARR, "rules", "specific block rules that are to be enforced",
                {
                    {RPCResult::Type::STR, "", "name of a rule the client must understand to some extent; see BIP 9 for format"},
                }},
                {RPCResult::Type::OBJ_DYN, "vbavailable", "set of pending, supported versionbit (BIP 9) softfork deployments",
                {
                    {RPCResult::Type::NUM, "rulename", "identifies the bit number as indicating acceptance and readiness for the named softfork rule"},
                }},
                {RPCResult::Type::ARR, "capabilities", "",
                {
                    {RPCResult::Type::STR, "value", "A supported feature, for example 'proposal'"},
                }},
                {RPCResult::Type::NUM, "vbrequired", "bit mask of versionbits the server requires set in submissions"},
                {RPCResult::Type::STR, "previousblockhash", "The hash of current highest block"},
                {RPCResult::Type::ARR, "transactions", "contents of non-coinbase transactions that should be included in the next block",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "data", "transaction data encoded in hexadecimal (byte-for-byte)"},
                        {RPCResult::Type::STR_HEX, "txid", "transaction hash excluding witness data, shown in byte-reversed hex"},
                        {RPCResult::Type::STR_HEX, "hash", "transaction hash including witness data, shown in byte-reversed hex"},
                        {RPCResult::Type::ARR, "depends", "array of numbers",
                        {
                            {RPCResult::Type::NUM, "", "transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is"},
                        }},
                        {RPCResult::Type::NUM, "fee", "difference in value between transaction inputs and outputs (in satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one"},
                        {RPCResult::Type::NUM, "priority", /*optional=*/true, "transaction coin-age priority (non-standard)"},
                        {RPCResult::Type::NUM, "sigops", "total SigOps cost, as counted for purposes of block limits; if key is not present, sigop cost is unknown and clients MUST NOT assume it is zero"},
                        {RPCResult::Type::NUM, "weight", "total transaction weight, as counted for purposes of block limits"},
                    }},
                }},
                {RPCResult::Type::OBJ_DYN, "coinbaseaux", "data that should be included in the coinbase's scriptSig content",
                {
                    {RPCResult::Type::STR_HEX, "key", "values must be in the coinbase (keys may be ignored)"},
                }},
                {RPCResult::Type::NUM, "coinbasevalue", "maximum allowable input to coinbase transaction, including the generation award and transaction fees (in satoshis)"},
                {RPCResult::Type::STR, "longpollid", "an id to include with a request to longpoll on an update to this template"},
                {RPCResult::Type::STR, "target", "The hash target"},
                {RPCResult::Type::NUM_TIME, "mintime", "The minimum timestamp appropriate for the next block time, expressed in " + UNIX_EPOCH_TIME + ". Adjusted for the proposed BIP94 timewarp rule."},
                {RPCResult::Type::ARR, "mutable", "list of ways the block template may be changed",
                {
                    {RPCResult::Type::STR, "value", "A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'"},
                }},
                {RPCResult::Type::STR_HEX, "noncerange", "A range of valid nonces"},
                {RPCResult::Type::NUM, "sigoplimit", "limit of sigops in blocks"},
                {RPCResult::Type::NUM, "sizelimit", "limit of block size"},
                {RPCResult::Type::NUM, "weightlimit", /*optional=*/true, "limit of block weight"},
                {RPCResult::Type::NUM_TIME, "curtime", "current timestamp in " + UNIX_EPOCH_TIME + ". Adjusted for the proposed BIP94 timewarp rule."},
                {RPCResult::Type::STR, "bits", "compressed target of next block"},
                {RPCResult::Type::NUM, "height", "The height of the next block"},
                {RPCResult::Type::STR_HEX, "signet_challenge", /*optional=*/true, "Only on signet"},
                {RPCResult::Type::STR_HEX, "default_witness_commitment", /*optional=*/true, "a valid witness commitment for the unmodified block template"},
            }},
        },
        RPCExamples{
                    HelpExampleCli("getblocktemplate", "'{\"rules\": [\"segwit\"]}'")
            + HelpExampleRpc("getblocktemplate", "{\"rules\": [\"segwit\"]}")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    Mining& miner = EnsureMining(node);

    // Proof of Datum: refuse to hand out a template to a connection this node
    // has flagged, heuristically or by hand. This withholds a voluntary
    // service only; it has no bearing on whether any block is valid. See
    // src/datum.h.
    const std::string datum_addr{StripDatumPort(request.peerAddr)};
    if (!datum_addr.empty()) {
        DatumTracker& datum{EnsureAnyDatumTracker(request.context)};
        if (const auto ban{datum.IsBanned(datum_addr)}) {
            throw JSONRPCError(RPC_MISC_ERROR,
                strprintf("This connection is on this node's Proof of Datum list and will not be served a "
                         "block template: %s", ban->reason));
        }
        datum.RecordTemplateRequest(datum_addr);
    }

    LOCK(cs_main);
    uint256 tip{CHECK_NONFATAL(miner.getTip()).value().hash};

    BlockAssembler::Options options;
    {
        const ArgsManager& args{EnsureAnyArgsman(request.context)};
        ApplyArgsManOptions(args, options);
    }
    const BlockAssembler::Options options_def{options.Clamped()};
    bool bypass_cache{false};

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    std::set<std::string> setClientRules;
    if (!request.params[0].isNull())
    {
        const UniValue& oparam = request.params[0].get_obj();
        const UniValue& modeval = oparam.find_value("mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = oparam.find_value("longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = oparam.find_value("data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
            if (pindex) {
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            }

            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != tip) {
                return "inconclusive-not-best-prevblk";
            }
            BlockValidationState state;
            TestBlockValidity(state, chainman.GetParams(), chainman.ActiveChainstate(), block, chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true);
            return BIP22ValidationResult(state);
        }

        const UniValue& aClientRules = oparam.find_value("rules");
        if (aClientRules.isArray()) {
            for (unsigned int i = 0; i < aClientRules.size(); ++i) {
                const UniValue& v = aClientRules[i];
                setClientRules.insert(v.get_str());
            }
        }

        if (!oparam["blockmaxsize"].isNull()) {
            options.nBlockMaxSize = oparam["blockmaxsize"].getInt<size_t>();
        }
        if (!oparam["blockmaxweight"].isNull()) {
            options.nBlockMaxWeight = oparam["blockmaxweight"].getInt<size_t>();
        }
        if (!oparam["blockreservedsize"].isNull()) {
            options.block_reserved_size = oparam["blockreservedsize"].getInt<size_t>();
        }
        if (!oparam["blockreservedweight"].isNull()) {
            options.block_reserved_weight = oparam["blockreservedweight"].getInt<size_t>();
        }
        if (!oparam["blockreservedsigops"].isNull()) {
            options.coinbase_output_max_additional_sigops = oparam["blockreservedsigops"].getInt<size_t>();
        }
        if (!oparam["minfeerate"].isNull()) {
            options.blockMinFeeRate = CFeeRate{AmountFromValue(oparam["minfeerate"]), COIN /* sat/vB */};
        }
        options = options.Clamped();
        bypass_cache |= !(options == options_def);

        // NOTE: Intentionally not setting bypass_cache for skip_validity_test since _using_ the cache is fine
        const UniValue& client_caps = oparam.find_value("capabilities");
        if (client_caps.isArray()) {
            for (unsigned int i = 0; i < client_caps.size(); ++i) {
                const UniValue& v = client_caps[i];
                if (!v.isStr()) continue;
                if (v.get_str() == "skip_validity_test") {
                    options.test_block_validity = false;
                }
            }
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if (!miner.isTestChain()) {
        const CConnman& connman = EnsureConnman(node);
        if (connman.GetNodeCount(ConnectionDirection::Both) == 0) {
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, CLIENT_NAME " is not connected!");
        }

        if (miner.isInitialBlockDownload()) {
            throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, CLIENT_NAME " is in initial sync and waiting for blocks...");
        }
    }

    static unsigned int nTransactionsUpdatedLast;
    const CTxMemPool& mempool = EnsureMemPool(node);

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            const std::string& lpstr = lpval.get_str();

            hashWatchedChain = ParseHashV(lpstr.substr(0, 64), "longpollid");
            nTransactionsUpdatedLastLP = LocaleIndependentAtoi<int64_t>(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = tip;
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            MillisecondsDouble checktxtime{std::chrono::minutes(1)};
            while (tip == hashWatchedChain && IsRPCRunning()) {
                std::optional<BlockRef> maybe_tip{miner.waitTipChanged(hashWatchedChain, checktxtime)};
                // Node is shutting down
                if (!maybe_tip) break;
                tip = maybe_tip->hash;
                // Timeout: Check transactions for update
                // without holding the mempool lock to avoid deadlocks
                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                    break;
                checktxtime = std::chrono::seconds(10);
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        tip = CHECK_NONFATAL(miner.getTip()).value().hash;

        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    const Consensus::Params& consensusParams = chainman.GetParams().GetConsensus();

    // GBT must be called with 'signet' set in the rules for signet chains
    if (consensusParams.signet_blocks && setClientRules.count("signet") != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the signet rule set (call with {\"rules\": [\"segwit\", \"signet\"]})");
    }

    // GBT must be called with 'segwit' set in the rules
    if (setClientRules.count("segwit") != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})");
    }

    // Update block
    static CBlockIndex* pindexPrev;
    static int64_t time_start;
    static std::unique_ptr<BlockTemplate> block_template;
    if (!pindexPrev || pindexPrev->GetBlockHash() != tip ||
        bypass_cache ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - time_start > 5))
    {
        if (bypass_cache || !options.test_block_validity) {
            // Create one-off template unrelated to cache
            const auto tx_update_counter = mempool.GetTransactionsUpdated();
            CBlockIndex* const local_pindexPrev = chainman.m_blockman.LookupBlockIndex(tip);
            auto tmpl = miner.createNewBlock2(options);
            CHECK_NONFATAL(tmpl);
            return TemplateToJSON(consensusParams, chainman, &*tmpl, local_pindexPrev, setClientRules, tx_update_counter);
        }
        CHECK_NONFATAL(options == options_def);

        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = nullptr;

        // Store the pindexBest used before createNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = chainman.m_blockman.LookupBlockIndex(tip);
        time_start = GetTime();

        // Create new block
        block_template = miner.createNewBlock();
        CHECK_NONFATAL(block_template);


        // Need to update only after we know createNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }
    CHECK_NONFATAL(pindexPrev);

    return TemplateToJSON(consensusParams, chainman, &*block_template, pindexPrev, setClientRules, nTransactionsUpdatedLast);
},
    };
}

static UniValue TemplateToJSON(const Consensus::Params& consensusParams, const ChainstateManager& chainman, const BlockTemplate* block_template, const CBlockIndex* const pindexPrev, const std::set<std::string>& setClientRules, const unsigned int nTransactionsUpdatedLast) {
    CHECK_NONFATAL(block_template);
    const CBlock& block = block_template->getBlock();

    // NOTE: If at some point we support pre-segwit miners post-segwit-activation, this needs to take segwit support into consideration
    const bool fPreSegWit = !DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_SEGWIT);

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    std::map<uint256, int64_t> setTxIndex;
    const std::vector<CAmount>& tx_fees{block_template->getTxFees()};
    const std::vector<CAmount>& tx_sigops{block_template->getTxSigops()};
    const std::vector<double>& tx_coin_age_priorities{block_template->getTxCoinAgePriorities()};

    int i = 0;
    for (const auto& it : block.vtx) {
        const CTransaction& tx = *it;
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase())
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.pushKV("data", EncodeHexTx(tx));
        entry.pushKV("txid", txHash.GetHex());
        entry.pushKV("hash", tx.GetWitnessHash().GetHex());

        UniValue deps(UniValue::VARR);
        for (const CTxIn &in : tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.pushKV("depends", std::move(deps));

        int index_in_template = i - 1;
        entry.pushKV("fee", tx_fees.at(index_in_template));
        int64_t nTxSigOps{tx_sigops.at(index_in_template)};
        if (fPreSegWit) {
            CHECK_NONFATAL(nTxSigOps % WITNESS_SCALE_FACTOR == 0);
            nTxSigOps /= WITNESS_SCALE_FACTOR;
        }
        entry.pushKV("sigops", nTxSigOps);
        entry.pushKV("weight", GetTransactionWeight(tx));
        if (index_in_template && !tx_coin_age_priorities.empty()) {
            entry.pushKV("priority", tx_coin_age_priorities.at(index_in_template));
        }

        transactions.push_back(std::move(entry));
    }

    UniValue aux(UniValue::VOBJ);

    CBlockHeader block_header{block};
    // Update nTime (and potentially nBits)
    UpdateTime(&block_header, consensusParams, pindexPrev);
    block_header.nNonce = 0;

    if (IsThisSoftwareExpired(block_header.nTime)) {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "node software has expired");
    }

    arith_uint256 hashTarget = arith_uint256().SetCompact(block_header.nBits);

    UniValue aMutable(UniValue::VARR);
    aMutable.push_back("time");
    aMutable.push_back("transactions");
    aMutable.push_back("prevblock");

    UniValue result(UniValue::VOBJ);
    result.pushKV("capabilities", std::move(aCaps));

    UniValue aRules(UniValue::VARR);
    aRules.push_back("csv");
    if (!fPreSegWit) aRules.push_back("!segwit");
    if (consensusParams.signet_blocks) {
        // indicate to miner that they must understand signet rules
        // when attempting to mine with this template
        aRules.push_back("!signet");
    }
    if (block.m_header_v2) {
        aRules.push_back("!blake2b");
        if (!setClientRules.count("blake2b")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Support for 'blake2b' rule requires explicit client support");
        }
    }

    UniValue vbavailable(UniValue::VOBJ);
    uint32_t vbrequired = 0;
    for (int j = 0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
        Consensus::DeploymentPos pos = Consensus::DeploymentPos(j);
        ThresholdState state = chainman.m_versionbitscache.State(pindexPrev, consensusParams, pos);
        switch (state) {
            case ThresholdState::DEFINED:
            case ThresholdState::FAILED:
            case ThresholdState::EXPIRED:
                // Not exposed to GBT at all
                break;
            case ThresholdState::LOCKED_IN:
                // Ensure bit is set in block version
                block_header.nVersion |= chainman.m_versionbitscache.Mask(consensusParams, pos);
                [[fallthrough]];
            case ThresholdState::STARTED:
            {
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                vbavailable.pushKV(gbt_vb_name(pos), consensusParams.vDeployments[pos].bit);
                if (DeploymentMustSignalAfter(pindexPrev, consensusParams, pos, state)) {
                    vbrequired |= chainman.m_versionbitscache.Mask(consensusParams, pos);
                }
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    if (!vbinfo.gbt_force) {
                        // If the client doesn't support this, don't indicate it in the [default] version
                        block_header.nVersion &= ~chainman.m_versionbitscache.Mask(consensusParams, pos);
                    }
                }
                break;
            }
            case ThresholdState::ACTIVE:
            {
                // Add to rules only
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                aRules.push_back(gbt_vb_name(pos));
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    // Not supported by the client; make sure it's safe to proceed
                    if (!vbinfo.gbt_force) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Support for '%s' rule requires explicit client support", vbinfo.name));
                    }
                }
                break;
            }
        }
    }
    // RDTS (now a flag-day deployment; no signalling surface remains). When
    // RDTS is active for the template's block, the rules were enforced
    // during transaction selection: advertise
    // "reduced_data" unprefixed, as before the deployment's removal
    // (gbt_force semantics: clients need no special support, there is no
    // client-side block construction involved).
    const bool rdts_active{pindexPrev != nullptr &&
        consensusParams.RdtsActiveAt(pindexPrev->nHeight + 1, pindexPrev->GetMedianTimePast())};
    if (rdts_active) {
        aRules.push_back("reduced_data");
    }
    if (pindexPrev != nullptr && consensusParams.CoinbaseMaturityLongActiveAt(pindexPrev->nHeight + 1)) {
        aRules.push_back("long_coinbase_maturity");
    }

    result.pushKV("version", block_header.GetCompleteVersion());
    result.pushKV("rules", std::move(aRules));
    result.pushKV("vbavailable", std::move(vbavailable));
    result.pushKV("vbrequired", vbrequired);

    result.pushKV("previousblockhash", block.hashPrevBlock.GetHex());
    result.pushKV("transactions", std::move(transactions));
    result.pushKV("coinbaseaux", std::move(aux));
    result.pushKV("coinbasevalue", (int64_t)block.vtx[0]->vout[0].nValue);
    result.pushKV("longpollid", pindexPrev->GetBlockHash().GetHex() + ToString(nTransactionsUpdatedLast));
    result.pushKV("target", hashTarget.GetHex());
    result.pushKV("mintime", GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()));
    result.pushKV("mutable", std::move(aMutable));
    result.pushKV("noncerange", "00000000ffffffff");
    int64_t nSigOpLimit = MAX_BLOCK_SIGOPS_COST;
    int64_t nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE;
    if (fPreSegWit) {
        CHECK_NONFATAL(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
        nSigOpLimit /= WITNESS_SCALE_FACTOR;
        CHECK_NONFATAL(nSizeLimit % WITNESS_SCALE_FACTOR == 0);
        nSizeLimit /= WITNESS_SCALE_FACTOR;
    }
    result.pushKV("sigoplimit", nSigOpLimit);
    result.pushKV("sizelimit", nSizeLimit);
    if (!fPreSegWit) {
        // While RDTS is active the consensus weight limit is reduced;
        // external miners (e.g. DATUM) must see the real cap.
        result.pushKV("weightlimit", (int64_t)(rdts_active ? REDUCED_DATA_MAX_BLOCK_WEIGHT : MAX_BLOCK_WEIGHT));
    }
    result.pushKV("curtime", block_header.GetBlockTime());
    result.pushKV("bits", strprintf("%08x", block_header.nBits));
    result.pushKV("height", (int64_t)(pindexPrev->nHeight+1));

    if (consensusParams.signet_blocks) {
        result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge));
    }

    if (!block_template->getCoinbaseCommitment().empty()) {
        result.pushKV("default_witness_commitment", HexStr(block_template->getCoinbaseCommitment()));
    }

    return result;
}

class submitblock_StateCatcher final : public CValidationInterface
{
public:
    uint256 hash;
    bool found{false};
    BlockValidationState state;

    explicit submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), state() {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) override {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

static RPCHelpMan submitblock()
{
    // We allow 2 arguments for compliance with BIP22. Argument 2 is ignored.
    return RPCHelpMan{"submitblock",
        "\nAttempts to submit new block to network.\n"
        "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n",
        {
            {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block data to submit"},
            {"dummy", RPCArg::Type::STR, RPCArg::DefaultHint{"ignored"}, "dummy value, for compatibility with BIP22. This value is ignored."},
        },
        {
            RPCResult{"If the block was accepted", RPCResult::Type::NONE, "", ""},
            RPCResult{"Otherwise", RPCResult::Type::STR, "", "According to BIP22"},
        },
        RPCExamples{
                    HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
        if (pindex) {
            chainman.UpdateUncommittedBlockStructures(block, pindex);
        }
    }

    if (auto* template_diversity{EnsureAnyNodeContext(request.context).template_diversity.get()}) {
        template_diversity->MarkLocalSubmission(block.GetHash());
    }

    bool new_block;
    auto sc = std::make_shared<submitblock_StateCatcher>(block.GetHash());
    CHECK_NONFATAL(chainman.m_options.signals)->RegisterSharedValidationInterface(sc);
    bool accepted = chainman.ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&new_block);
    CHECK_NONFATAL(chainman.m_options.signals)->UnregisterSharedValidationInterface(sc);

    // Proof of Datum: record this submission for scoring, regardless of the
    // outcome above. A submitted block is never refused over a Datum flag --
    // only template service is withheld -- because refusing to relay an
    // already-valid block helps no one and only risks delaying its
    // propagation. See src/datum.h.
    const std::string datum_addr{StripDatumPort(request.peerAddr)};
    if (!datum_addr.empty() && !block.vtx.empty() && !block.vtx[0]->vin.empty() && !block.vtx[0]->vout.empty()) {
        EnsureAnyDatumTracker(request.context).RecordSubmission(datum_addr, block.vtx[0]->vout[0].scriptPubKey,
                                                                node::BlockStructureKey(block));
    }

    if (!new_block && accepted) {
        return "duplicate";
    }
    if (!sc->found) {
        return "inconclusive";
    }
    return BIP22ValidationResult(sc->state);
},
    };
}

static RPCHelpMan submitheader()
{
    return RPCHelpMan{"submitheader",
                "\nDecode the given hexdata as a header and submit it as a candidate chain tip if valid."
                "\nThrows when the header is invalid.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block header data"},
                },
                RPCResult{
                    RPCResult::Type::NONE, "", "None"},
                RPCExamples{
                    HelpExampleCli("submitheader", "\"aabbcc\"") +
                    HelpExampleRpc("submitheader", "\"aabbcc\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CBlockHeader h;
    if (!DecodeHexBlockHeader(h, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block header decode failed");
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        if (!chainman.m_blockman.LookupBlockIndex(h.hashPrevBlock)) {
            throw JSONRPCError(RPC_VERIFY_ERROR, "Must submit previous header (" + h.hashPrevBlock.GetHex() + ") first");
        }
    }

    BlockValidationState state;
    chainman.ProcessNewBlockHeaders({{h}}, /*min_pow_checked=*/true, state);
    if (state.IsValid()) return UniValue::VNULL;
    if (state.IsError()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    }
    throw JSONRPCError(RPC_VERIFY_ERROR, state.GetRejectReason());
},
    };
}

static UniValue DatumVerdictToJSON(const std::string& addr, const node::DatumVerdict& verdict)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("address", addr);
    obj.pushKV("gbt_calls", verdict.stats.gbt_calls);
    obj.pushKV("blocks_submitted", verdict.stats.blocks_submitted);
    obj.pushKV("coinbase_reuse_pct", verdict.coinbase_reuse_pct);
    obj.pushKV("gbt_starved", verdict.gbt_starved);
    obj.pushKV("coinbase_stale", verdict.coinbase_stale);
    obj.pushKV("structure_reuse_pct", verdict.structure_reuse_pct);
    if (!verdict.dominant_structure.empty()) obj.pushKV("dominant_structure", verdict.dominant_structure);
    if (verdict.structure_chain_share_pct) obj.pushKV("structure_chain_share_pct", *verdict.structure_chain_share_pct);
    obj.pushKV("structure_allowed", verdict.structure_allowed);
    obj.pushKV("pool_structure_match", verdict.pool_structure_match);
    obj.pushKV("heuristic_match", verdict.heuristic_match);
    obj.pushKV("flagged", verdict.flagged);
    obj.pushKV("manually_flagged", verdict.manually_flagged);
    if (verdict.stats.first_seen) obj.pushKV("first_seen", verdict.stats.first_seen);
    if (verdict.stats.last_gbt_call_time) obj.pushKV("last_gbt_call_time", verdict.stats.last_gbt_call_time);
    return obj;
}

static RPCHelpMan gettemplatediversity()
{
    return RPCHelpMan{"gettemplatediversity",
        "Estimate how many independent block-template builders produced recent blocks.\n"
        "Blocks are grouped by structure: coinbase output layout, witness commitment placement, scriptSig push layout, "
        "locktime/sequence conventions and version-bit use. Coinbase text tags are reported but never used for grouping, "
        "since anyone can write any tag. A structure count is a lower bound on distinct template-building software and "
        "configurations, not a count of entities: unrelated miners running identical software share a structure, and "
        "one operator can run several.\n"
        "For blocks this node saw connect while synced, it also counts mempool transactions that had waited at least 60 "
        "seconds and paid more than the block's median included feerate, yet were left out. A structure whose blocks "
        "skip heavily in some cases but not in most is marked selection_divergent: a hint that more than one template "
        "builder shares it.\n"
        "Local and advisory only: this has no effect on validation, relay, or mining.\n",
        {
            {"nblocks", RPCArg::Type::NUM, RPCArg::Default{144}, "Number of most recent blocks to analyze (capped at 2016 and at the chain length)"},
            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include per-block detail"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "blocks", "Blocks analyzed"},
                {RPCResult::Type::NUM, "first_height", /*optional=*/true, "Lowest height analyzed"},
                {RPCResult::Type::NUM, "last_height", /*optional=*/true, "Highest height analyzed"},
                {RPCResult::Type::NUM, "unavailable_blocks", "Blocks skipped because their data is pruned or unreadable"},
                {RPCResult::Type::NUM, "distinct_structures", "Number of distinct template structures"},
                {RPCResult::Type::NUM, "effective_template_makers", "Inverse Simpson index over structure shares (1 means one structure built every block)"},
                {RPCResult::Type::NUM, "largest_structure_share", "Percentage of analyzed blocks built by the most common structure"},
                {RPCResult::Type::NUM, "divergent_structures", "Structures marked selection_divergent"},
                {RPCResult::Type::NUM, "template_makers_lower_bound", "distinct_structures plus divergent_structures"},
                {RPCResult::Type::NUM, "claimed_identities", "Distinct non-empty coinbase tags"},
                {RPCResult::Type::NUM, "live_samples", "Analyzed blocks with mempool-comparison data"},
                {RPCResult::Type::ARR, "structures", "Structures, most blocks first",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "structure", "Structure key"},
                        {RPCResult::Type::NUM, "blocks", "Blocks with this structure"},
                        {RPCResult::Type::NUM, "share", "Percentage of analyzed blocks"},
                        {RPCResult::Type::ARR, "tags", "Coinbase tags seen with this structure, most blocks first",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "tag", "Tag text (empty if none)"},
                                {RPCResult::Type::NUM, "blocks", "Blocks with this tag"},
                            }},
                        }},
                        {RPCResult::Type::NUM, "empty_blocks", "Blocks containing only a coinbase"},
                        {RPCResult::Type::NUM, "datacarrier_blocks", "Blocks with a transaction carrying more than 83 datacarrier bytes (needs undo data)"},
                        {RPCResult::Type::NUM, "live_samples", "Blocks with mempool-comparison data"},
                        {RPCResult::Type::NUM, "median_skipped_txs", /*optional=*/true, "Median skipped transactions across live samples"},
                        {RPCResult::Type::BOOL, "selection_divergent", "At least 4 live samples, with heavy skipping in at least a quarter but under three quarters of them"},
                    }},
                }},
                {RPCResult::Type::ARR, "blocks_detail", /*optional=*/true, "Per-block detail, newest first (verbose only)",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "height", "Block height"},
                        {RPCResult::Type::STR_HEX, "hash", "Block hash"},
                        {RPCResult::Type::STR, "structure", "Structure key"},
                        {RPCResult::Type::STR, "tag", "Coinbase tag text (empty if none)"},
                        {RPCResult::Type::NUM, "txs", "Transactions, including the coinbase"},
                        {RPCResult::Type::NUM, "datacarrier_bytes", /*optional=*/true, "Total datacarrier bytes (needs undo data)"},
                        {RPCResult::Type::NUM, "feerate_ordered_pct", /*optional=*/true, "Percentage of adjacent transaction pairs in non-increasing feerate order"},
                        {RPCResult::Type::NUM, "median_feerate", /*optional=*/true, "Median feerate in sat/vB"},
                        {RPCResult::Type::NUM, "eligible_txs", /*optional=*/true, "Mempool transactions old enough to have been included (live only)"},
                        {RPCResult::Type::NUM, "skipped_txs", /*optional=*/true, "Eligible transactions paying above the block's median feerate that were left out (live only)"},
                        {RPCResult::Type::NUM, "skipped_fees_sat", /*optional=*/true, "Fees of skipped transactions in satoshis (live only)"},
                    }},
                }},
            }},
        RPCExamples{
            HelpExampleCli("gettemplatediversity", "")
            + HelpExampleCli("gettemplatediversity", "2016 true")
            + HelpExampleRpc("gettemplatediversity", "144, false")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int nblocks{request.params[0].isNull() ? 144 : request.params[0].getInt<int>()};
    if (nblocks < 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "nblocks must be at least 1");
    nblocks = std::min(nblocks, 2016);
    const bool verbose{!request.params[1].isNull() && request.params[1].get_bool()};

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const node::FingerprintWindow window{node::CollectRecentFingerprints(chainman, node.template_diversity.get(), nblocks)};

    const auto round2{[](double x) { return std::round(x * 100) / 100; }};

    struct Structure {
        int blocks{0};
        std::map<std::string, int> tags;
        int empty{0};
        int datacarrier{0};
        std::vector<int64_t> skipped;
    };
    std::map<std::string, Structure> structures;
    std::map<std::string, int> claimed;
    int live_samples{0};
    for (const auto& [fp, live] : window.blocks) {
        Structure& s{structures[fp.structure_key]};
        ++s.blocks;
        ++s.tags[fp.coinbase_tag];
        if (!fp.coinbase_tag.empty()) ++claimed[fp.coinbase_tag];
        if (fp.tx_count == 1) ++s.empty;
        if (fp.datacarrier_txs > 0) ++s.datacarrier;
        if (live) {
            ++live_samples;
            s.skipped.push_back(live->skipped_txs);
        }
    }

    std::vector<std::pair<std::string, const Structure*>> sorted;
    for (const auto& [key, s] : structures) sorted.emplace_back(key, &s);
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
        return a.second->blocks != b.second->blocks ? a.second->blocks > b.second->blocks : a.first < b.first;
    });

    const double total{double(window.blocks.size())};
    double simpson{0};
    int largest{0};
    int divergent{0};
    UniValue structures_json(UniValue::VARR);
    for (const auto& [key, s] : sorted) {
        const double share{s->blocks / total};
        simpson += share * share;
        largest = std::max(largest, s->blocks);

        UniValue obj(UniValue::VOBJ);
        obj.pushKV("structure", key);
        obj.pushKV("blocks", s->blocks);
        obj.pushKV("share", round2(share * 100));

        std::vector<std::pair<std::string, int>> tags(s->tags.begin(), s->tags.end());
        std::sort(tags.begin(), tags.end(), [](const auto& a, const auto& b) {
            return a.second != b.second ? a.second > b.second : a.first < b.first;
        });
        UniValue tags_json(UniValue::VARR);
        for (const auto& [tag, count] : tags) {
            UniValue t(UniValue::VOBJ);
            t.pushKV("tag", tag);
            t.pushKV("blocks", count);
            tags_json.push_back(std::move(t));
        }
        obj.pushKV("tags", std::move(tags_json));
        obj.pushKV("empty_blocks", s->empty);
        obj.pushKV("datacarrier_blocks", s->datacarrier);
        obj.pushKV("live_samples", uint64_t(s->skipped.size()));

        bool selection_divergent{false};
        if (!s->skipped.empty()) {
            std::vector<int64_t> skipped{s->skipped};
            const auto mid{skipped.begin() + skipped.size() / 2};
            std::nth_element(skipped.begin(), mid, skipped.end());
            obj.pushKV("median_skipped_txs", *mid);
            if (skipped.size() >= 4) {
                const size_t heavy = std::count_if(skipped.begin(), skipped.end(),
                                                   [](int64_t n) { return n >= node::TEMPLATE_DIVERSITY_HEAVY_SKIP; });
                selection_divergent = heavy * 4 >= skipped.size() && heavy * 4 < skipped.size() * 3;
            }
        }
        if (selection_divergent) ++divergent;
        obj.pushKV("selection_divergent", selection_divergent);
        structures_json.push_back(std::move(obj));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("blocks", uint64_t(window.blocks.size()));
    if (!window.blocks.empty()) {
        result.pushKV("first_height", window.blocks.back().first.height);
        result.pushKV("last_height", window.blocks.front().first.height);
    }
    result.pushKV("unavailable_blocks", window.unavailable);
    result.pushKV("distinct_structures", uint64_t(structures.size()));
    result.pushKV("effective_template_makers", simpson > 0 ? round2(1 / simpson) : 0.0);
    result.pushKV("largest_structure_share", total > 0 ? round2(largest * 100 / total) : 0.0);
    result.pushKV("divergent_structures", divergent);
    result.pushKV("template_makers_lower_bound", uint64_t(structures.size()) + divergent);
    result.pushKV("claimed_identities", uint64_t(claimed.size()));
    result.pushKV("live_samples", live_samples);
    result.pushKV("structures", std::move(structures_json));

    if (verbose) {
        UniValue detail(UniValue::VARR);
        for (const auto& [fp, live] : window.blocks) {
            UniValue b(UniValue::VOBJ);
            b.pushKV("height", fp.height);
            b.pushKV("hash", fp.hash.GetHex());
            b.pushKV("structure", fp.structure_key);
            b.pushKV("tag", fp.coinbase_tag);
            b.pushKV("txs", uint64_t(fp.tx_count));
            if (fp.have_undo) {
                b.pushKV("datacarrier_bytes", fp.datacarrier_bytes);
                if (fp.feerate_ordered_pct >= 0) b.pushKV("feerate_ordered_pct", fp.feerate_ordered_pct);
                if (fp.median_feerate >= 0) b.pushKV("median_feerate", fp.median_feerate / 1000.0);
            }
            if (live) {
                b.pushKV("eligible_txs", live->eligible_txs);
                b.pushKV("skipped_txs", live->skipped_txs);
                b.pushKV("skipped_fees_sat", live->skipped_fees);
            }
            detail.push_back(std::move(b));
        }
        result.pushKV("blocks_detail", std::move(detail));
    }
    return result;
},
    };
}

static RPCHelpMan getdatuminfo()
{
    return RPCHelpMan{"getdatuminfo",
        "\nProof of Datum: this node's read on how a connection has been using its mining RPCs.\n"
        "This is a local, advisory heuristic, not a claim of certainty: it distinguishes a client that\n"
        "builds its own block templates from one that only ever submits an already-built block, by how\n"
        "often it calls getblocktemplate relative to what it submits, and how often its submitted blocks\n"
        "reuse the same coinbase payout script, over a fairly large sample (see DATUM_MIN_SUBMISSIONS).\n"
        "It also fingerprints each submitted block's template structure (see gettemplatediversity): if a\n"
        "connection's blocks keep using a structure that built a large share of recent network blocks,\n"
        "\"pool_structure_match\" is set. A structure verified to belong to self-templating software, such\n"
        "as a common DATUM gateway release, can be exempted with -datumallowstructure.\n"
        "\"heuristic_match\" reports whether the pattern matched; it is informational only and never by\n"
        "itself withholds anything. \"flagged\" reports whether this node is actually refusing this\n"
        "address a template right now, which only happens by an explicit adddatumban call, or (only\n"
        "with -datumautoban enabled) once heuristic_match has held. See doc/proof-of-datum.md.\n"
        "With no address given, returns every address this node has recorded activity for.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Look up a single address (as shown by getpeerinfo, without a port)"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "address", "the address"},
                    {RPCResult::Type::NUM, "gbt_calls", "getblocktemplate calls recorded from this address"},
                    {RPCResult::Type::NUM, "blocks_submitted", "blocks accepted by submitblock from this address"},
                    {RPCResult::Type::NUM, "coinbase_reuse_pct", "share (0-100) of recent submitted blocks sharing this address's single most common coinbase payout script"},
                    {RPCResult::Type::BOOL, "gbt_starved", "true if blocks are being submitted with too few getblocktemplate calls behind them"},
                    {RPCResult::Type::BOOL, "coinbase_stale", "true if one payout script dominates this address's recent submitted blocks"},
                    {RPCResult::Type::NUM, "structure_reuse_pct", "share (0-100) of recent submitted blocks sharing this address's single most common template structure"},
                    {RPCResult::Type::STR, "dominant_structure", /*optional=*/true, "that most common template structure"},
                    {RPCResult::Type::NUM, "structure_chain_share_pct", /*optional=*/true, "share (0-100) of recent network blocks, excluding blocks submitted to this node, built with that structure; omitted until enough blocks have connected"},
                    {RPCResult::Type::BOOL, "structure_allowed", "true if that structure is exempted with -datumallowstructure"},
                    {RPCResult::Type::BOOL, "pool_structure_match", "true if this address keeps submitting blocks with a structure that built a large share of recent network blocks"},
                    {RPCResult::Type::BOOL, "heuristic_match", "true if this address's pattern matches the built-in heuristic; informational, never enforced by itself"},
                    {RPCResult::Type::BOOL, "flagged", "true if this node is actually refusing this address a block template right now"},
                    {RPCResult::Type::BOOL, "manually_flagged", "true if the active flag came from a human decision (adddatumban) rather than -datumautoban"},
                    {RPCResult::Type::NUM_TIME, "first_seen", /*optional=*/true, "when this address was first recorded"},
                    {RPCResult::Type::NUM_TIME, "last_gbt_call_time", /*optional=*/true, "the most recent getblocktemplate call from this address"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("getdatuminfo", "")
            + HelpExampleCli("getdatuminfo", "\"203.0.113.5\"")
            + HelpExampleRpc("getdatuminfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    DatumTracker& datum{EnsureAnyDatumTracker(request.context)};
    UniValue result(UniValue::VARR);
    if (!request.params[0].isNull()) {
        const std::string addr{request.params[0].get_str()};
        result.push_back(DatumVerdictToJSON(addr, datum.GetVerdict(addr)));
        return result;
    }
    for (const std::string& addr : datum.GetTrackedAddresses()) {
        result.push_back(DatumVerdictToJSON(addr, datum.GetVerdict(addr)));
    }
    return result;
},
    };
}

static RPCHelpMan adddatumban()
{
    return RPCHelpMan{"adddatumban",
        "\nManually flag an address as a Proof of Datum offender: this node will stop serving it block\n"
        "templates. Use this for a connection you have reason to believe is a bare pool relay that the\n"
        "heuristic in getdatuminfo did not catch on its own -- a public disclosure, someone telling you\n"
        "directly, whatever the evidence is doesn't have to fit the heuristic's shape. Persisted across\n"
        "restarts. Never affects whether a block from this address is accepted or relayed.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to flag (as shown by getpeerinfo, without a port)"},
            {"reason", RPCArg::Type::STR, RPCArg::Optional::NO, "Why: recorded for your own future reference and shown by listdatumbans"},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{
            HelpExampleCli("adddatumban", "\"203.0.113.5\" \"known SV1-only bridge, reported by operator\"")
            + HelpExampleRpc("adddatumban", "\"203.0.113.5\", \"known SV1-only bridge, reported by operator\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    EnsureAnyDatumTracker(request.context).AddManualBan(request.params[0].get_str(), request.params[1].get_str());
    return UniValue::VNULL;
},
    };
}

static RPCHelpMan removedatumban()
{
    return RPCHelpMan{"removedatumban",
        "\nRemove a Proof of Datum flag from an address, whether it was set manually or by the heuristic.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to unflag"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether a flag was removed"},
        RPCExamples{
            HelpExampleCli("removedatumban", "\"203.0.113.5\"")
            + HelpExampleRpc("removedatumban", "\"203.0.113.5\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    return EnsureAnyDatumTracker(request.context).RemoveBan(request.params[0].get_str());
},
    };
}

static RPCHelpMan listdatumbans()
{
    return RPCHelpMan{"listdatumbans",
        "\nList every address this node currently refuses a block template, manual and heuristic alike.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "address", "the flagged address"},
                    {RPCResult::Type::STR, "reason", "why it was flagged"},
                    {RPCResult::Type::STR, "source", "\"manual\" (adddatumban) or \"heuristic\" (crossed the automatic thresholds)"},
                    {RPCResult::Type::NUM_TIME, "time", "when the flag was set"},
                }},
            }
        },
        RPCExamples{HelpExampleCli("listdatumbans", "") + HelpExampleRpc("listdatumbans", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue result(UniValue::VARR);
    for (const auto& [addr, entry] : EnsureAnyDatumTracker(request.context).ListBans()) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("address", addr);
        obj.pushKV("reason", entry.reason);
        obj.pushKV("source", entry.source);
        obj.pushKV("time", entry.time);
        result.push_back(std::move(obj));
    }
    return result;
},
    };
}

void RegisterMiningRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"mining", &getnetworkhashps},
        {"mining", &getmininginfo},
        {"mining", &prioritisetransaction},
        {"mining", &getprioritisedtransactions},
        {"mining", &getblocktemplate},
        {"mining", &submitblock},
        {"mining", &submitheader},
        {"mining", &getdatuminfo},
        {"mining", &adddatumban},
        {"mining", &removedatumban},
        {"mining", &listdatumbans},
        {"mining", &gettemplatediversity},

        {"hidden", &generatetoaddress},
        {"hidden", &generatetodescriptor},
        {"hidden", &generateblock},
        {"hidden", &generate},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
