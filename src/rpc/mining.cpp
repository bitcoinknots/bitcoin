// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/sharepool.h>
#include <consensus/sharepool_hash.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <deploymentinfo.h>
#include <deploymentstatus.h>
#include <interfaces/mining.h>
#include <key_io.h>
#include <net.h>
#include <net_processing.h>
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
#include <sharepool/relay.h>
#include <sharepool/hash_store.h>
#include <sharepool/retry_worker.h>
#include <streams.h>
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

#include <algorithm>
#include <limits>
#include <memory>
#include <stdint.h>

using interfaces::BlockRef;
using interfaces::BlockTemplate;
using interfaces::Mining;
using node::BlockAssembler;
using node::GetMinimumTime;
using node::NodeContext;
using node::RegenerateCommitments;
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
                        {RPCResult::Type::NUM, "difficulty", "The current difficulty"},
                        {RPCResult::Type::STR_HEX, "target", "The current target"},
                        {RPCResult::Type::NUM, "networkhashps", "The network hashes per second"},
                        {RPCResult::Type::NUM, "pooledtx", "The size of the mempool"},
                        {RPCResult::Type::STR, "chain", "current network name (" LIST_CHAIN_NAMES ")"},
                        {RPCResult::Type::STR_HEX, "signet_challenge", /*optional=*/true, "The block challenge (aka. block script), in hexadecimal (only present if the current network is a signet)"},
                        {RPCResult::Type::OBJ, "next", "The next block",
                        {
                            {RPCResult::Type::NUM, "height", "The next height"},
                            {RPCResult::Type::STR_HEX, "bits", "The next target nBits"},
                            {RPCResult::Type::NUM, "difficulty", "The next difficulty"},
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
    obj.pushKV("difficulty", GetDifficulty(tip));
    obj.pushKV("target", GetTarget(tip, chainman.GetConsensus().powLimit).GetHex());
    obj.pushKV("networkhashps",    getnetworkhashps().HandleRequest(request));
    obj.pushKV("pooledtx",         (uint64_t)mempool.size());
    obj.pushKV("chain", chainman.GetParams().GetChainTypeString());

    UniValue next(UniValue::VOBJ);
    CBlockIndex next_index;
    NextEmptyBlockIndex(tip, chainman.GetConsensus(), next_index);

    next.pushKV("height", next_index.nHeight);
    next.pushKV("bits", strprintf("%08x", next_index.nBits));
    next.pushKV("difficulty", GetDifficulty(next_index));
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

    if (state.IsPending()) return state.GetRejectReason();
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
                    {"sharepool", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "(literal) indicates support for the opt-in regtest settlement profile; complete the manifest and validate in proposal mode before mining"},
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
                {RPCResult::Type::OBJ, "sharepool", /*optional=*/true, "Required regtest settlement construction parameters. The base template is incomplete until its manifest and payouts are added and proposal validation succeeds.",
                {
                    {RPCResult::Type::NUM, "version", "Settlement wire profile version"},
                    {RPCResult::Type::NUM, "activation_height", "First block requiring settlement evidence"},
                    {RPCResult::Type::STR_HEX, "genesis", "Native genesis hash in RPC display order"},
                    {RPCResult::Type::STR_HEX, "rules_root", "Settlement rules hash in RPC display order"},
                    {RPCResult::Type::STR_HEX, "share_bits", /*optional=*/true, "Version 1 compact share target"},
                    {RPCResult::Type::STR_HEX, "share_target", /*optional=*/true, "Version 3 exact target derived from this job native bits"},
                    {RPCResult::Type::NUM, "max_share_age", "Maximum settlement height minus origin job height"},
                    {RPCResult::Type::NUM, "max_shares", /*optional=*/true, "Version 1 maximum proof count"},
                    {RPCResult::Type::NUM, "max_manifest_bytes", /*optional=*/true, "Version 1 in-block evidence byte limit"},
                    {RPCResult::Type::STR, "mode", /*optional=*/true, "Selected hash-only profile"},
                    {RPCResult::Type::STR, "payout_cutoff", /*optional=*/true, "Version 5 uses the actual native parent block"},
                    {RPCResult::Type::STR, "local_receipts", /*optional=*/true, "Version 5 local receipts are provisional until anchored"},
                    {RPCResult::Type::NUM, "max_snapshot_bytes", /*optional=*/true, "Version 3 complete off-block snapshot byte bound"},
                    {RPCResult::Type::NUM, "max_dependency_depth", /*optional=*/true, "Version 3 maximum origin dependency depth"},
                    {RPCResult::Type::NUM, "max_dependency_bytes", /*optional=*/true, "Version 3 maximum unique dependency bytes"},
                    {RPCResult::Type::BOOL, "requires_completion", "Always true: base templates require a settlement manifest and exact payouts"},
                }},
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

    if (chainman.ActiveChain().Height() + 1 >= consensusParams.SharePoolHeight &&
        setClientRules.count("sharepool") != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Support for 'sharepool' rule requires explicit client support; complete the settlement manifest and validate the resulting block in proposal mode before mining");
    }

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
    if (pindexPrev->nHeight + 1 >= consensusParams.SharePoolHeight) {
        aRules.push_back("!sharepool");
        UniValue settlement(UniValue::VOBJ);
        settlement.pushKV("version", consensusParams.SharePoolHashOnly ? sharepool::hashonly::ProfileVersion(consensusParams) : 1);
        settlement.pushKV("activation_height", consensusParams.SharePoolHeight);
        settlement.pushKV("genesis", consensusParams.hashGenesisBlock.GetHex());
        settlement.pushKV("rules_root", (consensusParams.SharePoolHashOnly ? sharepool::hashonly::RulesHash(sharepool::hashonly::ProfileVersion(consensusParams)) : sharepool::RulesHash()).GetHex());
        settlement.pushKV("max_share_age", sharepool::MAX_SHARE_AGE);
        if (consensusParams.SharePoolHashOnly) {
            settlement.pushKV("mode", consensusParams.SharePoolAdmittedLedger ? "hash-only-v5-confirmed-ledger" : "hash-only-v4");
            if (consensusParams.SharePoolAdmittedLedger) {
                settlement.pushKV("payout_cutoff", "native-parent-block");
                settlement.pushKV("local_receipts", "provisional-until-anchored");
            }
            settlement.pushKV("share_target", sharepool::hashonly::ShareTarget(block_header.nBits).GetHex());
            settlement.pushKV("max_snapshot_bytes", sharepool::hashonly::MAX_SNAPSHOT_BYTES);
            settlement.pushKV("max_dependency_depth", sharepool::hashonly::MAX_DEPENDENCY_DEPTH);
            settlement.pushKV("max_dependency_bytes", sharepool::hashonly::MAX_DEPENDENCY_BYTES);
        } else {
            settlement.pushKV("share_bits", strprintf("%08x", sharepool::SHARE_BITS));
            settlement.pushKV("max_shares", sharepool::MAX_SHARES);
            settlement.pushKV("max_manifest_bytes", sharepool::MAX_MANIFEST);
        }
        settlement.pushKV("requires_completion", true);
        result.pushKV("sharepool", std::move(settlement));
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

    bool new_block;
    auto sc = std::make_shared<submitblock_StateCatcher>(block.GetHash());
    CHECK_NONFATAL(chainman.m_options.signals)->RegisterSharedValidationInterface(sc);
    bool accepted = chainman.ProcessNewBlock(blockptr, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/&new_block);
    CHECK_NONFATAL(chainman.m_options.signals)->UnregisterSharedValidationInterface(sc);
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

static RPCHelpMan validatesharepooltemplate()
{
    return RPCHelpMan{"validatesharepooltemplate",
        "Validate a complete SPN1 template against its recent active-chain parent.\n"
        "Available only for the opt-in regtest profile, at most three blocks behind the native tip.\n"
        "Checks transactions, commitments, authorization and actual fee payouts using a temporary\n"
        "UTXO view. Candidate proof of work is not required. Does not change the chain, publish a\n"
        "block, or authorize mining. Historical block and undo data must be locally available.\n",
        {{"template", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical full block template, at most 4000000 bytes"}},
        RPCResult{RPCResult::Type::OBJ, "", "Validated template context",
        {
            {RPCResult::Type::BOOL, "valid", "True after complete native template validation"},
            {RPCResult::Type::STR_HEX, "native_tip", "Active tip used to check eligibility"},
            {RPCResult::Type::STR_HEX, "native_parent", "Actual active ancestor used for the UTXO view"},
            {RPCResult::Type::NUM, "origin_height", "Height of the validated template"},
            {RPCResult::Type::STR_HEX, "commitment", "SPN1 envelope commitment in RPC display order"},
        }},
        RPCExamples{HelpExampleCli("validatesharepooltemplate", "\"serialized_block_hex\"")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const auto text = request.params[0].get_str();
            if (text.empty() || text.size() > 2 * MAX_BLOCK_SERIALIZED_SIZE || !IsHex(text)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Template must contain at most 4000000 bytes of hexadecimal data");
            }
            CBlock block;
            try {
                const auto raw = ParseHex(text);
                DataStream stream{raw};
                stream >> TX_WITH_WITNESS(block);
                DataStream canonical;
                canonical << TX_WITH_WITNESS(block);
                if (!stream.empty() || HexStr(canonical) != HexStr(raw)) {
                    throw std::ios_base::failure("Noncanonical block encoding");
                }
            } catch (const std::exception&) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Noncanonical or malformed SPN1 template");
            }
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            const auto& params = chainman.GetParams();
            const auto& consensus = params.GetConsensus();
            auto& chainstate = chainman.ActiveChainstate();
            const auto* tip = chainstate.m_chain.Tip();
            if (params.GetChainType() != ChainType::REGTEST || !tip ||
                consensus.SharePoolHeight == std::numeric_limits<int>::max() ||
                tip->nHeight + 1 < consensus.SharePoolHeight) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Native sharepool validation is not active on this chain");
            }
            auto* parent = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
            if (!parent || !chainstate.m_chain.Contains(parent) ||
                parent->nHeight + 1 < consensus.SharePoolHeight ||
                tip->nHeight - parent->nHeight > int(sharepool::MAX_SHARE_AGE)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Template parent is not an eligible active native ancestor");
            }
            BlockValidationState state;
            if (!TestSharePoolTemplateOnAncestor(state, params, chainstate, block, parent)) {
                throw JSONRPCError(state.IsError() ? RPC_VERIFY_ERROR : RPC_VERIFY_REJECTED, state.ToString());
            }
            UniValue result(UniValue::VOBJ);
            result.pushKV("valid", true);
            result.pushKV("native_tip", tip->GetBlockHash().GetHex());
            result.pushKV("native_parent", parent->GetBlockHash().GetHex());
            result.pushKV("origin_height", parent->nHeight + 1);
            result.pushKV("commitment", block.m_mm_rhs.GetHex());
            return result;
        },
    };
}

static RPCHelpMan validatesharepoolshare()
{
    return RPCHelpMan{"validatesharepoolshare",
        "Validate one SPN1 share against the current native ancestry using native PoW and Schnorr verification.\n"
        "Available only while the opt-in regtest profile is active. This does not credit or publish work,\n"
        "check whether it was already paid, or validate the full body of its origin template.\n",
        {
            {"share", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical serialized SPN1 share"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Verified share and the native tip used for eligibility",
        {
            {RPCResult::Type::BOOL, "valid", "True after native proof verification"},
            {RPCResult::Type::STR_HEX, "proof_id", "Native PoW hash in RPC display order"},
            {RPCResult::Type::NUM, "origin_height", "Height of the authorized origin job"},
            {RPCResult::Type::STR_HEX, "pool", "Pool ID in RPC display order"},
            {RPCResult::Type::STR_HEX, "owner", "Precommitted x-only owner public key"},
            {RPCResult::Type::STR_HEX, "payout_script", "Precommitted direct payout script"},
            {RPCResult::Type::STR_HEX, "share_bits", /*optional=*/true, "Version 1 compact share target"},
            {RPCResult::Type::STR_HEX, "native_tip", "Tip hash used to check eligibility"},
            {RPCResult::Type::NUM, "settlement_height", "Next native block height"},
        }},
        RPCExamples{HelpExampleCli("validatesharepoolshare", "\"serialized_share_hex\"")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const auto text = request.params[0].get_str();
            if (text.empty() || text.size() > 2048 || !IsHex(text)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Share must contain at most 1024 bytes of hexadecimal data");
            }
            sharepool::Share share;
            try {
                const auto raw = ParseHex(text);
                DataStream stream{raw};
                stream >> share;
                DataStream canonical;
                canonical << share;
                if (!stream.empty() || HexStr(canonical) != HexStr(raw)) {
                    throw std::ios_base::failure("Noncanonical share encoding");
                }
            } catch (const std::exception&) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Noncanonical or malformed SPN1 share");
            }
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            const auto& params = chainman.GetParams();
            const auto& consensus = params.GetConsensus();
            const auto* parent = chainman.ActiveChain().Tip();
            if (params.GetChainType() != ChainType::REGTEST || !parent ||
                parent->nHeight + 1 < consensus.SharePoolHeight) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Native sharepool validation is not active on this chain");
            }
            const auto settlement_time = std::max<int64_t>(parent->GetMedianTimePast() + 1, GetTime());
            if (settlement_time < 0 || settlement_time > std::numeric_limits<uint32_t>::max()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Native time is outside the header range");
            }
            std::string error;
            if (!sharepool::CheckShare(share, parent, static_cast<uint32_t>(settlement_time), consensus, error)) {
                throw JSONRPCError(RPC_VERIFY_REJECTED, error);
            }
            UniValue result(UniValue::VOBJ);
            result.pushKV("valid", true);
            result.pushKV("proof_id", share.header.GetHash().GetHex());
            result.pushKV("origin_height", share.origin.height);
            result.pushKV("pool", share.origin.pool.GetHex());
            result.pushKV("owner", HexStr(share.origin.owner));
            result.pushKV("payout_script", HexStr(share.origin.payout_script));
            result.pushKV("share_bits", strprintf("%08x", sharepool::SHARE_BITS));
            result.pushKV("native_tip", parent->GetBlockHash().GetHex());
            result.pushKV("settlement_height", parent->nHeight + 1);
            return result;
        },
    };
}

static uint8_t SharePoolRelayKind(const UniValue& value)
{
    const auto kind = value.get_str();
    if (kind == "template") return sharepool::RELAY_TEMPLATE;
    if (kind == "receipt") return sharepool::RELAY_RECEIPT;
    throw JSONRPCError(RPC_INVALID_PARAMETER, "Evidence kind must be template or receipt");
}

static UniValue SharePoolObjectMetadata(const sharepool::RelayObject& object)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("kind", object.item.kind == sharepool::RELAY_TEMPLATE ? "template" : "receipt");
    result.pushKV("id", object.item.id.GetHex());
    result.pushKV("sha256", object.body_hash.GetHex());
    result.pushKV("bytes", object.data.size());
    result.pushKV("origin_height", object.origin_height);
    result.pushKV("origin_parent", object.origin_parent.GetHex());
    result.pushKV("template_id", object.template_id.GetHex());
    return result;
}

static RPCHelpMan setsharepoolrelay()
{
    return RPCHelpMan{"setsharepoolrelay",
        "Opt in to bounded SPN1 evidence relay on existing Bitcoin peer connections.\n"
        "Requires active regtest SPN1. One nonzero pool may be selected until restart.\n"
        "This cache is ephemeral; miner acknowledgment requires a separate durable gate.\n",
        {{"pool", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Pool identifier (32 bytes)"}},
        RPCResult{RPCResult::Type::BOOL, "", "True after local configuration"},
        RPCExamples{HelpExampleCli("setsharepoolrelay", "\"pool_id\"")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            auto& node = EnsureAnyNodeContext(request.context);
            auto& chainman = EnsureChainman(node);
            auto& peerman = EnsurePeerman(node);
            const uint256 pool = ParseHashV(request.params[0], "pool");
            LOCK(cs_main);
            std::string error;
            if (!peerman.SharePoolRelay().Configure(chainman, pool, error)) throw JSONRPCError(RPC_INVALID_PARAMETER, error);
            return true;
        },
    };
}

static RPCHelpMan submitsharepoolevidence()
{
    return RPCHelpMan{"submitsharepoolevidence",
        "Validate a full origin template or share and add it to the ephemeral native relay.\n"
        "Full origins must precede their receipts. Native scripts, fees and payout checks\n"
        "apply to templates; proof, owner and active-ancestry checks apply to receipts.\n"
        "Success is not durable miner acknowledgment or mining-job authorization.\n",
        {{"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "template or receipt"},
         {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical serialized object"}},
        RPCResult{RPCResult::Type::OBJ, "", "Validated relay identity", {
            {RPCResult::Type::STR, "kind", "Evidence type"},
            {RPCResult::Type::STR_HEX, "id", "Native template or proof identifier"},
        }},
        RPCExamples{HelpExampleCli("submitsharepoolevidence", "\"template\" \"serialized_block_hex\"")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const uint8_t kind = SharePoolRelayKind(request.params[0]);
            const auto text = request.params[1].get_str();
            const auto maximum = kind == sharepool::RELAY_TEMPLATE ? sharepool::MAX_RELAY_TEMPLATE : sharepool::MAX_RELAY_RECEIPT;
            if (text.empty() || text.size() > 2 * maximum || !IsHex(text)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid evidence byte encoding or bound");
            const auto raw = ParseHex(text);
            auto& node = EnsureAnyNodeContext(request.context);
            auto& chainman = EnsureChainman(node);
            auto& peerman = EnsurePeerman(node);
            LOCK(cs_main);
            std::string error;
            auto result = peerman.SharePoolRelay().Add(chainman, kind, raw, error);
            if (!result) throw JSONRPCError(RPC_VERIFY_REJECTED, error);
            UniValue value{UniValue::VOBJ};
            value.pushKV("kind", kind == sharepool::RELAY_TEMPLATE ? "template" : "receipt");
            value.pushKV("id", result->id.GetHex());
            return value;
        },
    };
}

static RPCHelpMan getsharepoolinventory()
{
    return RPCHelpMan{"getsharepoolinventory",
        "Return bounded validated evidence currently eligible on the active native chain.\n"
        "This inventory is not a complete-disclosure claim or a settlement checkpoint.\n",
        {}, RPCResult{RPCResult::Type::OBJ_DYN, "", "Relay profile, native context and object descriptors", {
            {RPCResult::Type::ANY, "field", "Profile/context fields or bounded items array"},
        }}, RPCExamples{HelpExampleCli("getsharepoolinventory", "")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            auto& node = EnsureAnyNodeContext(request.context);
            auto& chainman = EnsureChainman(node);
            auto& peerman = EnsurePeerman(node);
            LOCK(cs_main);
            auto& store = peerman.SharePoolRelay();
            const auto items = store.Inventory(chainman);
            const auto* tip = chainman.ActiveChain().Tip();
            UniValue result{UniValue::VOBJ}, entries{UniValue::VARR};
            result.pushKV("enabled", store.Active(chainman));
            result.pushKV("pool", store.Pool().GetHex());
            result.pushKV("genesis", chainman.GetParams().GetConsensus().hashGenesisBlock.GetHex());
            result.pushKV("rules", sharepool::RulesHash().GetHex());
            result.pushKV("activation_height", chainman.GetParams().GetConsensus().SharePoolHeight);
            result.pushKV("tip", tip ? tip->GetBlockHash().GetHex() : uint256{}.GetHex());
            result.pushKV("height", tip ? tip->nHeight : -1);
            result.pushKV("revision", store.Revision());
            for (const auto& item : items) {
                const auto object = store.Get(chainman, item.kind, item.id);
                if (object) entries.push_back(SharePoolObjectMetadata(*object));
            }
            result.pushKV("items", std::move(entries));
            return result;
        },
    };
}

static RPCHelpMan getsharepoolobject()
{
    return RPCHelpMan{"getsharepoolobject",
        "Read one locally validated active relay object. Expired or orphaned evidence\n"
        "is not served; durable acknowledged history belongs to the miner archive.\n",
        {{"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "template or receipt"},
         {"id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Native template or proof identifier"}},
        RPCResult{RPCResult::Type::OBJ_DYN, "", "Object descriptor and canonical data hex", {
            {RPCResult::Type::ANY, "field", "Descriptor field or serialized data"},
        }}, RPCExamples{HelpExampleCli("getsharepoolobject", "\"template\" \"identifier\"")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const uint8_t kind = SharePoolRelayKind(request.params[0]);
            const uint256 id = ParseHashV(request.params[1], "id");
            auto& node = EnsureAnyNodeContext(request.context);
            auto& chainman = EnsureChainman(node);
            auto& peerman = EnsurePeerman(node);
            LOCK(cs_main);
            const auto object = peerman.SharePoolRelay().Get(chainman, kind, id);
            if (!object) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown or ineligible relay object");
            auto result = SharePoolObjectMetadata(*object);
            result.pushKV("data", HexStr(object->data));
            return result;
        },
    };
}

static sharepool::HashSnapshotStore& RequireHashSnapshotStore(ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (chainman.GetParams().GetChainType() != ChainType::REGTEST ||
        !chainman.GetConsensus().SharePoolHashOnly || !chainman.m_sharepool_hash_store) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Hash-only settlement requires the explicit regtest profile");
    }
    return *chainman.m_sharepool_hash_store;
}

static void RequireHashValidation(sharepool::HashSnapshotStore& store,
                                  const sharepool::hashonly::Result& checked) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (checked.IsValid()) return;
    if (checked.IsMissing()) {
        store.Need(checked.missing);
        throw JSONRPCError(RPC_VERIFY_ERROR, "sharepool-hash-data-missing");
    }
    throw JSONRPCError(RPC_VERIFY_REJECTED, checked.reason);
}

static sharepool::hashonly::Snapshot ParseHashSnapshot(const UniValue& value)
{
    const auto encoded = value.get_str();
    if (encoded.empty() || encoded.size() > 2 * sharepool::hashonly::MAX_SNAPSHOT_BYTES || !IsHex(encoded)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Snapshot exceeds byte bound or is not hexadecimal");
    }
    try { return sharepool::hashonly::DecodeSnapshot(ParseHex(encoded)); }
    catch (const std::exception&) { throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Noncanonical or malformed snapshot"); }
}

static UniValue HashJobResult(const CBlock& block, const sharepool::hashonly::Snapshot& snapshot, CAmount reward)
{
    DataStream encoded;
    encoded << TX_WITH_WITNESS(block);
    UniValue result{UniValue::VOBJ};
    result.pushKV("template", HexStr(encoded));
    result.pushKV("snapshot", HexStr(sharepool::hashonly::EncodeSnapshot(snapshot)));
    result.pushKV("commitment", block.m_mm_rhs.GetHex());
    result.pushKV("job_commitment", snapshot.job_commitment.GetHex());
    result.pushKV("native_parent", block.hashPrevBlock.GetHex());
    result.pushKV("height", block.m_height);
    result.pushKV("reward", reward);
    return result;
}

static std::vector<RPCResult> HashJobResults()
{
    return {
        {RPCResult::Type::STR_HEX, "template", "Full normalized native template"},
        {RPCResult::Type::STR_HEX, "snapshot", "Complete canonical snapshot"},
        {RPCResult::Type::STR_HEX, "commitment", "Flat snapshot hash in m_mm_rhs"},
        {RPCResult::Type::STR_HEX, "job_commitment", "Exact job attestation digest"},
        {RPCResult::Type::STR_HEX, "native_parent", "Native parent used for construction and validation"},
        {RPCResult::Type::NUM, "height", "Native block height"},
        {RPCResult::Type::NUM, "reward", "Exact subsidy plus transaction fees, in satoshis"},
    };
}

static RPCHelpMan preparesharepoolhashjob()
{
    auto results = HashJobResults();
    results.emplace_back(RPCResult::Type::STR_HEX, "signing_payload", "Binding, job and contents hashes for the external owner signer");
    results.emplace_back(RPCResult::Type::STR_HEX, "signing_hash", "Owner signature message digest");
    return RPCHelpMan{"preparesharepoolhashjob",
        "Construct a native settlement job from a proposed unsigned snapshot using the local mempool.\n"
        "The proposal must name the current tip. The node derives paid state, exact fees and coinbase payouts,\n"
        "reserves their block space, and validates all transactions and dependencies before returning a signing payload.\n"
        "The proposal's payouts and paid state are replaced. Authorization must be zero. Does not store evidence or authorize mining.\n",
        {{"snapshot", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical unsigned proposal containing binding, selected templates and proofs"}},
        RPCResult{RPCResult::Type::OBJ, "", "Unsigned job requiring owner authorization", std::move(results)},
        RPCExamples{HelpExampleCli("preparesharepoolhashjob", "\"snapshot_hex\"")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            namespace ho = sharepool::hashonly;
            auto snapshot = ParseHashSnapshot(request.params[0]);
            if (snapshot.authorization != sharepool::Signature{}) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Proposal must have zero authorization");
            }
            auto& node = EnsureAnyNodeContext(request.context);
            auto& chainman = EnsureAnyChainman(request.context);
            CBlock block;
            CAmount reward{0};
            {
                LOCK(cs_main);
                auto& store = RequireHashSnapshotStore(chainman);
                const auto* tip = chainman.ActiveChain().Tip();
                const auto& consensus = chainman.GetConsensus();
                if (!tip || tip->nHeight + 1 < consensus.SharePoolHeight ||
                    snapshot.binding.height != uint32_t(tip->nHeight + 1) || snapshot.binding.native_parent != tip->GetBlockHash() ||
                    snapshot.binding.genesis != consensus.hashGenesisBlock || snapshot.binding.version != ho::ProfileVersion(consensus) ||
                    snapshot.binding.rules != ho::RulesHash(ho::ProfileVersion(consensus))) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Proposal must bind the current active tip and rules");
                }
                std::shared_ptr<const ho::Snapshot> parent;
                if (snapshot.binding.height > uint32_t(consensus.SharePoolHeight)) {
                    try { parent = store.Lookup(tip->m_mm_rhs); }
                    catch (const ho::MalformedSnapshot&) { throw JSONRPCError(RPC_VERIFY_REJECTED, "Malformed native parent settlement"); }
                    if (!parent) throw JSONRPCError(RPC_VERIFY_ERROR, "sharepool-hash-data-missing");
                }
                if (consensus.SharePoolAdmittedLedger) {
                    try { ho::ApplyLedgerState(snapshot, parent.get()); }
                    catch (const std::invalid_argument& error) { throw JSONRPCError(RPC_INVALID_PARAMETER, error.what()); }
                    catch (const std::ios_base::failure&) { throw JSONRPCError(RPC_INVALID_PARAMETER, "Confirmed ledger capacity reached; defer new admissions"); }
                } else {
                    snapshot.post_state.clear();
                    const auto minimum = std::max<int64_t>(consensus.SharePoolHeight, int64_t{snapshot.binding.height} - sharepool::MAX_SHARE_AGE);
                    if (parent) for (const auto& entry : parent->post_state) if (entry.origin_height >= minimum) snapshot.post_state.push_back(entry);
                    for (const auto& share : snapshot.shares) snapshot.post_state.push_back({share.origin.height, share.header.GetHash()});
                    std::sort(snapshot.post_state.begin(), snapshot.post_state.end(), [](const auto& a, const auto& b) {
                        return UintToArith256(a.proof_id) < UintToArith256(b.proof_id);
                    });
                }
                // Determine scripts before selecting transactions. Reserve a conservative
                // full coinbase (100-byte scriptSig and witness commitment), v2 header
                // and maximum CompactSize transaction counts. Final native validation
                // enforces the actual contextual weight, size and sigop limits.
                snapshot.payouts = ho::CalculatePayouts(snapshot, 0);
                size_t output_bytes{0};
                for (const auto& output : snapshot.payouts) output_bytes += GetSerializeSize(output);
                const size_t base_bytes = 164 + 9 + 4 + 1 + 36 + 1 + 100 + 4 + 9 + output_bytes + 47 + 4;
                const size_t reserved_weight = base_bytes * WITNESS_SCALE_FACTOR + 36;
                if (base_bytes + 36 > MAX_BLOCK_SERIALIZED_SIZE || reserved_weight > MAX_BLOCK_WEIGHT) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Settlement payouts exceed native block capacity");
                }
                BlockAssembler::Options options;
                node::ApplyArgsManOptions(*node.args, options);
                options.test_block_validity = false; // Incomplete until exact reward and signature are bound.
                options.coinbase_output_script = CScript{snapshot.binding.payout_script.begin(), snapshot.binding.payout_script.end()};
                options.block_reserved_size = std::max(options.block_reserved_size, base_bytes + 36);
                options.block_reserved_weight = std::max(options.block_reserved_weight, reserved_weight);
                const auto assembled = BlockAssembler(chainman.ActiveChainstate(), node.mempool.get(), options, node).CreateNewBlock();
                block = assembled->block;
                reward = block.vtx.at(0)->GetValueOut();
                snapshot.payouts = ho::CalculatePayouts(snapshot, reward);
                CMutableTransaction coinbase{*block.vtx.at(0)};
                coinbase.vout = snapshot.payouts;
                block.vtx[0] = MakeTransactionRef(std::move(coinbase));
                chainman.GenerateCoinbaseCommitment(block, tip);
                block.hashMerkleRoot = BlockMerkleRoot(block);
                snapshot.job_commitment = ho::JobHash(block);
                block.m_mm_rhs = ho::SnapshotHash(snapshot);
            }
            const auto overlay = std::make_shared<const ho::Snapshot>(snapshot);
            const auto checked = PrepareSharePoolHashOrigins(chainman, block, overlay, nullptr, true, true);
            {
                LOCK(cs_main);
                RequireHashSnapshotStore(chainman);
                if (checked.IsMissing()) throw JSONRPCError(RPC_VERIFY_ERROR, "sharepool-hash-data-missing");
                if (!checked.IsValid()) throw JSONRPCError(RPC_VERIFY_REJECTED, checked.reason);
                if (chainman.ActiveChain().Tip()->GetBlockHash() != block.hashPrevBlock) {
                    throw JSONRPCError(RPC_VERIFY_ERROR, "Native tip changed; prepare a new job");
                }
            }
            auto result = HashJobResult(block, snapshot, reward);
            DataStream payload;
            payload << snapshot.binding << snapshot.job_commitment << ho::SnapshotContentsHash(snapshot);
            result.pushKV("signing_payload", HexStr(payload));
            result.pushKV("signing_hash", ho::OwnerHash(snapshot).GetHex());
            return result;
        }};
}

static RPCHelpMan finalizesharepoolhashjob()
{
    return RPCHelpMan{"finalizesharepoolhashjob",
        "Bind an externally signed complete snapshot to a prepared native template and fully validate it.\n"
        "Changing any job body bytes requires new authorization. Does not store evidence, publish or dispatch mining work.\n",
        {{"template", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Prepared normalized full template"},
         {"snapshot", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Complete owner-signed snapshot"}},
        RPCResult{RPCResult::Type::OBJ, "", "Fully verified job", HashJobResults()},
        RPCExamples{HelpExampleCli("finalizesharepoolhashjob", "\"template_hex\" \"snapshot_hex\"")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            namespace ho = sharepool::hashonly;
            const auto value = request.params[0].get_str();
            if (value.empty() || value.size() > 2 * ho::MAX_TEMPLATE_BYTES || !IsHex(value)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Template exceeds byte bound or is not hexadecimal");
            }
            CBlock block;
            try { block = ho::DecodeTemplate(ParseHex(value)); }
            catch (const std::exception&) { throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Noncanonical or malformed template"); }
            const auto snapshot = std::make_shared<const ho::Snapshot>(ParseHashSnapshot(request.params[1]));
            if (snapshot->job_commitment != ho::JobHash(block)) throw JSONRPCError(RPC_VERIFY_REJECTED, "bad-sharepool-hash-job-commitment");
            block.m_mm_rhs = ho::SnapshotHash(*snapshot);
            auto& chainman = EnsureAnyChainman(request.context);
            { LOCK(cs_main); RequireHashSnapshotStore(chainman); }
            const auto checked = PrepareSharePoolHashOrigins(chainman, block, snapshot, nullptr, false, true);
            {
                LOCK(cs_main);
                if (checked.IsMissing()) throw JSONRPCError(RPC_VERIFY_ERROR, "sharepool-hash-data-missing");
                if (!checked.IsValid()) throw JSONRPCError(RPC_VERIFY_REJECTED, checked.reason);
                if (!chainman.ActiveChain().Tip() || chainman.ActiveChain().Tip()->GetBlockHash() != block.hashPrevBlock) {
                    throw JSONRPCError(RPC_VERIFY_ERROR, "Native tip changed; prepare a new job");
                }
            }
            return HashJobResult(block, *snapshot, checked.expected_reward.value());
        }};
}

static RPCHelpMan submitsharepoolhashsnapshot()
{
    return RPCHelpMan{"submitsharepoolhashsnapshot",
        "Durably store a bounded hash-only snapshot preimage and retry dependent pending blocks.\n"
        "Storage establishes content identity. Complete validation checks canonical encoding and rules.\n",
        {{"snapshot", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Complete snapshot preimage, at most 16777216 bytes"}},
        RPCResult{RPCResult::Type::OBJ, "", "Content-addressed storage result", {
            {RPCResult::Type::STR_HEX, "hash", "Snapshot hash"},
            {RPCResult::Type::STR, "status", "stored or present"},
            {RPCResult::Type::ARR, "missing", "Required snapshot dependencies still missing", {
                {RPCResult::Type::STR_HEX, "", "Snapshot hash"}}},
        }}, RPCExamples{HelpExampleCli("submitsharepoolhashsnapshot", "\"snapshot_hex\"")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const auto value = request.params[0].get_str();
            if (value.empty() || value.size() > 2 * sharepool::hashonly::MAX_SNAPSHOT_BYTES || !IsHex(value)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Snapshot exceeds the snapshot byte bound or is not hexadecimal");
            }
            const auto raw = ParseHex(value);
            auto& chainman = EnsureAnyChainman(request.context);
            UniValue result{UniValue::VOBJ};
            {
                LOCK(cs_main);
                auto& store = RequireHashSnapshotStore(chainman);
                const auto hash = sharepool::hashonly::SnapshotHash(raw);
                const bool present = store.Has(hash);
                try { store.Put(raw, hash); }
                catch (const std::exception& e) { throw JSONRPCError(RPC_VERIFY_ERROR, e.what()); }
                result.pushKV("hash", hash.GetHex());
                result.pushKV("status", present ? "present" : "stored");
            }
            chainman.RequestSharePoolHashBlocks();
            {
                LOCK(cs_main);
                UniValue missing{UniValue::VARR};
                for (const auto& hash : RequireHashSnapshotStore(chainman).Needed()) missing.push_back(hash.GetHex());
                result.pushKV("missing", std::move(missing));
            }
            return result;
        }};
}

static RPCHelpMan getsharepoolhashsnapshot()
{
    return RPCHelpMan{"getsharepoolhashsnapshot", "Read the complete locally stored snapshot by hash.\n",
        {{"hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Snapshot hash"}},
        RPCResult{RPCResult::Type::OBJ, "", "Canonical snapshot", {
            {RPCResult::Type::STR_HEX, "hash", "Snapshot hash"},
            {RPCResult::Type::STR_HEX, "data", "Complete snapshot bytes"},
        }}, RPCExamples{HelpExampleCli("getsharepoolhashsnapshot", "\"snapshot_hash\"")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const auto hash = ParseHashV(request.params[0], "hash");
            auto& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            const auto raw = RequireHashSnapshotStore(chainman).GetShared(hash);
            if (!raw) throw JSONRPCError(RPC_VERIFY_ERROR, "sharepool-hash-data-missing");
            UniValue result{UniValue::VOBJ};
            result.pushKV("hash", hash.GetHex());
            result.pushKV("data", HexStr(*raw));
            return result;
        }};
}

static RPCHelpMan getsharepoolhashstatus()
{
    return RPCHelpMan{"getsharepoolhashstatus", "Read local hash-only snapshot availability. Stored objects are not mining authorizations.\n", {},
        RPCResult{RPCResult::Type::OBJ, "", "Local hash-only profile and storage", {
            {RPCResult::Type::STR, "mode", "hash-only-v4 or hash-only-v5-confirmed-ledger"},
            {RPCResult::Type::STR_HEX, "rules", "Canonical active-profile rule hash"},
            {RPCResult::Type::NUM, "activation_height", "First native height requiring the selected settlement profile"},
            {RPCResult::Type::NUM, "max_snapshot_bytes", "Per-snapshot byte bound"},
            {RPCResult::Type::NUM, "pending_blocks", "Blocks awaiting evidence"},
            {RPCResult::Type::NUM, "stored_snapshots", "Stored snapshot count"},
            {RPCResult::Type::NUM, "stored_bytes", "Local retained evidence bytes"},
            {RPCResult::Type::ARR, "inventory", "Available snapshot hashes", {{RPCResult::Type::STR_HEX, "", "Hash"}}},
            {RPCResult::Type::OBJ, "validation_worker", "Bounded asynchronous validation telemetry", {
                {RPCResult::Type::BOOL, "started", "Worker lifecycle started"},
                {RPCResult::Type::BOOL, "active", "A pending-block pass is running"},
                {RPCResult::Type::BOOL, "pending", "One coalesced notification is waiting"},
                {RPCResult::Type::BOOL, "stopping", "Shutdown requested"},
                {RPCResult::Type::NUM, "requests", "Notification count"},
                {RPCResult::Type::NUM, "passes", "Completed passes"},
                {RPCResult::Type::NUM, "failures", "Local worker exceptions"},
                {RPCResult::Type::NUM, "last_micros", "Last completed pass duration"},
                {RPCResult::Type::NUM, "max_micros", "Longest completed pass duration"},
                {RPCResult::Type::NUM, "outside_script_checks", "Origin input scripts executed without cs_main"},
                {RPCResult::Type::NUM, "locked_fallbacks", "Historical/local-budget synchronous origin fallbacks"},
                {RPCResult::Type::NUM, "context_retries", "Passes restarted because the native context changed"},
            }},
        }}, RPCExamples{HelpExampleCli("getsharepoolhashstatus", "")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            auto& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            auto& store = RequireHashSnapshotStore(chainman);
            UniValue result{UniValue::VOBJ};
            result.pushKV("mode", chainman.GetConsensus().SharePoolAdmittedLedger ? "hash-only-v5-confirmed-ledger" : "hash-only-v4");
            result.pushKV("rules", sharepool::hashonly::RulesHash(sharepool::hashonly::ProfileVersion(chainman.GetConsensus())).GetHex());
            result.pushKV("activation_height", chainman.GetConsensus().SharePoolHeight);
            result.pushKV("max_snapshot_bytes", sharepool::hashonly::MAX_SNAPSHOT_BYTES);
            result.pushKV("pending_blocks", store.PendingBlocks().size());
            result.pushKV("stored_snapshots", store.Count());
            result.pushKV("stored_bytes", store.Bytes() + store.TemplateBytes());
            UniValue inventory{UniValue::VARR};
            for (const auto& hash : store.Inventory()) inventory.push_back(hash.GetHex());
            result.pushKV("inventory", std::move(inventory));
            const auto stats = chainman.SharePoolHashWorkerStats();
            UniValue worker{UniValue::VOBJ};
            worker.pushKV("started", stats.started);
            worker.pushKV("active", stats.active);
            worker.pushKV("pending", stats.pending);
            worker.pushKV("stopping", stats.stopping);
            worker.pushKV("requests", stats.requests);
            worker.pushKV("passes", stats.passes);
            worker.pushKV("failures", stats.failures);
            worker.pushKV("last_micros", stats.last_micros);
            worker.pushKV("max_micros", stats.max_micros);
            worker.pushKV("outside_script_checks", chainman.m_sharepool_hash_outside_script_checks.load());
            worker.pushKV("locked_fallbacks", chainman.m_sharepool_hash_locked_fallbacks.load());
            worker.pushKV("context_retries", chainman.m_sharepool_hash_context_retries.load());
            result.pushKV("validation_worker", std::move(worker));
            return result;
        }};
}

static RPCHelpMan validatesharepoolhashtemplate()
{
    return RPCHelpMan{"validatesharepoolhashtemplate",
        "Validate a complete hash-only settlement template, its native transactions and its full snapshot dependencies.\n"
        "Checks exact subsidy plus fees and payout scripts. Requires an eligible active-chain parent.\n"
        "Physical search fields are normalized; candidate proof of work is not required. Does not publish a block or authorize mining.\n",
        {{"template", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical full template, at most 4000000 bytes"},
         {"snapshot", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional complete snapshot: validate in memory without admitting snapshot/template evidence"},
         {"mining", RPCArg::Type::BOOL, RPCArg::Default{true}, "Reserve capacity for newly dispatched work; false checks historical block validity only"}},
        RPCResult{RPCResult::Type::OBJ, "", "Verified native context", {
            {RPCResult::Type::BOOL, "valid", "True after complete validation"},
            {RPCResult::Type::STR_HEX, "native_tip", "Active native tip"},
            {RPCResult::Type::STR_HEX, "native_parent", "Active parent of the origin"},
            {RPCResult::Type::NUM, "origin_height", "Template height"},
            {RPCResult::Type::STR_HEX, "commitment", "Complete snapshot hash"},
        }}, RPCExamples{HelpExampleCli("validatesharepoolhashtemplate", "\"template_hex\"")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const auto value = request.params[0].get_str();
            if (value.empty() || value.size() > 2 * sharepool::hashonly::MAX_TEMPLATE_BYTES || !IsHex(value)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Template exceeds the snapshot byte bound or is not hexadecimal");
            }
            CBlock block;
            try {
                const auto raw = ParseHex(value);
                block = sharepool::hashonly::DecodeBlock(raw);
                // This RPC validates the underlying mining template. Physical
                // search fields are excluded from its exact job signature and
                // are checked separately when validating a submitted proof.
                block.nNonce = block.m_nonce2 = block.m_nonce3 = block.m_time_offset = 0;
                block.m_extranonce.SetNull();
            } catch (const std::exception&) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Noncanonical or malformed hash-only template");
            }
            std::shared_ptr<const sharepool::hashonly::Snapshot> overlay;
            if (!request.params[1].isNull()) {
                const auto value = request.params[1].get_str();
                if (value.empty() || value.size() > 2 * sharepool::hashonly::MAX_SNAPSHOT_BYTES || !IsHex(value)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Snapshot exceeds byte bound or is not hexadecimal");
                }
                try {
                    const auto raw = ParseHex(value);
                    if (sharepool::hashonly::SnapshotHash(raw) != block.m_mm_rhs) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Snapshot does not match template commitment");
                    }
                    overlay = std::make_shared<const sharepool::hashonly::Snapshot>(sharepool::hashonly::DecodeSnapshot(raw));
                } catch (const std::exception&) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Noncanonical or malformed snapshot");
                }
            }
            auto& chainman = EnsureAnyChainman(request.context);
            uint256 captured_tip;
            {
                LOCK(cs_main);
                RequireHashSnapshotStore(chainman);
                if (const auto* tip = chainman.ActiveChain().Tip()) captured_tip = tip->GetBlockHash();
            }
            const bool mining = request.params[2].isNull() || request.params[2].get_bool();
            const auto checked = !mining && chainman.GetConsensus().SharePoolAdmittedLedger
                ? ValidateSharePoolHashHistoricalTemplateUnlocked(chainman, block, overlay)
                : PrepareSharePoolHashOrigins(chainman, block, overlay, nullptr, false, mining);
            LOCK(cs_main);
            auto& store = RequireHashSnapshotStore(chainman);
            const auto& consensus = chainman.GetConsensus();
            const auto* tip = chainman.ActiveChain().Tip();
            const auto* parent = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
            if (!tip || tip->GetBlockHash() != captured_tip) throw JSONRPCError(RPC_VERIFY_ERROR, "Native tip changed during validation");
            if (!tip || !parent || !chainman.ActiveChain().Contains(parent) ||
                parent->nHeight + 1 < consensus.SharePoolHeight ||
                tip->nHeight - parent->nHeight > int(sharepool::MAX_SHARE_AGE)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Template parent is not an eligible active native ancestor");
            }
            const auto require = [&](const sharepool::hashonly::Result& result) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
                if (!overlay) { RequireHashValidation(store, result); return; }
                if (result.IsMissing()) throw JSONRPCError(RPC_VERIFY_ERROR, "sharepool-hash-data-missing");
                if (!result.IsValid()) throw JSONRPCError(RPC_VERIFY_REJECTED, result.reason);
            };
            require(checked);
            if (!overlay) store.RememberTemplate(block);
            UniValue result{UniValue::VOBJ};
            result.pushKV("valid", true);
            result.pushKV("native_tip", tip->GetBlockHash().GetHex());
            result.pushKV("native_parent", parent->GetBlockHash().GetHex());
            result.pushKV("origin_height", parent->nHeight + 1);
            result.pushKV("commitment", block.m_mm_rhs.GetHex());
            return result;
        }};
}

static RPCHelpMan validatesharepoolhashshare()
{
    return RPCHelpMan{"validatesharepoolhashshare",
        "Verify a canonical hash-only proof, owner signature, full origin and its snapshot dependencies.\n"
        "Does not pay, acknowledge, or publish work. Settlement separately enforces no repeat payment.\n",
        {{"share", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical share, at most 1024 bytes"}},
        RPCResult{RPCResult::Type::OBJ, "", "Verified proof and native context", {
            {RPCResult::Type::BOOL, "valid", "True after full proof verification"},
            {RPCResult::Type::STR_HEX, "proof_id", "Native proof hash"},
            {RPCResult::Type::STR_HEX, "payout_script", "Authorized payout script"},
            {RPCResult::Type::STR_HEX, "pool", "Pool ID"},
            {RPCResult::Type::STR_HEX, "native_tip", "Active native tip"},
            {RPCResult::Type::STR_HEX, "native_parent", "Active parent of the origin"},
            {RPCResult::Type::NUM, "origin_height", "Origin height"},
        }}, RPCExamples{HelpExampleCli("validatesharepoolhashshare", "\"share_hex\"")},
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const auto value = request.params[0].get_str();
            if (value.empty() || value.size() > 2048 || !IsHex(value)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Share exceeds 1024 bytes or is not hexadecimal");
            }
            sharepool::Share share;
            try {
                const auto raw = ParseHex(value);
                DataStream stream{raw};
                stream >> share;
                DataStream canonical;
                canonical << share;
                if (!stream.empty() || HexStr(canonical) != HexStr(raw)) throw std::runtime_error("noncanonical share");
            } catch (const std::exception&) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Noncanonical or malformed hash-only share");
            }
            auto& chainman = EnsureAnyChainman(request.context);
            uint256 captured_tip;
            {
                LOCK(cs_main);
                RequireHashSnapshotStore(chainman);
                const auto* tip = chainman.ActiveChain().Tip();
                if (!tip || tip->nHeight + 1 < chainman.GetConsensus().SharePoolHeight) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Hash-only settlement is not active at the current tip");
                }
                captured_tip = tip->GetBlockHash();
            }
            const auto checked = ValidateSharePoolHashProofUnlocked(chainman, share);
            LOCK(cs_main);
            auto& store = RequireHashSnapshotStore(chainman);
            const auto* tip = chainman.ActiveChain().Tip();
            if (!tip || tip->GetBlockHash() != captured_tip) throw JSONRPCError(RPC_VERIFY_ERROR, "Native tip changed during validation");
            RequireHashValidation(store, checked);
            UniValue result{UniValue::VOBJ};
            result.pushKV("valid", true);
            result.pushKV("proof_id", share.header.GetHash().GetHex());
            result.pushKV("payout_script", HexStr(share.origin.payout_script));
            result.pushKV("pool", share.origin.pool.GetHex());
            result.pushKV("native_tip", tip->GetBlockHash().GetHex());
            result.pushKV("native_parent", share.header.hashPrevBlock.GetHex());
            result.pushKV("origin_height", share.origin.height);
            return result;
        }};
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
        {"mining", &validatesharepoolshare},
        {"mining", &validatesharepooltemplate},
        {"mining", &setsharepoolrelay},
        {"mining", &submitsharepoolevidence},
        {"mining", &getsharepoolinventory},
        {"mining", &getsharepoolobject},
        {"mining", &submitsharepoolhashsnapshot},
        {"mining", &preparesharepoolhashjob},
        {"mining", &finalizesharepoolhashjob},
        {"mining", &getsharepoolhashsnapshot},
        {"mining", &getsharepoolhashstatus},
        {"mining", &validatesharepoolhashtemplate},
        {"mining", &validatesharepoolhashshare},

        {"hidden", &generatetoaddress},
        {"hidden", &generatetodescriptor},
        {"hidden", &generateblock},
        {"hidden", &generate},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
