// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/coin.h>

#include <node/context.h>
#include <txmempool.h>
#include <validation.h>

namespace node {
void FindCoins(const NodeContext& node, std::map<COutPoint, Coin>& coins)
{
    assert(node.mempool);
    assert(node.chainman);
    LOCK2(cs_main, node.mempool->cs);
    CCoinsViewCache& chain_view = node.chainman->ActiveChainstate().CoinsTip();
    const int height{node.chainman->ActiveChain().Height() + 1};
    const std::optional<int> relock_height{height >= node.chainman->GetConsensus().CoinbaseRelockHeight
        ? std::optional<int>{height} : std::nullopt};
    CCoinsViewMemPool mempool_view(&chain_view, *node.mempool, relock_height);
    for (auto& [outpoint, coin] : coins) {
        if (auto c{mempool_view.GetCoin(outpoint)}) {
            coin = std::move(*c);
        } else {
            coin.Clear(); // Either the coin is not in the CCoinsViewCache or is spent
        }
    }
}
} // namespace node
