# Forward Reward Share

A consensus change that is disabled on every network. From
`forward_share_height`, every coinbase must pay `forward_share_bps` basis points
of the block **subsidy** to an output with one fixed script:

    <"FWD1"> OP_DROP OP_TRUE

Anyone can spend that output once coinbase maturity (100 blocks) has passed. In
practice the miner of a block about 100 blocks later spends it, collects its
value as a fee, and pays it to itself through its own coinbase.

It replaces an earlier Loyalty Tax design. That design paid a share of every
reward to a treasury script and confiscated the whole reward from coinbases
without an `OP_RETURN` tag.

## What changed from Loyalty Tax, and why

| Loyalty Tax | Forward Reward Share | Review point addressed |
|---|---|---|
| Share paid to a treasury script set in chain params | Share paid to an anyone-can-spend output, which later miners collect | Whoever held the treasury key would be paid on every block without mining |
| Whole reward confiscated if the coinbase lacked an `OP_RETURN LOY1` tag | No tag, no confiscation | The tag declared nothing, since every miner would carry it, and confiscation punished a missing tag rather than any behaviour |
| Tax on subsidy plus fees | Share of the subsidy only | Claimed shares arrive as fees, so fees are not forwarded again |
| `getblocktemplate` reported only the first coinbase output as `coinbasevalue` | `coinbasevalue` is the whole reward, and `forwardshare` names the required output | External template users could not build a valid coinbase |

The rule applies identically to every miner. No party receives anything
without mining a block. Total issuance and the subsidy schedule are unchanged;
part of each subsidy is simply paid about 100 blocks later, to whoever mines
then.

## Mining

- The reference miner adds the forward share output to its coinbase.
- It claims the shares of the block exactly `COINBASE_MATURITY` blocks back and
  of up to five blocks before that, if still unspent. Claims are added before
  mempool transactions, so block weight and sigop limits account for them.
- A claim is one transaction spending the matured share outputs of one earlier
  coinbase, with a single empty `OP_RETURN` output. Its whole input value is fee.
- `getblocktemplate` lists claim transactions under `transactions`, with their
  fee. Its `forwardshare` object gives the script and minimum amount the
  coinbase must include.

## Regtest

    bitcoind -regtest -forwardshareheight=<height> -forwardsharebps=<bps>

## Limitations

- **It still takes part of what a miner earns.** The share goes to a future
  miner rather than to a treasury, but the miner who found the block does not
  keep it.
- **Claims can be sniped.** Claim transactions are non-standard and are not
  relayed, but any miner can include one. Whoever mines the first block after
  maturity usually collects the share.
- **Reorg incentive.** A block that claims a share is worth slightly more than
  one that doesn't, and the gap grows with `forward_share_bps`.
- **Disk reads while building templates.** Finding claimable shares reads up to
  six earlier blocks from disk under `cs_main` for each template.
- **No activation.** No height is set for mainnet, testnet, testnet4 or signet.

## Testing

`test/functional/feature_forward_share.py` covers:
- no forwarding before activation
- the reference miner's forwarded share, and `getblocktemplate`'s `forwardshare` and `coinbasevalue`
- rejecting coinbases that forward nothing or one satoshi too little, and accepting a hand-built coinbase that forwards exactly the share
- the share staying unspent until maturity
- the template claiming it, the claim block's fee and coinbase value, and a hand-built block's share being claimed the same way
