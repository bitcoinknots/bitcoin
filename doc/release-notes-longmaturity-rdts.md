Long coinbase maturity: four periods, extending RDTS
---------------------------------------------------

RDTS is unchanged. This softfork adds four coinbase-maturity periods on top of it, from the 45-day rule Knots 29.4.2 already enforces through RDTS expiry. Every RDTS rule remains in force until a block's parent median time past reaches 2027 September 1st 00:00 UTC.

The periods use the 10-minute target (144 blocks per day). Lengths end in 0 or 5, except the last, which is however many blocks are left until RDTS expires:

* 45 days, blocks 973440–979919, spendable from block 979920. This is the rule 29.4.2 already enforces.
* 105 days, blocks 979920–995039, spendable from block 995040.
* 105 days, blocks 995040–1010159, spendable from block 1010160.
* The blocks from 1010160 on, spendable from the first block whose parent median time past has reached the RDTS expiry. That remainder is about 102–109 days.

After a period releases, its coinbases need the ordinary 100 confirmations. Through block 979919 the rules match 29.4.2. Block 979920 is the first 29.4.2 could accept and this version reject: 29.4.2 would allow a spend of any coinbase from block 973440 on, and this version still holds coinbases from block 979920 on. Miners and nodes need to upgrade before that block, expected between the 17th and the 24th of October.

A node that upgrades while the rule still applies rechecks the blocks it has not already validated under the rule. Knots 29.4.2 recorded that check through block 979919, so it rewinds to that block. A node with no such record (Bitcoin Core, or an earlier Knots) rewinds to block 973439. The rewind needs block and undo data back to that height; a pruned node may have to reindex. It does not keep growing after the release. Once the chain is more than one window of blocks past the last block the rule applied to, the node does not rewind from its tip and has to be restarted with -reindex-chainstate. Upgrading before block 979920 avoids the rewind.

The mempool and the wallet follow these same periods. `getdeploymentinfo` lists them under `long_coinbase_maturity` as `periods`, and reports the RDTS expiry as `expiry_time`. It no longer reports `height_end` or `maturity`. The regtest option `-testcoinbasematuritylong` is still one period, `<start_height>:<enforce_height>:<release_time>`.
