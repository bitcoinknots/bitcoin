### Batched extended coinbase maturity (temporary softfork)

Coinbase outputs created while this deployment is active use a longer
maturity that is *attached to the creating block*, not to the spend:

- 1/6 of window blocks (`(height - start) % 6 == 0`): 2016 confirmations
- 2/6 of window blocks (`% 6` in {1,2}): 8064 confirmations
- 1/2 of window blocks (`% 6` in {3,4,5}): 26280 confirmations

The assignment is by **block height**, so coinbase transaction size does
not change. There is no extra output and no DATUM/script change.

The window is the same shape as RDTS: first block whose parent MTP
reaches the start time, through the last block whose parent MTP is still
below the RDTS expiry. After expiry, **new** coinbases go back to the
ordinary 100-block maturity. Coinbases created *inside* the window keep
their 2016/8064/26280 lock until they actually mature — expiry does not
unlock them early.

Outputs created before activation are never affected.

Mainnet/testnet start time is unset in this patch (flag day later).
Regtest: `-extendedcoinbasematurity=<mtp>` requires `-rdtsexpiry` and
must precede it.
