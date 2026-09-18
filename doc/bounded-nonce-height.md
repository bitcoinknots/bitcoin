# BoundNonceHeight

Flag-day consensus change on the Bitcoin Knots BLAKE2b chain (header v2, Knots #359).

Remote hashing without the transaction list is invalid.
Remote hashing with the transaction list is valid and expensive in proportion to distance.
A template produced by pool software on the same local network as the hardware remains valid.
This document does not identify who built the template. It specifies which preimages are legal.

## Current behavior (#359)

Header v2 is 164 bytes. Proof of work is BLAKE2b. Mining hardware is given an 80-byte work buffer: previous block hash, an 8-byte nonce, nTime, and a work root that includes a 12-byte extranonce.

Consensus also exposes nonce, nonce2, nonce3, and a 16-byte header extranonce.
For one merkle root and one transaction list, that is a very large set of legal preimages.

A peer can send merkle branches and coinbase halves without sending the transactions, and the hardware can still search for a long time. GetPoWHash accepts the result.

Header v2 is 164 bytes. Proof of work is BLAKE2b.
Mining hardware is given an 80-byte work buffer: previous block hash, an 8-byte nonce, nTime, and a work root that includes a 12-byte extranonce.
Consensus also exposes nonce, nonce2, nonce3, and a 16-byte header extranonce. For one merkle root and one transaction list, that is a very large set of legal preimages.
A peer can send merkle branches and coinbase halves without sending the transactions, and the hardware can still search for a long time. GetPoWHash accepts the result.
CheckBlock already requires that the merkle root match the transactions and that header height and transaction count match the body.

## Parameters

Consensus::Params:

* BoundNonceHeight
* nHeaderNonceBits — width of the only header field that may change while the transaction-list commitment stays fixed
* nMaxCoinbaseExtranonceBytes
* nMaxHeaderExtranonceBytes

nHeaderNonceBits is a constant chosen from measured hashrate so one fixed template is exhausted in about 10–20ms on current hardware.
Nodes do not check elapsed time.

## Header checks (CheckBlockHeader, GetPoWHash)

1. Version bit 31 still marks header v2.
2. At BoundNonceHeight, GetPoWHash uses the new preimage. Below that height, keep the current function.
3. After previous block hash, merkle root or transaction-list commitment, nBits, nTime, and the remaining non-nonce v2 fields are set, the variable nonce field is at most nHeaderNonceBits wide. Wider: bad-nonce-width.
4. GetPoWHash(header) < target.

A node that has only the header can verify these items. It cannot verify that the sender possessed the transactions at search time.

## Block checks (CheckBlock, ContextualCheckBlock)

5. Merkle root must equal the tree of the included transactions (bad-txnmrklroot).
6. Coinbase scriptSig extra-nonce length must be <= nMaxCoinbaseExtranonceBytes (bad-cb-extranonce).
7. The rollable prefix of the header extranonce must be <= nMaxHeaderExtranonceBytes. Any remaining bytes are fixed for that template.
8. Add a transaction-list commitment: a tagged hash of the txids in order, or of the serialized transactions. Store it in the header or in the work root. GetPoWHash includes it.
The connecting node computes the same value from the body it received. Mismatch: bad-txcommitment.
9. Time-offset and hasher time rolling must not add a wide variable field. At BoundNonceHeight, time-offset is fixed for a given template, or it counts against nHeaderNonceBits.
10. ASIC profile 0 work buffer uses an 8-byte nonce (nonce8, 2^64 values per extra-nonce2). At this height that field is reduced to nHeaderNonceBits, or profile 0 is invalid.
Leaving 64 free bits per extra-nonce2 preserves today’s preimage and this change has no effect.

A worker that has only merkle branches and coinbase halves cannot compute the transaction-list commitment and cannot produce a legal GetPoWHash. A worker that is sent the full transaction list can.
Sending that list across a high-latency path often enough to refresh a short nonce is costly. Sending it across a local network is not.

## Out of scope

No per-address share limit. No job-age field in the header. No manufacturer keys. No change to RDTS, difficulty interval, or the 164-byte header as an object.

## Compatibility

This is a hard fork. The current 80-byte Sia work buffer with a wide nonce will not satisfy GetPoWHash at BoundNonceHeight. Firmware that only increments nonce8 on one work root will not produce valid blocks.
Software that has the transaction list may compute a new work buffer each time extra-nonce or the transaction list changes.

## Adversarial cases

* Fat extra-nonce in coinbase or header: reject.
* Legal short nonce, commitment matches body: accept.
* One transaction altered, header commitment left unchanged: reject.
* Merkle branches plus coinbase halves, transactions omitted: cannot form a valid preimage.
* Full transaction list delivered to remote hardware, new template computed before the short nonce is exhausted: accept. Validity does not depend on IP address or latency.
* Template produced by pool software on the same local network as the hardware: accept. The block is indistinguishable from one produced by the miner’s node.

## What a node verifies

From the header: construction, nonce width, hash below target.
From the body: merkle root, extra-nonce length, transaction-list commitment, preimage includes that commitment.

The node does not verify where the template was built. It verifies that a block without the transaction list cannot be valid work, and that a block with the transaction list can.

