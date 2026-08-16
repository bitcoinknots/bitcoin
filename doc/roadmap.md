# Bitcoin Purity roadmap

## Short-term (this tree)

See [purity-consensus.md](purity-consensus.md).

1. Rebrand the node as Bitcoin Purity (documentation and `CLIENT_NAME`).
2. Make BIP110/RDTS rules permanently active; remove the opt-out.
3. Switch difficulty adjustment to 24-hour ASERT (`aserti3-1d`), anchor
   enforcement-chain block 961632. Keep SHA256d.
4. Enable Bitcoin Cash Node-style deep-reorg parking (depth greater than 6).
5. Specify automatic double-spend freeze; **do not implement it yet**.

No replay protection.

## Later (not scheduled, not implemented)

These items are product direction only. They have no activation height and
must not be treated as incomplete bugs in the current node.

1. SEAL-2 block header.
2. Remove Taproot, and possibly Segwit.
3. Post-quantum signatures and 32 MB block size.

Work on those requires a new consensus document and an explicit decision to
implement.
