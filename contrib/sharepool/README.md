# Share-pool feasibility experiments

This directory is a **synthetic commitment experiment**, not a working pool.
See [the protocol draft](../../doc/sharepool-design.md) for the proposed system,
unresolved rules, and limitations.

In the proposed system, the pool coordinator supplies the snapshot commitment
for the mining job, and miners verify its supporting data locally before hashing.
The experiment demonstrates only how that supplied commitment binds the header;
it does not implement coordinator messages or miner-side proposal verification.
The broader objective is evidence of work on templates distinguished by node
coinbase tags. Identical non-coinbase transaction selections are permitted.
This experiment does not verify those tags or prove that miners independently
selected transactions or used DATUM.

From the repository root, with Python 3:

```sh
python3 contrib/sharepool/precommit_demo.py
python3 -m unittest discover -s contrib/sharepool -p 'test_*.py' -v
```

The experiment uses this checkout's upstream Python test-framework implementation
of the BLAKE2b header hash. It demonstrates that an immutable example snapshot can
be committed in `m_mm_rhs` before hashing, and that changing the commitment
changes the hash. A changed hash must be checked against the target anew; it is
not mathematically guaranteed to fail an easy target.

Opaque example records are not actual validated miner shares. The synthetic
header has no complete block or chain context. No networking, round persistence,
payouts, consensus rules, or live/regtest acceptance are implemented or tested.
The zero XOR key also does not exercise hidden-key pool protection.

`work_concentration.py` implements the exact arithmetic predicate for the user's
10% limit: `total_work > 0` and `10 * group_work <= total_work` for every group.
It operates on supplied credited-share records for one pool and window. Its
result does not verify PoW, authenticate a coinbase tag, check target assignment,
select a window, or establish that the records include all eligible pool work.
The draft groups refreshed jobs by their stable coinbase node identifier.

This concentration check is not wired into Knots block validation. The test
fixtures exercise the arithmetic and duplicate handling, not a live mining pool.
