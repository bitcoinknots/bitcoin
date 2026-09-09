# Share-pool feasibility experiment

This directory is a **synthetic commitment experiment**, not a working pool.
See [the protocol draft](../../doc/sharepool-design.md) for the proposed system,
unresolved rules, and limitations.

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
