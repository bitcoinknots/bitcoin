# Bitcoin Purity Versioning and User Agent Specification

## 1. Purpose

This document defines the versioning and user-agent conventions used by Bitcoin Purity.

The goals are to:

- clearly distinguish Bitcoin Purity from Bitcoin Knots, Bitcoin Core, and other Bitcoin implementations;
- preserve traceability to the upstream Bitcoin Knots version;
- explicitly indicate that the codebase and core consensus rules are derived from Bitcoin Core 29.4;
- provide predictable version ordering for users, package managers, build systems, and release tooling;
- avoid using the P2P user agent as a protocol compatibility mechanism;
- maintain a stable convention as Bitcoin Purity evolves independently.

---

## 2. Version Concepts

Bitcoin Purity uses several different version identifiers. They MUST NOT be treated as interchangeable.

The relevant identifiers are:

1. **Bitcoin Purity release version**
2. **Upstream Bitcoin Knots base version**
3. **Bitcoin Core consensus baseline**
4. **Git release tag**
5. **P2P user agent (`subver`)**
6. **P2P protocol version**
7. **Build metadata**

Each identifier serves a different purpose.

---

# 3. Bitcoin Purity Release Version

Bitcoin Purity SHALL maintain its own independent release version.

The canonical format is:

```text
MAJOR.MINOR.PATCH
```

Example:

```text
1.0.0
1.0.1
1.1.0
2.0.0
```

The Bitcoin Purity release version is independent of the upstream Bitcoin Knots version.

For example:

```text
Bitcoin Purity: 1.2.0
Based on Bitcoin Knots: 29.4.0
Bitcoin Core consensus baseline: 29.4
```

The upstream Bitcoin Knots version MUST NOT be used as the primary Bitcoin Purity release version.

---

# 4. Version Increment Rules

## 4.1 PATCH

Increment `PATCH` for compatible maintenance releases.

Examples:

```text
1.0.0 -> 1.0.1
1.0.1 -> 1.0.2
```

Typical PATCH changes include:

- bug fixes;
- build fixes;
- packaging fixes;
- GUI fixes;
- logging improvements;
- documentation changes;
- performance improvements;
- non-consensus RPC fixes;
- low-risk networking fixes;
- security fixes that do not intentionally change consensus or major externally visible behavior.

A PATCH release SHOULD remain operationally compatible with other releases in the same MINOR series.

---

## 4.2 MINOR

Increment `MINOR` for significant feature or policy releases that remain within the same general Bitcoin Purity protocol generation.

Examples:

```text
1.0.3 -> 1.1.0
1.1.4 -> 1.2.0
```

Typical MINOR changes include:

- new RPC methods;
- significant wallet changes;
- new mining functionality;
- significant P2P functionality;
- mempool policy changes;
- new configuration interfaces;
- major performance improvements;
- adoption of substantial upstream Bitcoin Knots functionality.

A MINOR release MAY contain changes that alter node policy but SHOULD NOT normally represent a deliberately incompatible Bitcoin Purity consensus generation.

---

## 4.3 MAJOR

Increment `MAJOR` when Bitcoin Purity introduces a major protocol or consensus generation change.

Examples:

```text
1.4.2 -> 2.0.0
```

A MAJOR release SHOULD be considered when introducing changes such as:

- intentionally incompatible consensus rules;
- a hard fork requiring coordinated node upgrades;
- fundamental changes to block validation;
- fundamental changes to difficulty adjustment;
- major changes to transaction validity;
- major changes to the network's long-term consensus model.

Not every consensus-related code change necessarily requires a MAJOR increment. The release maintainers determine whether the change represents a new Bitcoin Purity protocol generation.

---

# 5. Upstream Bitcoin Knots and Bitcoin Core Consensus Baseline

Bitcoin Purity SHALL separately record the upstream Bitcoin Knots release or commit from which it is derived.

The current upstream baseline is:

```text
Bitcoin Knots 29.4.0
```

Bitcoin Purity SHALL also record the corresponding Bitcoin Core consensus baseline:

```text
Bitcoin Core 29.4
```

The upstream relationship SHOULD be displayed as:

```text
Bitcoin Purity version v1.0.0
Based on Bitcoin Knots 29.4.0
Bitcoin Core consensus baseline 29.4
```

This means that Bitcoin Purity's codebase and core consensus rules are derived from Bitcoin Core 29.4 through the Bitcoin Knots 29.4.0 codebase.

Where appropriate, development builds MAY additionally record the upstream Git commit:

```text
Upstream Bitcoin Knots: v29.4.0
Bitcoin Core consensus baseline: 29.4
Upstream commit: <commit hash>
```

The upstream version is informational and SHALL NOT determine the Bitcoin Purity release number.

---

# 6. Git Tags

Official Bitcoin Purity releases SHALL use Git tags in the following format:

```text
vMAJOR.MINOR.PATCH
```

Examples:

```text
v1.0.0
v1.0.1
v1.1.0
v2.0.0
```

Release candidates SHALL use:

```text
vMAJOR.MINOR.PATCHrcN
```

Examples:

```text
v1.1.0rc1
v1.1.0rc2
v2.0.0rc1
```

The final release MUST NOT contain the `rc` suffix.

Example sequence:

```text
v1.1.0rc1
v1.1.0rc2
v1.1.0rc3
v1.1.0
```

---

# 7. Development Builds

Non-release development builds SHOULD be clearly distinguishable from official releases.

Recommended formats include:

```text
1.1.0-dev
```

or:

```text
1.1.0-dev-<git-short-hash>
```

Example:

```text
1.1.0-dev-a83f921
```

A development build MUST NOT identify itself as an official release if its source tree differs from the tagged release.

---

# 8. `bitcoind --version`

The command:

```text
bitcoind --version
```

SHOULD identify Bitcoin Purity, its upstream Bitcoin Knots base, and its Bitcoin Core consensus baseline.

Recommended output:

```text
Bitcoin Purity Daemon version v1.0.0
Based on Bitcoin Knots 29.4.0
Bitcoin Core consensus baseline 29.4
```

Additional copyright and licensing information MAY follow.

The first line MUST identify the software as Bitcoin Purity rather than Bitcoin Knots or Bitcoin Core.

---

# 9. GUI Version Display

The GUI About dialog SHOULD display:

```text
Bitcoin Purity
Version 1.0.0
Based on Bitcoin Knots 29.4.0
Bitcoin Core consensus baseline 29.4
```

Bitcoin Knots and Bitcoin Core attribution and copyright notices SHALL continue to be retained where required by the applicable licenses.

---

# 10. P2P User Agent

Bitcoin Purity SHALL identify itself on the Bitcoin P2P network using the BIP 14 user-agent mechanism.

The canonical user-agent string SHALL be:

```text
/Satoshi:29.4/Purity:MAJOR.MINOR.PATCH/
```

Example:

```text
/Satoshi:29.4/Purity:1.0.0/
```

Subsequent releases:

```text
/Satoshi:29.4/Purity:1.0.1/
/Satoshi:29.4/Purity:1.1.0/
/Satoshi:29.4/Purity:2.0.0/
```

The `/Satoshi:29.4/` component indicates that Bitcoin Purity is based on the Bitcoin Core 29.4 code and core consensus baseline.

The `/Purity:MAJOR.MINOR.PATCH/` component identifies the independent Bitcoin Purity release version.

Bitcoin Purity MUST use the exact capitalization and component order shown above for official production releases:

```text
/Satoshi:29.4/Purity:x.x.x/
```

Bitcoin Purity SHOULD NOT use:

```text
/BitcoinPurity:1.0.0/
```

as its canonical production user agent, because the required user-agent format explicitly preserves the Bitcoin Core 29.4 baseline through the `/Satoshi:29.4/` component.

---

# 11. User-Agent Comments

Optional BIP 14 comments MAY be appended where necessary.

For example:

```text
/Satoshi:29.4/Purity:1.0.0(test)/
```

However, official production releases SHOULD normally use the simplest canonical form:

```text
/Satoshi:29.4/Purity:1.0.0/
```

Build dates, Git commits, operating systems, and architecture information SHOULD NOT normally be placed in the P2P user agent.

The upstream baseline is already represented by `/Satoshi:29.4/`, while the Bitcoin Purity release is represented by `/Purity:x.x.x/`.

Additional build information belongs in build metadata or local version output.

This keeps the network identifier short, stable, and privacy-preserving.

---

# 12. P2P Protocol Version

The Bitcoin P2P protocol version is distinct from the Bitcoin Purity software version.

For example:

```json
{
  "version": 70016,
  "subver": "/Satoshi:29.4/Purity:1.0.0/"
}
```

In this example:

```text
70016
```

is the P2P protocol version.

It is NOT the Bitcoin Purity release version.

The protocol version SHALL only be changed when required by actual P2P protocol behavior.

It MUST NOT be incremented merely because a new Bitcoin Purity software release is published.

---

# 13. User Agent MUST NOT Determine Consensus

Bitcoin Purity implementations MUST NOT determine consensus validity based on the remote node's user-agent string.

For example, code MUST NOT implement logic equivalent to:

```text
if peer.subver == "/Satoshi:29.4/Purity:1.0.0/"
    accept block
else
    reject block
```

The user agent is informational only.

The `/Satoshi:29.4/` component indicates the intended upstream code and consensus baseline, but it does not prove that a remote node is running compatible consensus rules.

Consensus compatibility MUST be determined through consensus rules and, where applicable, explicitly designed protocol mechanisms.

Similarly, peer banning, block validity, transaction validity, and chain selection MUST NOT depend solely on a peer's advertised user agent.

---

# 14. Network Crawlers and Node Identification

Network monitoring tools MAY use the following prefix to identify Bitcoin Purity nodes:

```text
/Satoshi:29.4/Purity:
```

For example:

```text
/Satoshi:29.4/Purity:1.0.0/
/Satoshi:29.4/Purity:1.1.2/
```

may both be categorized as Bitcoin Purity implementations based on the Bitcoin Core 29.4 baseline.

The `/Satoshi:29.4/` component MAY be used to identify the upstream Bitcoin Core consensus baseline.

The `/Purity:x.x.x/` component MAY be used for Bitcoin Purity software-version statistics.

Neither component SHOULD be assumed to prove complete consensus compatibility without additional information.

---

# 15. Release Metadata

Every official Bitcoin Purity GitHub release SHOULD record at least:

```text
Bitcoin Purity version:
1.0.0

Upstream Bitcoin Knots:
29.4.0

Bitcoin Core consensus baseline:
29.4

Git tag:
v1.0.0

P2P user agent:
/Satoshi:29.4/Purity:1.0.0/

Consensus status:
<description>

Recommended upgrade:
Yes / No / Required
```

For consensus-sensitive releases, release notes SHOULD explicitly state:

- whether consensus rules changed;
- whether the Bitcoin Core 29.4 consensus baseline remains unchanged;
- whether old Bitcoin Purity nodes remain consensus-compatible;
- activation height or activation condition, if applicable;
- whether miners must upgrade;
- whether ordinary full nodes must upgrade;
- whether wallets are affected.

---

# 16. Example Release

A hypothetical Bitcoin Purity release may therefore appear as follows:

```text
Product:
Bitcoin Purity

Release:
1.2.0

Git tag:
v1.2.0

Upstream:
Bitcoin Knots 29.4.0

Bitcoin Core consensus baseline:
29.4

P2P user agent:
/Satoshi:29.4/Purity:1.2.0/

P2P protocol version:
70016
```

The corresponding peer information may appear as:

```json
{
  "version": 70016,
  "subver": "/Satoshi:29.4/Purity:1.2.0/"
}
```

and:

```text
bitcoind --version
```

may return:

```text
Bitcoin Purity Daemon version v1.2.0
Based on Bitcoin Knots 29.4.0
Bitcoin Core consensus baseline 29.4
```

---

# 17. Upstream Rebase Example

Suppose Bitcoin Purity `1.2.0` is based on Bitcoin Knots `29.4.0` and therefore uses the Bitcoin Core `29.4` consensus baseline.

The corresponding user agent is:

```text
/Satoshi:29.4/Purity:1.2.0/
```

If Bitcoin Purity later rebases onto a different upstream Bitcoin Knots release, the `/Satoshi:` component MUST be updated to reflect the new Bitcoin Core baseline.

For example, if a future release is based on Bitcoin Knots `30.2.0` and the corresponding Bitcoin Core baseline is `30.2`, the user agent may become:

```text
/Satoshi:30.2/Purity:1.3.0/
```

The Bitcoin Purity release version remains independent:

```text
Bitcoin Purity 1.3.0
Based on Bitcoin Knots 30.2.0
Bitcoin Core consensus baseline 30.2
```

It SHOULD NOT automatically become:

```text
30.2
```

or:

```text
30.2-purity
```

because the Bitcoin Core release series, Bitcoin Knots release series, and Bitcoin Purity release series represent different software projects.

---

# 18. Legacy Version Migration

Older Bitcoin Purity builds may use version identifiers derived directly from Bitcoin Core, for example:

```text
29.4.0.purity20260816
```

These SHALL be considered legacy Bitcoin Purity version identifiers.

Once the independent versioning convention is adopted, new releases SHOULD use:

```text
1.0.0
1.0.1
1.1.0
...
```

The first release using the new convention SHOULD clearly document the mapping between the old and new versions.

Example:

```text
Bitcoin Purity 1.0.0

Supersedes legacy build:
29.4.0.purity20260816

Upstream:
Bitcoin Knots 29.4.0

Bitcoin Core consensus baseline:
29.4

P2P user agent:
/Satoshi:29.4/Purity:1.0.0/
```

Thereafter, the legacy date-based version format SHOULD NOT be reused for official releases.

---

# 19. Canonical Summary

The canonical Bitcoin Purity versioning convention is:

```text
Software release:
1.0.0

Git tag:
v1.0.0

Upstream:
Bitcoin Knots 29.4.0

Bitcoin Core consensus baseline:
29.4

P2P user agent:
/Satoshi:29.4/Purity:1.0.0/

P2P protocol version:
70016
```

The `/Satoshi:29.4/` component indicates that Bitcoin Purity's codebase and core consensus rules are derived from Bitcoin Core 29.4 through Bitcoin Knots 29.4.0.

The `/Purity:1.0.0/` component identifies the independent Bitcoin Purity software release.

These identifiers have separate meanings and MUST remain logically independent.
