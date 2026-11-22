Consensus
---------

- Rolling coinbase maturity (1 year). On mainnet, from block 995000, every
  generated coin mined from block 979919 up to (not including) block 6930000,
  the first block without subsidy, must be buried 52560 blocks (365 days of
  144 blocks) before it can be spent. Each reward counts from its own block,
  so one reward unlocks per block. Rewards mined from 6930000 on return to
  ordinary 100-block maturity, and no covered reward is released early.

  The rule is decided by block heights alone and does not depend on RDTS. It is
  combined with the other maturity rules by taking the maximum, so it never
  shortens them. It activates before any covered reward reaches the 180-day
  maturity of the existing rule (979919 + 25920 = 1005839), so no reward that
  has become spendable is ever locked again. Relay policy applies the rolling
  depth to covered rewards as soon as this version runs.

  Upgrading nodes check every block from 995000 again using the existing
  chainstate revalidation, under the marker `rolling_coinbase_maturity_1y`.

  `getdeploymentinfo` reports the rule as `rolling_coinbase_maturity`, with
  `coinbase_start_height` and `coinbase_end_height`, and `getblocktemplate`
  lists `rolling_coinbase_maturity` in `rules` once it is active. Wallets and
  the GUI show the maturity that applies to each reward. Testnet4, signet and
  regtest are unchanged; regtest can opt in with
  `-testcoinbasematurityrolling=<activation_height>:<start_height>:<end_height>:<maturity>`.
