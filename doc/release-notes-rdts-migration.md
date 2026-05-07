Notifications and chain state
-----------------------------

- A node enforcing the BIP110/RDTS mandatory-signaling rule now corrects chain
  state inherited from a client that was not enforcing RDTS. Such a data
  directory can contain blocks that violate the rule; normal startup does not
  re-validate inherited history, so at startup the node marks every offending
  block invalid (whether or not on the active chain) and reorganizes to the best
  valid chain, mirroring the approach used for BIP148. The verdict is derived
  from the stored block headers, so it requires no additional on-disk data and
  cannot misfire on a chain that was validated correctly. It covers the
  mandatory-signaling rule only; output-size and script-push violations are not
  header-derivable and remain a `-reindex-chainstate` matter. If the block
  data needed to rewind to an offending block has been pruned, the node refuses
  to start and asks the operator to `-reindex` rather than run on an invalid chain.
