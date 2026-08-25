// Copyright (c) 2026-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_SIGHASH_RULES_H
#define BITCOIN_COMMON_SIGHASH_RULES_H

#include <script/interpreter.h>

class ArgsManager;
namespace Consensus {
struct Params;
}

/** Default for -walletoldsigs */
static constexpr bool DEFAULT_WALLET_OLD_SIGS{false};

/** Register -walletoldsigs, so every binary that signs describes it the same way. */
void SetupSighashRulesArgs(ArgsManager& argsman);

/** Which signature hash rules this node signs under.
 *
 * Wherever the fork is scheduled, without asking how far along the chain is. The
 * height is a question about a block, and a signature is not in one yet: a node
 * whose blocks lag would answer it from a stale tip and sign away its own replay
 * protection quietly. Software carrying this rule is run for the fork, so being
 * scheduled is the whole answer. A signature made ahead of the height relays and
 * waits in the mempool until a block can carry it.
 *
 * Where the fork is not scheduled at all there is nothing to opt into.
 *
 * -walletoldsigs signs the legacy message instead, for a signer that has to
 * interoperate with software which does not know the fork, and for a test that
 * wants a legacy signature.
 *
 * Deliberately not in policy/, which the kernel compiles: this reads the command
 * line, and the kernel does not link it. */
SighashRules SighashRulesForSigning(const ArgsManager& args, const Consensus::Params& params);

#endif // BITCOIN_COMMON_SIGHASH_RULES_H
