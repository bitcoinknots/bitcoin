// Copyright (c) 2026-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/sighash_rules.h>

#include <common/args.h>
#include <consensus/params.h>
#include <deploymentstatus.h>
#include <util/translation.h>

void SetupSighashRulesArgs(ArgsManager& argsman)
{
    argsman.AddArg("-walletoldsigs",
                   strprintf("Sign with the legacy signature hash rather than the hardfork one, which gives up replay protection (default: %u)",
                             DEFAULT_WALLET_OLD_SIGS),
                   ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
}

SighashRules SighashRulesForSigning(const ArgsManager& args, const Consensus::Params& params)
{
    if (args.GetBoolArg("-walletoldsigs", DEFAULT_WALLET_OLD_SIGS)) return SighashRules::LEGACY;
    return DeploymentEnabled(params, Consensus::DEPLOYMENT_BLAKE2B) ? SighashRules::UNIFIED
                                                                    : SighashRules::LEGACY;
}
