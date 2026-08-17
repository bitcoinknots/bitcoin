// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <consensus/params.h>
#include <deploymentinfo.h>
#include <kernel/chainparams.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <cassert>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

using util::SplitString;

static const char* PURITY_ACTIVATION_HEIGHT_FILENAME = "purity_activation_height";

static bool ParsePurityActivationHeight(const std::string& value, int& height_out, std::string& error)
{
    int32_t height;
    if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
        error = strprintf("Invalid -purityactivationheight height (%s)", value);
        return false;
    }
    height_out = height;
    return true;
}

void ApplyPurityActivationHeightLock(ArgsManager& args)
{
    const fs::path lock_path{args.GetDataDirBase() / PURITY_ACTIVATION_HEIGHT_FILENAME};

    std::optional<int> from_arg;
    if (args.IsArgSet("-purityactivationheight")) {
        int height;
        std::string error;
        if (!ParsePurityActivationHeight(args.GetArg("-purityactivationheight", ""), height, error)) {
            throw std::runtime_error(error);
        }
        from_arg = height;
    }

    if (fs::exists(lock_path)) {
        const auto [ok, data] = ReadBinaryFile(lock_path, /*maxsize=*/64);
        if (!ok) {
            throw std::runtime_error(strprintf("Failed to read Purity activation height lock file %s", fs::PathToString(lock_path)));
        }
        // Trim trailing whitespace/newlines.
        std::string text{data};
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ' || text.back() == '\t')) {
            text.pop_back();
        }
        int locked_height;
        std::string error;
        if (!ParsePurityActivationHeight(text, locked_height, error)) {
            throw std::runtime_error(strprintf("Corrupt Purity activation height lock file %s", fs::PathToString(lock_path)));
        }
        if (from_arg && *from_arg != locked_height) {
            LogPrintf("Ignoring -purityactivationheight=%d; already locked at %d (%s)\n",
                      *from_arg, locked_height, fs::PathToString(lock_path));
        } else {
            LogPrintf("Using locked Purity activation height %d (%s)\n",
                      locked_height, fs::PathToString(lock_path));
        }
        args.ForceSetArg("-purityactivationheight", util::ToString(locked_height));
        return;
    }

    if (from_arg) {
        if (!WriteBinaryFile(lock_path, strprintf("%d\n", *from_arg))) {
            throw std::runtime_error(strprintf("Failed to write Purity activation height lock file %s", fs::PathToString(lock_path)));
        }
        LogPrintf("Locked Purity activation height to %d (%s)\n", *from_arg, fs::PathToString(lock_path));
    }
}

void ReadMainArgs(const ArgsManager& args, CChainParams::MainOptions& options)
{
    if (const auto height{args.GetIntArg("-purityactivationheight")}) {
        if (*height < 0 || *height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid -purityactivationheight height (%d)", *height));
        }
        options.purity_activation_height = static_cast<int>(*height);
        LogPrintf("Setting Purity activation height to %d\n", *options.purity_activation_height);
    }
}

void ReadSigNetArgs(const ArgsManager& args, CChainParams::SigNetOptions& options)
{
    if (!args.GetArgs("-signetseednode").empty()) {
        options.seeds.emplace(args.GetArgs("-signetseednode"));
    }
    if (!args.GetArgs("-signetchallenge").empty()) {
        const auto signet_challenge = args.GetArgs("-signetchallenge");
        if (signet_challenge.size() != 1) {
            throw std::runtime_error("-signetchallenge cannot be multiple values.");
        }
        const auto val{TryParseHex<uint8_t>(signet_challenge[0])};
        if (!val) {
            throw std::runtime_error(strprintf("-signetchallenge must be hex, not '%s'.", signet_challenge[0]));
        }
        options.challenge.emplace(*val);
    }
    if (const auto signetblocktime{args.GetIntArg("-signetblocktime")}) {
        if (!args.IsArgSet("-signetchallenge")) {
            throw std::runtime_error("-signetblocktime cannot be set without -signetchallenge");
        }
        if (*signetblocktime <= 0) {
            throw std::runtime_error("-signetblocktime must be greater than 0");
        }
        options.pow_target_spacing = *signetblocktime;
    }
}

void ReadRegTestArgs(const ArgsManager& args, CChainParams::RegTestOptions& options)
{
    if (auto value = args.GetBoolArg("-fastprune")) options.fastprune = *value;
    if (HasTestOption(args, "bip94")) options.enforce_bip94 = true;

    for (const std::string& arg : args.GetArgs("-testactivationheight")) {
        const auto found{arg.find('@')};
        if (found == std::string::npos) {
            throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
        }

        const auto value{arg.substr(found + 1)};
        int32_t height;
        if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
        }

        const auto deployment_name{arg.substr(0, found)};
        if (const auto buried_deployment = GetBuriedDeployment(deployment_name)) {
            options.activation_heights[*buried_deployment] = height;
        } else {
            throw std::runtime_error(strprintf("Invalid name (%s) for -testactivationheight=name@height.", arg));
        }
    }

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams = SplitString(strDeployment, ':');
        if (vDeploymentParams.size() < 3 || 7 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:min_activation_height[:max_activation_height[:active_duration[:threshold]]]]");
        }
        CChainParams::VersionBitsParameters vbparams{};
        if (!ParseInt64(vDeploymentParams[1], &vbparams.start_time)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &vbparams.timeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() >= 4) {
            if (!ParseInt32(vDeploymentParams[3], &vbparams.min_activation_height)) {
                throw std::runtime_error(strprintf("Invalid min_activation_height (%s)", vDeploymentParams[3]));
            }
        } else {
            vbparams.min_activation_height = 0;
        }
        if (vDeploymentParams.size() >= 5) {
            if (!ParseInt32(vDeploymentParams[4], &vbparams.max_activation_height)) {
                throw std::runtime_error(strprintf("Invalid max_activation_height (%s)", vDeploymentParams[4]));
            }
        }
        if (vDeploymentParams.size() >= 6) {
            if (!ParseInt32(vDeploymentParams[5], &vbparams.active_duration)) {
                throw std::runtime_error(strprintf("Invalid active_duration (%s)", vDeploymentParams[5]));
            }
        }
        if (vDeploymentParams.size() >= 7) {
            if (!ParseInt32(vDeploymentParams[6], &vbparams.threshold)) {
                throw std::runtime_error(strprintf("Invalid threshold (%s)", vDeploymentParams[6]));
            }
        }
        // Validate that timeout and max_activation_height are mutually exclusive
        if (vbparams.timeout != Consensus::BIP9Deployment::NO_TIMEOUT && vbparams.max_activation_height < std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Cannot specify both timeout (%ld) and max_activation_height (%d) for deployment %s. Use timeout for BIP9 or max_activation_height for mandatory activation deadline, not both.", vbparams.timeout, vbparams.max_activation_height, vDeploymentParams[0]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                options.version_bits_parameters[Consensus::DeploymentPos(j)] = vbparams;
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, min_activation_height=%d, max_activation_height=%d, active_duration=%d, threshold=%d\n", vDeploymentParams[0], vbparams.start_time, vbparams.timeout, vbparams.min_activation_height, vbparams.max_activation_height, vbparams.active_duration, vbparams.threshold);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainType chain)
{
    g_rdts_consent = RDTSConsentFlag::IMPLICIT;
    g_enable_rdts = true;

    switch (chain) {
    case ChainType::MAIN: {
        auto opts = CChainParams::MainOptions{};
        ReadMainArgs(args, opts);
        return CChainParams::Main(opts);
    }
    case ChainType::TESTNET:
        return CChainParams::TestNet();
    case ChainType::TESTNET4:
        return CChainParams::TestNet4();
    case ChainType::SIGNET: {
        auto opts = CChainParams::SigNetOptions{};
        ReadSigNetArgs(args, opts);
        return CChainParams::SigNet(opts);
    }
    case ChainType::REGTEST: {
        auto opts = CChainParams::RegTestOptions{};
        ReadRegTestArgs(args, opts);
        return CChainParams::RegTest(opts);
    }
    }
    assert(false);
}

void SelectParams(const ChainType chain)
{
    SelectBaseParams(chain);
    globalChainParams = CreateChainParams(gArgs, chain);
}
