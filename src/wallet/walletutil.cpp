// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/walletutil.h>

#include <logging.h>
#include <util/system.h>

#include <set>

bool ExistsBerkeleyDatabase(const fs::path& path);
bool ExistsSQLiteDatabase(const fs::path& path);

fs::path GetWalletDir()
{
    fs::path path;

    if (gArgs.IsArgSet("-walletdir")) {
        path = gArgs.GetArg("-walletdir", "");
        if (!fs::is_directory(path)) {
            // If the path specified doesn't exist, we return the deliberately
            // invalid empty string.
            path = "";
        }
    } else {
        path = GetDataDir();
        // If a wallets directory exists, use that, otherwise default to GetDataDir
        if (fs::is_directory(path / "wallets")) {
            path /= "wallets";
        }
    }

    return path;
}

std::vector<fs::path> ListWalletDir()
{
    const fs::path wallet_dir = GetWalletDir();
    const fs::path data_dir = GetDataDir();
    const fs::path blocks_dir = GetBlocksDir();

    const size_t offset = wallet_dir.string().size() + (wallet_dir == wallet_dir.root_name() ? 0 : 1);
    std::vector<fs::path> paths;
    boost::system::error_code ec;

    // Here we place the top level dirs we want to skip in case walletdir is datadir or blocksdir
    // Those directories are referenced in doc/files.md
    const std::set<fs::path> ignore_paths = {
                                        blocks_dir,
                                        data_dir / "blktree",
                                        data_dir / "blocks",
                                        data_dir / "chainstate",
                                        data_dir / "coins",
                                        data_dir / "database",
                                        data_dir / "indexes",
                                        data_dir / "regtest",
                                        data_dir / "signet",
                                        data_dir / "testnet3"
                                        };

    for (auto it = fs::recursive_directory_iterator(wallet_dir, ec); it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) {
            if (fs::is_directory(*it)) {
                it.no_push();
                LogPrintf("%s: %s %s -- skipping.\n", __func__, ec.message(), it->path().string());
            } else {
                LogPrintf("%s: %s %s\n", __func__, ec.message(), it->path().string());
            }
            continue;
        }

        // We don't want to iterate through those special node dirs
        if (ignore_paths.count(it->path())) {
            it.no_push();
            continue;
        }

        try {
            // Get wallet path relative to walletdir by removing walletdir from the wallet path.
            // This can be replaced by boost::filesystem::lexically_relative once boost is bumped to 1.60.
            const fs::path path = it->path().string().substr(offset);

            if (it->status().type() == fs::directory_file &&
                (ExistsBerkeleyDatabase(it->path()) || ExistsSQLiteDatabase(it->path()))) {
                // Found a directory which contains wallet.dat btree file, add it as a wallet.
                paths.emplace_back(path);
            } else if (it.level() == 0 && it->symlink_status().type() == fs::regular_file && ExistsBerkeleyDatabase(it->path())) {
                if (it->path().filename() == "wallet.dat") {
                    // Found top-level wallet.dat btree file, add top level directory ""
                    // as a wallet.
                    paths.emplace_back();
                } else {
                    // Found top-level btree file not called wallet.dat. Current bitcoin
                    // software will never create these files but will allow them to be
                    // opened in a shared database environment for backwards compatibility.
                    // Add it to the list of available wallets.
                    paths.emplace_back(path);
                }
            }
        } catch (const std::exception& e) {
            LogPrintf("%s: Error scanning %s: %s\n", __func__, it->path().string(), e.what());
            it.no_push();
        }
    }

    return paths;
}

bool IsFeatureSupported(int wallet_version, int feature_version)
{
    return wallet_version >= feature_version;
}

WalletFeature GetClosestWalletFeature(int version)
{
    if (version >= FEATURE_LATEST) return FEATURE_LATEST;
    if (version >= FEATURE_PRE_SPLIT_KEYPOOL) return FEATURE_PRE_SPLIT_KEYPOOL;
    if (version >= FEATURE_NO_DEFAULT_KEY) return FEATURE_NO_DEFAULT_KEY;
    if (version >= FEATURE_HD_SPLIT) return FEATURE_HD_SPLIT;
    if (version >= FEATURE_HD) return FEATURE_HD;
    if (version >= FEATURE_COMPRPUBKEY) return FEATURE_COMPRPUBKEY;
    if (version >= FEATURE_WALLETCRYPT) return FEATURE_WALLETCRYPT;
    if (version >= FEATURE_BASE) return FEATURE_BASE;
    return static_cast<WalletFeature>(0);
}
