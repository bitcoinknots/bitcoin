// Copyright (c) 2025 The Bitcoin Purity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PACKAGEDOWNLOADER_H
#define BITCOIN_QT_PACKAGEDOWNLOADER_H

#include <kernel/official_packages.h>

#include <optional>
#include <string>

class QWidget;
class QString;

/** Download, verify, and extract an official datadir archive into the data directory. */
class PackageDownloader
{
public:
    /** Blocking UI dialog; returns true on success. */
    static bool runBlocking(const OfficialDataPackage& package, const QString& data_dir, QWidget* parent = nullptr);

private:
    PackageDownloader() = delete;
};

#endif // BITCOIN_QT_PACKAGEDOWNLOADER_H
