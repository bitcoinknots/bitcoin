// Copyright (c) 2011-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_INTRO_H
#define BITCOIN_QT_INTRO_H

#include <kernel/official_packages.h>

#include <QMutex>
#include <QThread>
#include <QWizard>

#include <memory>
#include <optional>

static const bool DEFAULT_CHOOSE_DATADIR = false;

class FreespaceChecker;
class IntroDataDirPage;
class IntroSyncModePage;
class IntroStoragePage;

enum class IntroSyncMode {
    P2P_FULL,
    OFFICIAL_PACKAGE,
};

namespace interfaces {
    class Node;
}

/** Introduction wizard (pre-GUI startup).
  Allows the user to choose a data directory, sync method, and storage options.
 */
class Intro : public QWizard
{
    Q_OBJECT

public:
    explicit Intro(QWidget *parent = nullptr,
                   int64_t blockchain_size_gb = 0, int64_t chain_state_size_gb = 0);
    ~Intro();

    QString getDataDirectory() const;
    void setDataDirectory(const QString &dataDir);
    /** Skip the data-directory page (e.g. when -datadir is given on the command line). */
    void setSkipDataDirPage(bool skip);
    int64_t getPruneMiB() const;
    QString getAssumeValid() const;
    IntroSyncMode syncMode() const;
    const std::vector<OfficialDataPackage>& officialPackages() const { return m_official_packages; }
    std::optional<OfficialDataPackage> selectedPackage() const;

    /**
     * Determine data directory. Let the user choose if the current one doesn't exist.
     * Let the user configure additional preferences such as pruning.
     *
     * @returns true if a data directory was selected, false if the user cancelled the selection
     * dialog.
     *
     * @note do NOT call global gArgs.GetDataDirNet() before calling this function, this
     * will cause the wrong path to be cached.
     */
    static bool showIfNeeded(std::unique_ptr<Intro>& intro);

    /** Re-show the wizard after a failed official package download. Returns false if cancelled. */
    bool retryAfterPackageDownloadFailure();

Q_SIGNALS:
    void requestCheck();

public Q_SLOTS:
    void setStatus(int status, const QString &message, quint64 bytesAvailable);

private Q_SLOTS:
    void onSyncModeChanged();

private:
    bool validateCurrentPage() override;

    const int64_t m_blockchain_size_gb;
    const int64_t m_chain_state_size_gb;
    int64_t m_required_space_gb{0};
    uint64_t m_bytes_available{0};
    int64_t m_prune_target_mib;
    std::vector<OfficialDataPackage> m_official_packages;
    QString m_official_packages_load_error;
    IntroDataDirPage* m_data_dir_page;
    IntroSyncModePage* m_sync_mode_page;
    IntroStoragePage* m_storage_page;
    bool m_skip_data_dir_page{false};
    bool m_prune_checkbox_is_default{true};
    QThread* thread{nullptr};
    QMutex mutex;
    bool signalled{false};
    QString pathToCheck;

    void reloadOfficialPackages();
    void updateOfficialPackageAvailability();
    void startThread();
    void checkPath(const QString &dataDir);
    QString getPathToCheck();
    void updateRequiredSpace();
    void UpdateFreeSpaceLabel();

    friend class FreespaceChecker;
    friend class IntroDataDirPage;
    friend class IntroSyncModePage;
    friend class IntroStoragePage;
};

#endif // BITCOIN_QT_INTRO_H
