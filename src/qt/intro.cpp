// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <qt/intro.h>
#include <kernel/official_packages.h>
#include <util/chaintype.h>
#include <util/fs.h>

#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>

#include <common/args.h>
#include <common/settings.h>
#include <interfaces/node.h>
#include <logging.h>
#include <node/interface_ui.h>
#include <util/fs_helpers.h>
#include <util/translation.h>
#include <univalue.h>
#include <validation.h>

#include <QButtonGroup>
#include <QCheckBox>
#include <QCoreApplication>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QApplication>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QEventLoop>
#include <QTimer>
#include <QUrl>
#include <QPushButton>
#include <QRadioButton>
#include <QSettings>
#include <QSpinBox>
#include <QStackedWidget>
#include <QVBoxLayout>

#include <cmath>
#include <cstdlib>

namespace {

static constexpr int OFFICIAL_PACKAGES_FETCH_TIMEOUT_MS{30'000};

std::optional<std::string> FetchOfficialPackagesJson(const QUrl& url, QString& error_out)
{
    QNetworkAccessManager manager;
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::UserAgentHeader,
        QStringLiteral("%1/%2").arg(CLIENT_NAME, QString::fromStdString(FormatFullVersion())));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    QNetworkReply* reply = manager.get(request);

    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    timeout.setInterval(OFFICIAL_PACKAGES_FETCH_TIMEOUT_MS);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    timeout.start();
    loop.exec();

    if (!reply->isFinished()) {
        error_out = QStringLiteral("Timed out loading the official package list.");
        reply->abort();
        reply->deleteLater();
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
        return std::nullopt;
    }
    if (reply->error() != QNetworkReply::NoError) {
        error_out = reply->errorString();
        reply->deleteLater();
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
        return std::nullopt;
    }

    const std::string contents = reply->readAll().toStdString();
    reply->deleteLater();
    QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    if (contents.empty()) {
        error_out = QStringLiteral("The official package list was empty.");
        return std::nullopt;
    }
    return contents;
}

} // namespace

class FreespaceChecker : public QObject
{
    Q_OBJECT

public:
    explicit FreespaceChecker(Intro *intro);

    enum Status {
        ST_OK,
        ST_ERROR
    };

public Q_SLOTS:
    void check();

Q_SIGNALS:
    void reply(int status, const QString &message, quint64 available);

private:
    Intro *intro;
};

class IntroDataDirPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit IntroDataDirPage(Intro* wizard, int64_t blockchain_size_gb, int64_t chain_state_size_gb);

    QString dataDirectory() const { return m_data_directory->text(); }
    void setDataDirectory(const QString& dataDir);

private Q_SLOTS:
    void onDataDirectoryTextChanged(const QString& dataDirStr);
    void onEllipsisClicked();
    void onDataDirDefaultClicked();
    void onDataDirCustomClicked();

private:
    Intro* m_wizard;
    QRadioButton* m_data_dir_default;
    QRadioButton* m_data_dir_custom;
    QLineEdit* m_data_directory;
    QPushButton* m_ellipsis_button;
    QLabel* m_size_warning_label;
    QLabel* m_free_space;
    QLabel* m_error_message;

    friend class Intro;
};

class IntroSyncModePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit IntroSyncModePage(Intro* wizard, int64_t blockchain_size_gb);

    IntroSyncMode syncMode() const;

    void initializePage() override;

private:
    Intro* m_wizard;
    QRadioButton* m_p2p_full;
    QRadioButton* m_official_package;

    friend class Intro;
};

class IntroStoragePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit IntroStoragePage(Intro* wizard);

    int64_t pruneMiB() const;
    QString assumeValid() const;
    std::optional<OfficialDataPackage> selectedPackage() const;
    void refreshForSyncMode(IntroSyncMode mode);

private Q_SLOTS:
    void onPruneStateChanged(int state);
    void onPruneMiBChanged(int value);
    void onPackageSelectionChanged();

private:
    Intro* m_wizard;
    QStackedWidget* m_stack;
    QWidget* m_p2p_page;
    QWidget* m_package_page;
    QCheckBox* m_prune;
    QSpinBox* m_prune_mib;
    QLabel* m_prune_suffix;
    QCheckBox* m_assumevalid;
    QLineEdit* m_assumevalid_block;
    QWidget* m_group_assumevalid;
    QListWidget* m_package_list;
    QLabel* m_p2p_explanation;
    QLabel* m_package_explanation;
    std::vector<OfficialDataPackage> m_packages;

    friend class Intro;
};

#include <qt/intro.moc>

namespace {
fs::path NetworkSettingsPath(const fs::path& base_datadir)
{
    fs::path path = base_datadir;
    if (!BaseParams().DataDir().empty()) {
        path /= fs::PathFromString(BaseParams().DataDir());
    }
    return path / "settings.json";
}

bool NeedsSyncSetup(const fs::path& base_datadir)
{
    const fs::path settings_path = NetworkSettingsPath(base_datadir);
    if (!fs::exists(settings_path)) {
        return true;
    }
    std::map<std::string, common::SettingsValue> values;
    std::vector<std::string> errors;
    if (!common::ReadSettings(settings_path, values, errors)) {
        return true;
    }
    const auto it = values.find("sync-mode");
    return it == values.end() || !it->second.isStr();
}

int GetPruneTargetMiB()
{
    int64_t prune_target_mib = gArgs.GetIntArg("-prune", 0);
    return prune_target_mib > 1 ? prune_target_mib : DEFAULT_PRUNE_TARGET_MiB;
}

QString FormatBytes(quint64 bytes)
{
    static constexpr quint64 GB_BYTES = 1024ULL * 1024 * 1024;
    if (bytes >= GB_BYTES) {
        return Intro::tr("%1 GB").arg(QString::number(bytes / static_cast<double>(GB_BYTES), 'f', 1));
    }
    static constexpr quint64 MB_BYTES = 1024ULL * 1024;
    return Intro::tr("%1 MB").arg(bytes / MB_BYTES);
}

/** Apply a GUI-chosen datadir to gArgs before InitConfig.
 *
 * SoftSetArg cannot update a value already SoftSet earlier in the intro flow, so a custom
 * path chosen in the wizard would be ignored and the node would keep using the default
 * datadir. ForceSetArg (or clearing a temporary default SoftSet) makes the user's choice
 * take effect. Never SoftSet/ForceSet the OS default path permanently: that would block a
 * -datadir override from bitcoin.conf in the default data directory.
 */
void ApplyIntroDataDir(const QString& dataDir)
{
    if (dataDir != GUIUtil::getDefaultDataDirectory()) {
        gArgs.ForceSetArg("-datadir", fs::PathToString(GUIUtil::QStringToPath(dataDir)));
    } else {
        gArgs.LockSettings([](common::Settings& settings) {
            settings.forced_settings.erase("datadir");
        });
    }
    gArgs.ClearPathCache();
}
} // namespace

FreespaceChecker::FreespaceChecker(Intro *_intro)
{
    this->intro = _intro;
}

void FreespaceChecker::check()
{
    QString dataDirStr = intro->getPathToCheck();
    fs::path dataDir = GUIUtil::QStringToPath(dataDirStr);
    uint64_t freeBytesAvailable = 0;
    int replyStatus = ST_OK;
    QString replyMessage = Intro::tr("A new data directory will be created.");

    fs::path parentDir = dataDir;
    fs::path parentDirOld = fs::path();
    while(parentDir.has_parent_path() && !fs::exists(parentDir))
    {
        parentDir = parentDir.parent_path();
        if (parentDirOld == parentDir)
            break;
        parentDirOld = parentDir;
    }

    try {
        freeBytesAvailable = fs::space(parentDir).available;
        if(fs::exists(dataDir))
        {
            if(fs::is_directory(dataDir))
            {
                QString separator = "<code>" + QDir::toNativeSeparators("/") + Intro::tr("name") + "</code>";
                replyStatus = ST_OK;
                replyMessage = Intro::tr("Directory already exists. Add %1 if you intend to create a new directory here.").arg(separator);
            } else {
                replyStatus = ST_ERROR;
                replyMessage = Intro::tr("Path already exists, and is not a directory.");
            }
        }
    } catch (const fs::filesystem_error&)
    {
        replyStatus = ST_ERROR;
        replyMessage = Intro::tr("Cannot create data directory here.");
    }
    Q_EMIT reply(replyStatus, replyMessage, freeBytesAvailable);
}

IntroDataDirPage::IntroDataDirPage(Intro* wizard, int64_t blockchain_size_gb, int64_t chain_state_size_gb)
    : QWizardPage(wizard),
      m_wizard(wizard)
{
    setTitle(Intro::tr("Welcome"));
    setSubTitle(Intro::tr("As this is the first time the program is launched, you can choose where %1 will store its data.").arg(CLIENT_NAME));

    auto* layout = new QVBoxLayout(this);

    auto* welcome = new QLabel(Intro::tr("Welcome to %1.").arg(CLIENT_NAME), this);
    welcome->setWordWrap(true);
    welcome->setStyleSheet(QStringLiteral("QLabel { font-style:italic; }"));
    layout->addWidget(welcome);

    m_size_warning_label = new QLabel(this);
    m_size_warning_label->setWordWrap(true);
    layout->addWidget(m_size_warning_label);

    m_data_dir_default = new QRadioButton(Intro::tr("Use the default data directory"), this);
    m_data_dir_custom = new QRadioButton(Intro::tr("Use a custom data directory:"), this);
    layout->addWidget(m_data_dir_default);
    layout->addWidget(m_data_dir_custom);

    auto* dir_layout = new QHBoxLayout();
    dir_layout->addSpacing(60);
    m_data_directory = new QLineEdit(this);
    m_ellipsis_button = new QPushButton(QStringLiteral("…"), this);
    m_ellipsis_button->setAutoDefault(false);
    dir_layout->addWidget(m_data_directory);
    dir_layout->addWidget(m_ellipsis_button);
    layout->addLayout(dir_layout);

    m_free_space = new QLabel(this);
    m_free_space->setWordWrap(true);
    layout->addWidget(m_free_space);

    m_error_message = new QLabel(this);
    m_error_message->setWordWrap(true);
    m_error_message->setTextFormat(Qt::RichText);
    layout->addWidget(m_error_message);

    connect(m_data_directory, &QLineEdit::textChanged, this, &IntroDataDirPage::onDataDirectoryTextChanged);
    connect(m_ellipsis_button, &QPushButton::clicked, this, &IntroDataDirPage::onEllipsisClicked);
    connect(m_data_dir_default, &QRadioButton::clicked, this, &IntroDataDirPage::onDataDirDefaultClicked);
    connect(m_data_dir_custom, &QRadioButton::clicked, this, &IntroDataDirPage::onDataDirCustomClicked);

    Q_UNUSED(blockchain_size_gb);
    Q_UNUSED(chain_state_size_gb);
}

void IntroDataDirPage::setDataDirectory(const QString& dataDir)
{
    m_data_directory->setText(dataDir);
    if(dataDir == GUIUtil::getDefaultDataDirectory())
    {
        m_data_dir_default->setChecked(true);
        m_data_directory->setEnabled(false);
        m_ellipsis_button->setEnabled(false);
    } else {
        m_data_dir_custom->setChecked(true);
        m_data_directory->setEnabled(true);
        m_ellipsis_button->setEnabled(true);
    }
    onDataDirectoryTextChanged(dataDir);
}

void IntroDataDirPage::onDataDirectoryTextChanged(const QString& dataDirStr)
{
    m_wizard->checkPath(dataDirStr);
}

void IntroDataDirPage::onEllipsisClicked()
{
    QString dir = QDir::toNativeSeparators(QFileDialog::getExistingDirectory(this, Intro::tr("Choose data directory"), m_data_directory->text()));
    if(!dir.isEmpty())
        m_data_directory->setText(dir);
}

void IntroDataDirPage::onDataDirDefaultClicked()
{
    setDataDirectory(GUIUtil::getDefaultDataDirectory());
}

void IntroDataDirPage::onDataDirCustomClicked()
{
    m_data_directory->setEnabled(true);
    m_ellipsis_button->setEnabled(true);
}

IntroSyncModePage::IntroSyncModePage(Intro* wizard, int64_t blockchain_size_gb)
    : QWizardPage(wizard),
      m_wizard(wizard)
{
    setTitle(Intro::tr("Choose initial sync method"));
    setSubTitle(Intro::tr("Downloading and verifying the blockchain can take a long time. Choose how you want to get started."));

    auto* layout = new QVBoxLayout(this);

    m_p2p_full = new QRadioButton(this);
    m_p2p_full->setText(Intro::tr("Download and verify the full blockchain from the network"));
    m_p2p_full->setChecked(true);
    layout->addWidget(m_p2p_full);

    auto* p2p_detail = new QLabel(
        Intro::tr("<b>Trustless, but slow.</b><br/>Requires downloading approximately %1 GB from peers and verifying every block. This can take from several days to several weeks depending on your hardware and connection.")
            .arg(blockchain_size_gb),
        this);
    p2p_detail->setTextFormat(Qt::RichText);
    p2p_detail->setWordWrap(true);
    p2p_detail->setIndent(20);
    layout->addWidget(p2p_detail);

    layout->addSpacing(12);

    m_official_package = new QRadioButton(Intro::tr("Start from an official data package"), this);
    layout->addWidget(m_official_package);

    auto* package_detail = new QLabel(
        Intro::tr("<b>Fast start, but requires trust.</b><br/>Download a pre-built data directory archive from %1. Choose a storage option on the next page. The node still downloads recent blocks from the network to reach the current tip.")
            .arg(QStringLiteral("bitcoinpurity.org")),
        this);
    package_detail->setTextFormat(Qt::RichText);
    package_detail->setWordWrap(true);
    package_detail->setIndent(20);
    layout->addWidget(package_detail);

    m_official_package->setEnabled(false);

    connect(m_p2p_full, &QRadioButton::toggled, m_wizard, &Intro::onSyncModeChanged);
    connect(m_official_package, &QRadioButton::toggled, m_wizard, &Intro::onSyncModeChanged);
}

IntroSyncMode IntroSyncModePage::syncMode() const
{
    return m_official_package->isChecked() ? IntroSyncMode::OFFICIAL_PACKAGE : IntroSyncMode::P2P_FULL;
}

void IntroSyncModePage::initializePage()
{
    m_official_package->setEnabled(false);
    m_official_package->setToolTip(Intro::tr("Loading official package list…"));
    QApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    m_wizard->reloadOfficialPackages();
    m_wizard->updateOfficialPackageAvailability();
}

IntroStoragePage::IntroStoragePage(Intro* wizard)
    : QWizardPage(wizard),
      m_wizard(wizard)
{
    setTitle(Intro::tr("Choose storage options"));

    auto* layout = new QVBoxLayout(this);
    m_stack = new QStackedWidget(this);
    layout->addWidget(m_stack);

    m_p2p_page = new QWidget(this);
    auto* p2p_layout = new QVBoxLayout(m_p2p_page);

    m_p2p_explanation = new QLabel(m_p2p_page);
    m_p2p_explanation->setWordWrap(true);
    p2p_layout->addWidget(m_p2p_explanation);

    auto* prune_layout = new QHBoxLayout();
    m_prune = new QCheckBox(Intro::tr("Limit block chain storage to"), m_p2p_page);
    m_prune->setToolTip(Intro::tr("Reverting this setting requires re-downloading the entire blockchain. It is faster to download the full chain first and prune it later. Disables some advanced features."));
    m_prune_mib = new QSpinBox(m_p2p_page);
    m_prune_mib->setSuffix(Intro::tr(" MiB"));
    m_prune_suffix = new QLabel(m_p2p_page);
    prune_layout->addWidget(m_prune);
    prune_layout->addWidget(m_prune_mib);
    prune_layout->addWidget(m_prune_suffix);
    prune_layout->addStretch();
    p2p_layout->addLayout(prune_layout);

    m_group_assumevalid = new QWidget(m_p2p_page);
    auto* assume_layout = new QVBoxLayout(m_group_assumevalid);
    auto* assume_explain = new QLabel(
        Intro::tr("The initial synchronisation process can go faster if you skip verification of older transactions. This does, however, require trusting that the \"assumed valid\" blockchain below is in fact valid. Uncheck this if you want to fully validate the entire blockchain history."),
        m_group_assumevalid);
    assume_explain->setWordWrap(true);
    assume_layout->addWidget(assume_explain);

    auto* assume_row = new QHBoxLayout();
    m_assumevalid = new QCheckBox(Intro::tr("Skip validation of the transactions until after block:"), m_group_assumevalid);
    m_assumevalid->setChecked(true);
    m_assumevalid_block = new QLineEdit(m_group_assumevalid);
    m_assumevalid_block->setMaxLength(64);
    assume_row->addWidget(m_assumevalid);
    assume_row->addStretch();
    assume_layout->addLayout(assume_row);

    auto* assume_hash_row = new QHBoxLayout();
    assume_hash_row->addStretch();
    assume_hash_row->addWidget(m_assumevalid_block);
    assume_layout->addLayout(assume_hash_row);
    p2p_layout->addWidget(m_group_assumevalid);
    p2p_layout->addStretch();

    m_package_page = new QWidget(this);
    auto* package_layout = new QVBoxLayout(m_package_page);
    m_package_explanation = new QLabel(m_package_page);
    m_package_explanation->setWordWrap(true);
    package_layout->addWidget(m_package_explanation);

    m_package_list = new QListWidget(m_package_page);
    m_package_list->setSelectionMode(QAbstractItemView::SingleSelection);
    package_layout->addWidget(m_package_list);

    m_stack->addWidget(m_p2p_page);
    m_stack->addWidget(m_package_page);

    const int min_prune_target_MiB = (MIN_DISK_SPACE_FOR_BLOCK_FILES + MiB_BYTES - 1) / MiB_BYTES;
    m_prune_mib->setRange(min_prune_target_MiB, std::numeric_limits<int>::max());
    m_prune_mib->setValue(GetPruneTargetMiB());

#if (QT_VERSION >= QT_VERSION_CHECK(6, 7, 0))
    connect(m_prune, &QCheckBox::checkStateChanged, this, &IntroStoragePage::onPruneStateChanged);
#else
    connect(m_prune, &QCheckBox::stateChanged, this, &IntroStoragePage::onPruneStateChanged);
#endif
    connect(m_prune_mib, qOverload<int>(&QSpinBox::valueChanged), this, &IntroStoragePage::onPruneMiBChanged);
    connect(m_package_list, &QListWidget::currentRowChanged, this, &IntroStoragePage::onPackageSelectionChanged);
}

void IntroStoragePage::refreshForSyncMode(IntroSyncMode mode)
{
    if (mode == IntroSyncMode::OFFICIAL_PACKAGE) {
        setSubTitle(Intro::tr("Select one of the official data packages. Each package includes a fixed snapshot height and storage configuration."));
        m_stack->setCurrentWidget(m_package_page);
        m_packages = m_wizard->officialPackages();
        m_package_list->clear();
        for (const auto& package : m_packages) {
            QString storage_label = package.prune_mib > 0
                ? Intro::tr("Pruned to %1 MiB").arg(package.prune_mib)
                : Intro::tr("Full node (keep all blocks)");
            const QString label = Intro::tr("Block height %1 — %2 — download %3, needs %4 on disk after extraction")
                .arg(package.snapshot_height)
                .arg(storage_label)
                .arg(FormatBytes(package.archive_size_bytes))
                .arg(FormatBytes(package.extracted_size_bytes));
            m_package_list->addItem(label);
        }
        if (!m_packages.empty()) {
            m_package_list->setCurrentRow(0);
        }
        m_package_explanation->setText(
            Intro::tr("Official packages are downloaded from %1 and verified before extraction. You cannot customize the prune size when using a data package.")
                .arg(QStringLiteral("bitcoinpurity.org")));
    } else {
        setSubTitle(Intro::tr("Choose how much blockchain data to keep on disk."));
        m_stack->setCurrentWidget(m_p2p_page);
        m_p2p_explanation->setText(
            Intro::tr("When you click Start, %1 will begin to download and process the full %4 block chain (%2 GB) starting with the earliest transactions in %3 when %4 initially launched.")
                .arg(CLIENT_NAME)
                .arg(m_wizard->m_blockchain_size_gb)
                .arg(2009)
                .arg(Intro::tr("Bitcoin")));
    }
    onPackageSelectionChanged();
    onPruneStateChanged(m_prune->checkState());
}

void IntroStoragePage::onPruneStateChanged(int state)
{
    m_wizard->m_prune_checkbox_is_default = false;
    const bool prune_checked = state == Qt::Checked;
    m_prune_mib->setEnabled(prune_checked);
    m_wizard->m_prune_target_mib = m_prune_mib->value();
    static constexpr uint64_t nPowTargetSpacing = 10 * 60;
    static constexpr uint32_t expected_block_data_size = 2250000;
    const uint64_t expected_backup_days = m_wizard->m_prune_target_mib * MiB_BYTES / (uint64_t(expected_block_data_size) * 86400 / nPowTargetSpacing);
    m_prune_suffix->setText(Intro::tr("(sufficient to restore backups %n day(s) old)", "", expected_backup_days));
    m_wizard->updateRequiredSpace();
}

void IntroStoragePage::onPruneMiBChanged(int value)
{
    m_wizard->m_prune_target_mib = value;
    onPruneStateChanged(m_prune->checkState());
}

void IntroStoragePage::onPackageSelectionChanged()
{
    m_wizard->updateRequiredSpace();
}

int64_t IntroStoragePage::pruneMiB() const
{
    if (m_wizard->syncMode() == IntroSyncMode::OFFICIAL_PACKAGE) {
        const auto package = selectedPackage();
        return package ? package->prune_mib : 0;
    }
    switch (m_prune->checkState()) {
    case Qt::Checked:
        return m_wizard->m_prune_target_mib;
    case Qt::PartiallyChecked:
        return 1;
    case Qt::Unchecked: default:
        return 0;
    }
}

QString IntroStoragePage::assumeValid() const
{
    if (m_wizard->syncMode() == IntroSyncMode::OFFICIAL_PACKAGE) {
        return QStringLiteral("0");
    }
    if (!m_assumevalid->isChecked()) {
        return QStringLiteral("0");
    }
    return m_assumevalid_block->text();
}

std::optional<OfficialDataPackage> IntroStoragePage::selectedPackage() const
{
    const int row = m_package_list->currentRow();
    if (row < 0 || static_cast<size_t>(row) >= m_packages.size()) {
        return std::nullopt;
    }
    return m_packages[static_cast<size_t>(row)];
}

Intro::Intro(QWidget *parent, int64_t blockchain_size_gb, int64_t chain_state_size_gb) :
    QWizard(parent, GUIUtil::dialog_flags),
    m_blockchain_size_gb(blockchain_size_gb),
    m_chain_state_size_gb(chain_state_size_gb),
    m_prune_target_mib{GetPruneTargetMiB()},
    m_official_packages{},
    m_data_dir_page(new IntroDataDirPage(this, blockchain_size_gb, chain_state_size_gb)),
    m_sync_mode_page(new IntroSyncModePage(this, blockchain_size_gb)),
    m_storage_page(new IntroStoragePage(this))
{
    setWindowTitle(Intro::tr("Welcome"));
    setWindowIcon(QIcon(QStringLiteral(":icons/bitcoin")));
    setWizardStyle(QWizard::ModernStyle);
    setOption(QWizard::IndependentPages, false);
    setOption(QWizard::NoCancelButton, true);
    setOption(QWizard::HaveCustomButton1, true);
    setButtonText(QWizard::FinishButton, Intro::tr("Start"));
    setButtonText(QWizard::CustomButton1, Intro::tr("Quit"));
    connect(this, &QWizard::customButtonClicked, this, [this](int which) {
        if (which == QWizard::CustomButton1) {
            reject();
        }
    });

    addPage(m_data_dir_page);
    addPage(m_sync_mode_page);
    addPage(m_storage_page);

    if (gArgs.IsArgSet("-prune")) {
        m_prune_checkbox_is_default = false;
        switch (gArgs.GetIntArg("-prune", 0)) {
        case 0:
            m_storage_page->m_prune->setChecked(false);
            break;
        case 1:
            m_storage_page->m_prune->setTristate();
            m_storage_page->m_prune->setCheckState(Qt::PartiallyChecked);
            break;
        default:
            m_storage_page->m_prune->setChecked(true);
        }
    }
    m_storage_page->m_prune_mib->setValue(m_prune_target_mib);

    bool have_user_assumevalid = false;
    if (gArgs.IsArgSet("-assumevalid")) {
        const auto user_assumevalid = gArgs.GetArg("-assumevalid", "");
        const auto block_hash{uint256::FromUserHex(user_assumevalid)};
        if (block_hash && !block_hash->IsNull()) {
            m_storage_page->m_assumevalid->setChecked(true);
            m_storage_page->m_assumevalid_block->setText(QString::fromStdString(user_assumevalid));
            have_user_assumevalid = true;
        } else {
            m_storage_page->m_assumevalid->setChecked(false);
        }
    }
    if (!have_user_assumevalid) {
        const auto chainparams = CreateChainParams(gArgs, gArgs.GetChainType());
        const uint256 default_assumevalid = chainparams ? chainparams->GetConsensus().defaultAssumeValid : uint256();
        if (default_assumevalid.IsNull()) {
            m_storage_page->m_group_assumevalid->setVisible(false);
        } else {
            m_storage_page->m_assumevalid_block->setText(QString::fromStdString(default_assumevalid.GetHex()));
            m_storage_page->m_assumevalid_block->setReadOnly(true);
        }
    }
    {
        const int text_width = m_storage_page->m_assumevalid_block->fontMetrics().horizontalAdvance(QStringLiteral("4")) * (64 + 4);
        m_storage_page->m_assumevalid_block->setFixedWidth(text_width);
    }

    connect(this, &QWizard::currentIdChanged, this, [this](int id) {
        if (id == 2) {
            m_storage_page->refreshForSyncMode(syncMode());
        }
    });

    m_storage_page->refreshForSyncMode(IntroSyncMode::P2P_FULL);
    startThread();
}

Intro::~Intro()
{
    if (thread) {
        thread->quit();
        thread->wait();
    }
}

QString Intro::getDataDirectory() const
{
    return m_data_dir_page->dataDirectory();
}

void Intro::setDataDirectory(const QString &dataDir)
{
    m_data_dir_page->setDataDirectory(dataDir);
}

void Intro::setSkipDataDirPage(bool skip)
{
    m_skip_data_dir_page = skip;
    if (skip) {
        setStartId(1);
    }
}

bool Intro::retryAfterPackageDownloadFailure()
{
    setStartId(m_skip_data_dir_page ? 1 : 0);
    m_storage_page->refreshForSyncMode(syncMode());
    return exec() == QDialog::Accepted;
}

int64_t Intro::getPruneMiB() const
{
    return m_storage_page->pruneMiB();
}

QString Intro::getAssumeValid() const
{
    return m_storage_page->assumeValid();
}

IntroSyncMode Intro::syncMode() const
{
    return m_sync_mode_page->syncMode();
}

std::optional<OfficialDataPackage> Intro::selectedPackage() const
{
    return m_storage_page->selectedPackage();
}

void Intro::reloadOfficialPackages()
{
    const ChainType chain = Params().GetChainType();
    m_official_packages_load_error.clear();

    if (gArgs.IsArgSet("-officialpackages")) {
        m_official_packages = LoadOfficialDataPackages(gArgs, chain);
        if (m_official_packages.empty()) {
            m_official_packages_load_error = tr("Could not read the file specified by -officialpackages.");
        }
        return;
    }

    if (FindDatadirOfficialPackagesConfigPath(gArgs, chain)) {
        m_official_packages = LoadOfficialDataPackages(gArgs, chain);
        if (m_official_packages.empty()) {
            m_official_packages_load_error = tr("Could not read the official package list from the data directory.");
        }
        return;
    }

    const auto url = GetDefaultOfficialPackagesUrl(chain);
    if (!url) {
        m_official_packages.clear();
        m_official_packages_load_error = tr("Official data packages are not available on this network.");
        return;
    }

    QString fetch_error;
    const auto contents = FetchOfficialPackagesJson(QUrl(QString::fromStdString(*url)), fetch_error);
    if (!contents) {
        LogPrintf("Failed to fetch official packages from %s: %s\n", *url, fetch_error.toStdString());
        m_official_packages.clear();
        m_official_packages_load_error = fetch_error.isEmpty()
            ? tr("Could not load the official package list from downloads.bitcoinpurity.org.")
            : fetch_error;
        return;
    }

    m_official_packages = ParseOfficialDataPackagesFromJson(*contents, *url);
    if (m_official_packages.empty()) {
        m_official_packages_load_error = tr("The official package list from downloads.bitcoinpurity.org contained no valid packages.");
    }
}

void Intro::updateOfficialPackageAvailability()
{
    const bool have_packages = !m_official_packages.empty();
    m_sync_mode_page->m_official_package->setEnabled(have_packages);
    if (have_packages) {
        m_sync_mode_page->m_official_package->setToolTip(QString{});
    } else {
        QString tooltip = m_official_packages_load_error;
        if (tooltip.isEmpty()) {
            tooltip = tr("Could not load the official package list from downloads.bitcoinpurity.org. Check your network connection, or pass -officialpackages=<file> to use a local JSON file.");
        } else if (!gArgs.IsArgSet("-officialpackages") && !FindDatadirOfficialPackagesConfigPath(gArgs, Params().GetChainType())) {
            tooltip += QLatin1Char(' ');
            tooltip += tr("You can also pass -officialpackages=<file> to use a local JSON file.");
        }
        m_sync_mode_page->m_official_package->setToolTip(tooltip);
        if (m_sync_mode_page->syncMode() == IntroSyncMode::OFFICIAL_PACKAGE) {
            m_sync_mode_page->m_p2p_full->setChecked(true);
        }
    }
}

void Intro::onSyncModeChanged()
{
    if (currentId() == 2) {
        m_storage_page->refreshForSyncMode(syncMode());
    }
}

bool Intro::validateCurrentPage()
{
    if (currentId() == 0) {
        // Page 0 is skipped when -datadir was given on the command line. Otherwise apply
        // the path immediately so later wizard steps (e.g. official package lookup) see it.
        if (!m_skip_data_dir_page) {
            ApplyIntroDataDir(getDataDirectory());
        }
        return true;
    }
    if (currentId() == 2) {
        if (syncMode() == IntroSyncMode::OFFICIAL_PACKAGE) {
            if (!selectedPackage()) {
                QMessageBox::warning(this, windowTitle(), tr("Please select an official data package."));
                return false;
            }
        }
        updateRequiredSpace();
        if (m_bytes_available < static_cast<uint64_t>(m_required_space_gb) * GB_BYTES) {
            QMessageBox::warning(this, windowTitle(),
                tr("Not enough disk space. At least %1 GB is required.").arg(m_required_space_gb));
            return false;
        }
    }
    return true;
}

bool Intro::showIfNeeded(std::unique_ptr<Intro>& intro)
{
    intro.reset();

    QSettings settings;
    const bool datadir_from_cli = !gArgs.GetArg("-datadir", "").empty();

    QString dataDir;
    if (datadir_from_cli) {
        dataDir = GUIUtil::PathToQString(fs::absolute(fs::PathFromString(gArgs.GetArg("-datadir", ""))));
    } else {
        dataDir = settings.value("strDataDir", GUIUtil::getDefaultDataDirectory()).toString();
    }

    try {
        SelectParams(gArgs.GetChainType());
    } catch (const std::exception& e) {
        InitError(Untranslated(e.what()));
        QMessageBox::critical(nullptr, CLIENT_NAME, QObject::tr("Error: %1").arg(QString(e.what())));
        std::exit(EXIT_FAILURE);
    }

    const fs::path datadir_path = GUIUtil::QStringToPath(dataDir);
    const bool need_intro =
        !fs::exists(datadir_path) ||
        gArgs.GetBoolArg("-choosedatadir", DEFAULT_CHOOSE_DATADIR) ||
        settings.value("fReset", false).toBool() ||
        gArgs.GetBoolArg("-resetguisettings", false) ||
        NeedsSyncSetup(datadir_path);

    if (!need_intro) {
        if (!datadir_from_cli) {
            ApplyIntroDataDir(dataDir);
        }
        return true;
    }

    // Apply the known path so GetDataDir* works during the wizard (official package files
    // under the datadir). SoftSetArg of the default path is intentionally avoided here —
    // see ApplyIntroDataDir.
    if (!datadir_from_cli) {
        ApplyIntroDataDir(dataDir);
    }

    intro = std::make_unique<Intro>(nullptr, Params().AssumedBlockchainSize(), Params().AssumedChainStateSize());
    intro->setDataDirectory(dataDir);
    if (datadir_from_cli) {
        intro->setSkipDataDirPage(true);
    }

    while (true) {
        if (intro->exec() != QDialog::Accepted) {
            return false;
        }
        dataDir = intro->getDataDirectory();
        try {
            if (TryCreateDirectories(GUIUtil::QStringToPath(dataDir))) {
                TryCreateDirectories(GUIUtil::QStringToPath(dataDir) / "wallets");
            }
            break;
        } catch (const fs::filesystem_error&) {
            QMessageBox::critical(nullptr, CLIENT_NAME,
                Intro::tr("Error: Specified data directory \"%1\" cannot be created.").arg(dataDir));
        }
    }

    settings.setValue("strDataDir", dataDir);
    settings.setValue("fReset", false);

    /* Only override -datadir if different from the default, to make it possible to
     * override -datadir in the bitcoin.conf file in the default data directory
     * (to be consistent with bitcoind behavior). Use ForceSetArg rather than SoftSetArg
     * because the wizard may already have SoftSet/ForceSet a prior path. */
    if (!datadir_from_cli) {
        ApplyIntroDataDir(dataDir);
    }
    return true;
}

void Intro::setStatus(int status, const QString &message, quint64 bytesAvailable)
{
    switch(status)
    {
    case FreespaceChecker::ST_OK:
        m_data_dir_page->m_error_message->setText(message);
        m_data_dir_page->m_error_message->setStyleSheet("");
        break;
    case FreespaceChecker::ST_ERROR:
        m_data_dir_page->m_error_message->setText(tr("Error") + ": " + message);
        m_data_dir_page->m_error_message->setStyleSheet("QLabel { color: #800000 }");
        break;
    }
    if(status == FreespaceChecker::ST_ERROR)
    {
        m_data_dir_page->m_free_space->setText("");
    } else {
        m_bytes_available = bytesAvailable;
        if (m_storage_page->m_prune->isEnabled() && m_prune_checkbox_is_default && syncMode() == IntroSyncMode::P2P_FULL) {
            m_storage_page->m_prune->setChecked(m_bytes_available < (m_blockchain_size_gb + m_chain_state_size_gb + 10) * GB_BYTES);
        }
        UpdateFreeSpaceLabel();
        updateRequiredSpace();
    }
    button(QWizard::NextButton)->setEnabled(status != FreespaceChecker::ST_ERROR);
    button(QWizard::FinishButton)->setEnabled(status != FreespaceChecker::ST_ERROR);
}

void Intro::updateRequiredSpace()
{
    if (syncMode() == IntroSyncMode::OFFICIAL_PACKAGE) {
        const auto package = selectedPackage();
        if (package) {
            static constexpr uint64_t buffer_bytes = 2ULL * 1024 * 1024 * 1024;
            const uint64_t required_bytes = package->archive_size_bytes + package->extracted_size_bytes + buffer_bytes;
            m_required_space_gb = (required_bytes + GB_BYTES - 1) / GB_BYTES;
            m_data_dir_page->m_size_warning_label->setText(
                tr("%1 will download an official data package and extract it into this directory.").arg(CLIENT_NAME) + " " +
                tr("Approximately %1 GB of data will be stored in this directory after extraction.").arg((package->extracted_size_bytes + GB_BYTES - 1) / GB_BYTES) + " " +
                tr("The wallet will also be stored in this directory."));
        }
    } else {
        m_required_space_gb = m_blockchain_size_gb + m_chain_state_size_gb;
        QString storageRequiresMsg = tr("At least %1 GB of data will be stored in this directory, and it will grow over time.");
        const int64_t prune_target_gb = (m_prune_target_mib * MiB_BYTES + GB_BYTES - 1) / GB_BYTES;
        if (m_storage_page->m_prune->checkState() == Qt::Checked && prune_target_gb <= m_blockchain_size_gb) {
            m_required_space_gb = prune_target_gb + m_chain_state_size_gb;
            storageRequiresMsg = tr("Approximately %1 GB of data will be stored in this directory.");
        }
        m_data_dir_page->m_size_warning_label->setText(
            tr("%1 will download and store a copy of the Bitcoin block chain.").arg(CLIENT_NAME) + " " +
            storageRequiresMsg.arg(m_required_space_gb) + " " +
            tr("The wallet will also be stored in this directory."));
    }
    UpdateFreeSpaceLabel();
}

void Intro::UpdateFreeSpaceLabel()
{
    QString freeString = tr("%n GB of space available", "", m_bytes_available / GB_BYTES);
    if (m_bytes_available < static_cast<uint64_t>(m_required_space_gb) * GB_BYTES) {
        freeString += " " + tr("(of %n GB needed)", "", m_required_space_gb);
        m_data_dir_page->m_free_space->setStyleSheet("QLabel { color: #800000 }");
    } else if (m_bytes_available / GB_BYTES - m_required_space_gb < 10) {
        freeString += " " + tr("(%n GB needed)", "", m_required_space_gb);
        m_data_dir_page->m_free_space->setStyleSheet("QLabel { color: #999900 }");
    } else {
        m_data_dir_page->m_free_space->setStyleSheet("");
    }
    m_data_dir_page->m_free_space->setText(freeString + ".");
}

void Intro::startThread()
{
    thread = new QThread(this);
    FreespaceChecker *executor = new FreespaceChecker(this);
    executor->moveToThread(thread);

    connect(executor, &FreespaceChecker::reply, this, &Intro::setStatus);
    connect(this, &Intro::requestCheck, executor, &FreespaceChecker::check);
    connect(thread, &QThread::finished, executor, &QObject::deleteLater);

    thread->start();
}

void Intro::checkPath(const QString &dataDir)
{
    mutex.lock();
    pathToCheck = dataDir;
    if(!signalled)
    {
        signalled = true;
        Q_EMIT requestCheck();
    }
    mutex.unlock();
}

QString Intro::getPathToCheck()
{
    QString retval;
    mutex.lock();
    retval = pathToCheck;
    signalled = false;
    mutex.unlock();
    return retval;
}
