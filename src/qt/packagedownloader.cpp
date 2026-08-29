// Copyright (c) 2025 The Bitcoin Purity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/packagedownloader.h>

#include <qt/guiutil.h>

#include <crypto/sha256.h>
#include <crypto/sha256.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <QApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QLabel>
#include <QMessageBox>
#include <QDateTime>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProcess>
#include <QEventLoop>
#include <QFont>
#include <QProgressBar>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

#include <array>
#include <cctype>
#include <fstream>
#include <functional>
#include <optional>
#include <string_view>
#include <vector>

namespace {

//! Restart the download when no bytes arrive for this long.
static constexpr qint64 STALL_TIMEOUT_MS{45'000};
//! Maximum resume attempts when the server ignores byte-range requests.
static constexpr int MAX_RANGE_RESUME_RETRIES{5};
//! How often to refresh the UI while hashing or extracting large archives.
static constexpr uint64_t HASH_PROGRESS_BYTES{64ULL << 20};

using ProgressPumpFn = std::function<void(int percent, const QString& detail)>;

bool HashFileSha256(const fs::path& path, uint256& hash_out, uint64_t total_bytes, const ProgressPumpFn& pump = {})
{
    CSHA256 hasher;
    std::ifstream file{path, std::ios::binary};
    if (!file) return false;
    std::array<unsigned char, 1 << 16> buffer{};
    uint64_t processed{0};
    uint64_t last_pump{0};
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        const std::streamsize bytes = file.gcount();
        if (bytes > 0) {
            hasher.Write(buffer.data(), static_cast<size_t>(bytes));
            processed += static_cast<uint64_t>(bytes);
            if (pump && total_bytes > 0 && processed - last_pump >= HASH_PROGRESS_BYTES) {
                const int percent = static_cast<int>(processed * 100 / total_bytes);
                pump(percent, QString());
                last_pump = processed;
            }
        }
    }
    if (!file.eof() && file.fail()) return false;
    hasher.Finalize(hash_out.begin());
    if (pump) pump(100, QString());
    return true;
}

uint64_t GetFileSize(const fs::path& path)
{
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    return ec ? 0 : size;
}

bool TruncateFile(const fs::path& path, uint64_t size)
{
    QFile file(GUIUtil::PathToQString(path));
    if (!file.open(QIODevice::ReadWrite)) return false;
    return file.resize(static_cast<qint64>(size));
}

std::string StandardSha256Hex(const uint256& hash)
{
    return HexStr(Span<const uint8_t>(hash.begin(), hash.size()));
}

std::optional<UniValue> ReadPackageManifest(const fs::path& datadir)
{
    const fs::path manifest_path = datadir / "bitcoinpurity-package.json";
    if (!fs::exists(manifest_path)) return std::nullopt;
    std::ifstream manifest_file{manifest_path};
    if (!manifest_file) return std::nullopt;
    const std::string contents((std::istreambuf_iterator<char>(manifest_file)), std::istreambuf_iterator<char>());
    UniValue json;
    if (!json.read(contents)) return std::nullopt;
    return json;
}

bool ValidateExtractedPackage(const fs::path& datadir, const OfficialDataPackage& package, QString& error)
{
    if (!fs::exists(datadir / "blocks") || !fs::is_directory(datadir / "blocks")) {
        error = QObject::tr("Extracted data is missing the blocks directory.");
        return false;
    }
    if (!fs::exists(datadir / "chainstate") || !fs::is_directory(datadir / "chainstate")) {
        error = QObject::tr("Extracted data is missing the chainstate directory.");
        return false;
    }
    if (!fs::exists(datadir / "chainstate" / "CURRENT")) {
        error = QObject::tr("Extracted chainstate appears incomplete.");
        return false;
    }

    const auto manifest = ReadPackageManifest(datadir);
    if (manifest && manifest->isObject()) {
        const std::string id = manifest->exists("id") ? manifest->find_value("id").get_str() : "";
        if (!id.empty() && id != package.id) {
            error = QObject::tr("Package manifest id does not match the selected package.");
            return false;
        }
        if (manifest->exists("base_blockhash")) {
            const auto hash = uint256::FromUserHex(manifest->find_value("base_blockhash").get_str());
            if (!hash || *hash != package.base_blockhash) {
                error = QObject::tr("Package base block hash does not match the expected value.");
                return false;
            }
        }
        if (manifest->exists("snapshot_height")) {
            const int height = manifest->find_value("snapshot_height").getInt<int>();
            if (height != package.snapshot_height) {
                error = QObject::tr("Package snapshot height does not match the expected value.");
                return false;
            }
        }
    }
    return true;
}

bool PathEndsWithIgnoreCase(const fs::path& path, std::string_view suffix)
{
    const std::string name = fs::PathToString(path.filename());
    if (name.size() < suffix.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), name.rbegin(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
    });
}

std::string ArchiveFilenameFromUri(const std::string& uri, const std::string& package_id)
{
    const QUrl url(QString::fromStdString(uri));
    const QString filename = url.fileName(QUrl::FullyDecoded);
    if (!filename.isEmpty()) {
        return filename.toStdString();
    }
    return package_id + ".zip";
}

bool ShouldSkipZipEntryPath(std::string_view entry)
{
    return entry.starts_with("__MACOSX/") || entry.starts_with("._") || entry.find("/._") != std::string_view::npos;
}

std::optional<std::vector<std::string>> ListZipEntryNames(const fs::path& archive_path, QString& error)
{
    QProcess process;
    process.setProgram(QStringLiteral("unzip"));
    process.setArguments({
        QStringLiteral("-Z1"),
        GUIUtil::PathToQString(archive_path),
    });
    process.start();
    if (!process.waitForStarted(-1)) {
        error = QObject::tr("Failed to start the archive listing tool.");
        return std::nullopt;
    }
    if (!process.waitForFinished(-1)) {
        error = QObject::tr("Archive listing was interrupted.");
        return std::nullopt;
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        error = QObject::tr("Could not read archive contents: %1")
            .arg(QString::fromLocal8Bit(process.readAllStandardError()));
        return std::nullopt;
    }

    std::vector<std::string> entries;
    const QStringList lines = QString::fromUtf8(process.readAllStandardOutput()).split('\n', Qt::SkipEmptyParts);
    entries.reserve(lines.size());
    for (const QString& line : lines) {
        entries.push_back(line.trimmed().toStdString());
    }
    return entries;
}

std::optional<int> DetectZipStripComponents(const std::vector<std::string>& entries)
{
    bool root_layout{false};
    std::optional<std::string> package_prefix;

    const auto consider_marker = [&](std::string_view marker) {
        for (const std::string& entry : entries) {
            if (ShouldSkipZipEntryPath(entry)) continue;

            if (entry == marker || entry.starts_with(marker)) {
                root_layout = true;
                return;
            }

            const std::string nested = std::string("/") + std::string(marker);
            const size_t pos = entry.find(nested);
            if (pos == std::string::npos) continue;

            const std::string prefix = entry.substr(0, pos);
            if (prefix.empty()) {
                root_layout = true;
                return;
            }
            if (!package_prefix) {
                package_prefix = prefix;
            } else if (*package_prefix != prefix) {
                package_prefix = std::nullopt;
                return;
            }
        }
    };

    consider_marker("blocks/");
    consider_marker("chainstate/");

    if (root_layout) return 0;
    if (!package_prefix) return std::nullopt;

    const int slash_count = static_cast<int>(std::count(package_prefix->begin(), package_prefix->end(), '/'));
    return slash_count + 1;
}

bool RunExtractProcess(const QString& program, const QStringList& arguments, QString& error, const ProgressPumpFn& pump = {})
{
    QProcess process;
    process.setProgram(program);
    process.setArguments(arguments);
    process.start();
    if (!process.waitForStarted(-1)) {
        return false;
    }
    while (!process.waitForFinished(250)) {
        if (pump) pump(-1, QString());
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        error = QObject::tr("Archive extraction failed: %1").arg(QString::fromLocal8Bit(process.readAllStandardError()));
        return false;
    }
    return true;
}

bool ExtractArchiveWithStrip(const fs::path& archive_path, const fs::path& datadir, int strip_components, QString& error, const ProgressPumpFn& pump = {})
{
    const QString archive = GUIUtil::PathToQString(archive_path);
    const QString dest = GUIUtil::PathToQString(datadir);
    QStringList args{
        QStringLiteral("-xf"),
        archive,
        QStringLiteral("-C"),
        dest,
        QStringLiteral("--exclude=__MACOSX"),
        QStringLiteral("--exclude=*/.DS_Store"),
        QStringLiteral("--exclude=*/._*"),
    };
    if (strip_components > 0) {
        args << QStringLiteral("--strip-components=%1").arg(strip_components);
    }

    error.clear();
    if (RunExtractProcess(QStringLiteral("bsdtar"), args, error, pump)) {
        return true;
    }
    const QString bsdtar_error = error;
    error.clear();
    if (RunExtractProcess(QStringLiteral("tar"), args, error, pump)) {
        return true;
    }
    error = bsdtar_error;
    return false;
}

bool IsPackageDataRoot(const fs::path& path)
{
    return fs::exists(path / "blocks") && fs::is_directory(path / "blocks") &&
           fs::exists(path / "chainstate") && fs::is_directory(path / "chainstate");
}

bool ShouldSkipExtractEntryName(const std::string& name)
{
    return name == ".package-download" || name == "__MACOSX";
}

bool HoistWrappedExtractRoot(const fs::path& datadir, QString& error)
{
    if (IsPackageDataRoot(datadir)) {
        return true;
    }

    fs::path wrapper;
    int wrapper_count{0};
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(datadir, ec)) {
        if (ec || !entry.is_directory()) continue;
        const std::string name = fs::PathToString(entry.path().filename());
        if (ShouldSkipExtractEntryName(name)) continue;
        if (IsPackageDataRoot(entry.path())) {
            wrapper = entry.path();
            ++wrapper_count;
        }
    }

    if (wrapper_count == 0) {
        error = QObject::tr("Extracted data is missing the blocks directory.");
        return false;
    }
    if (wrapper_count > 1) {
        error = QObject::tr("Archive contains multiple data roots; expected a single package layout.");
        return false;
    }

    for (const auto& entry : fs::directory_iterator(wrapper, ec)) {
        if (ec) {
            error = QObject::tr("Failed to normalize extracted package layout.");
            return false;
        }
        fs::path dest{datadir};
        dest /= entry.path().filename();
        if (fs::exists(dest)) {
            fs::remove_all(dest, ec);
            if (ec) {
                error = QObject::tr("Failed to normalize extracted package layout.");
                return false;
            }
        }
        fs::rename(entry.path(), dest, ec);
        if (ec) {
            error = QObject::tr("Failed to normalize extracted package layout.");
            return false;
        }
    }

    fs::remove(wrapper, ec);
    fs::remove_all(datadir / "__MACOSX", ec);

    if (!IsPackageDataRoot(datadir)) {
        error = QObject::tr("Extracted data is missing the blocks directory.");
        return false;
    }
    return true;
}

bool ExtractArchive(const fs::path& archive_path, const fs::path& datadir, QString& error, const ProgressPumpFn& pump = {})
{
    if (!PathEndsWithIgnoreCase(archive_path, ".zip")) {
        error = QObject::tr("Official data packages must be .zip archives.");
        return false;
    }

    if (pump) pump(-1, QObject::tr("Reading archive layout…"));

    QString list_error;
    const auto entries = ListZipEntryNames(archive_path, list_error);
    if (!entries) {
        error = list_error;
        return false;
    }

    const auto strip_components = DetectZipStripComponents(*entries);
    if (!strip_components) {
        error = QObject::tr("Could not determine the layout of the archive.");
        return false;
    }

    if (pump) pump(-1, QObject::tr("Extracting archive…"));

    if (ExtractArchiveWithStrip(archive_path, datadir, *strip_components, error, pump)) {
        fs::remove_all(datadir / "__MACOSX");
        if (IsPackageDataRoot(datadir)) {
            return true;
        }
        error = QObject::tr("Extracted data is missing the blocks directory.");
        return false;
    }

    // Fallback for systems without bsdtar/tar zip support.
    QStringList unzip_args{
        QStringLiteral("-q"),
        GUIUtil::PathToQString(archive_path),
        QStringLiteral("-d"),
        GUIUtil::PathToQString(datadir),
    };
    if (!RunExtractProcess(QStringLiteral("unzip"), unzip_args, error, pump)) {
        return false;
    }

    return HoistWrappedExtractRoot(datadir, error);
}

std::optional<uint64_t> ParseContentRangeTotal(const QByteArray& header)
{
    const QString value = QString::fromUtf8(header);
    const int slash = value.lastIndexOf('/');
    if (slash < 0) return std::nullopt;
    bool ok = false;
    const uint64_t total = value.mid(slash + 1).toULongLong(&ok);
    if (!ok || total == 0) return std::nullopt;
    return total;
}

bool AppendFileToFile(const fs::path& source, std::ofstream& out)
{
    std::ifstream in{source, std::ios::binary};
    if (!in) return false;
    std::array<char, 1 << 16> buffer{};
    while (in) {
        in.read(buffer.data(), buffer.size());
        const std::streamsize bytes = in.gcount();
        if (bytes > 0) {
            out.write(buffer.data(), bytes);
        }
    }
    return static_cast<bool>(in) || in.eof();
}

class PackageDownloadDialog : public QDialog
{
    Q_OBJECT

public:
    PackageDownloadDialog(const OfficialDataPackage& package, const fs::path& datadir, QWidget* parent)
        : QDialog(parent, GUIUtil::dialog_flags),
          m_package(package),
          m_datadir(datadir)
    {
        setWindowTitle(tr("Downloading official data package"));
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(12, 12, 12, 12);
        layout->setSpacing(10);
        layout->setSizeConstraint(QLayout::SetMinimumSize);

        m_status = new QLabel(tr("Preparing download…"), this);
        m_status->setWordWrap(true);
        m_status->setMinimumWidth(480);
        m_status->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::MinimumExpanding);
        m_status->setAlignment(Qt::AlignLeft | Qt::AlignTop);
        layout->addWidget(m_status);

        m_progress_percent = new QLabel(QStringLiteral("0.0%"), this);
        m_progress_percent->setAlignment(Qt::AlignHCenter);
        QFont percent_font = m_progress_percent->font();
        percent_font.setBold(true);
        percent_font.setPointSize(percent_font.pointSize() + 1);
        m_progress_percent->setFont(percent_font);
        m_progress_percent->setVisible(false);
        layout->addWidget(m_progress_percent);

        m_progress = new QProgressBar(this);
        m_progress->setRange(0, 100);
        m_progress->setValue(0);
        m_progress->setMinimum(0);
        m_progress->setMaximum(100);
        m_progress->setMinimumHeight(24);
        m_progress->setFixedHeight(24);
        m_progress->setTextVisible(true);
        m_progress->setFormat(QStringLiteral("%p%"));
        m_progress->setStyleSheet(
            "QProgressBar {"
            "  border: 1px solid #a0a0a0;"
            "  border-radius: 5px;"
            "  background-color: #ececec;"
            "  text-align: center;"
            "  color: #222;"
            "}"
            "QProgressBar::chunk {"
            "  background-color: #007aff;"
            "  border-radius: 4px;"
            "}");
        layout->addWidget(m_progress);

        m_progress_stats = new QLabel(this);
        m_progress_stats->setAlignment(Qt::AlignHCenter);
        m_progress_stats->setVisible(false);
        layout->addWidget(m_progress_stats);

        m_progress_eta = new QLabel(this);
        m_progress_eta->setAlignment(Qt::AlignHCenter);
        m_progress_eta->setVisible(false);
        layout->addWidget(m_progress_eta);

        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
        connect(buttons, &QDialogButtonBox::rejected, this, &PackageDownloadDialog::onCancel);
        layout->addWidget(buttons);

        setMinimumSize(520, 210);
        resize(minimumSize());

        m_manager = new QNetworkAccessManager(this);
        m_progress_timer = new QTimer(this);
        m_progress_timer->setInterval(250);
        connect(m_progress_timer, &QTimer::timeout, this, &PackageDownloadDialog::updateProgress);

        preparePaths();
        probeDownload();
    }

    bool succeeded() const { return m_success; }
    QString lastError() const { return m_last_error; }

private Q_SLOTS:
    void onCancel()
    {
        m_cancelled = true;
        abortActiveDownload();
        saveDownloadMeta();
        reject();
    }

    void updateProgress()
    {
        if (m_total_bytes == 0) return;
        updateDownloadProgressDisplay();
        checkDownloadStall();
    }

private:
    QString formatDownloadProgressText(uint64_t received, uint64_t total) const
    {
        const double percent = total > 0 ? received * 100.0 / total : 0.0;
        return tr("%1% complete — %2 of %3")
            .arg(QString::number(percent, 'f', 1))
            .arg(FormatArchiveSize(received))
            .arg(FormatArchiveSize(total));
    }

    void updateDownloadProgressDisplay()
    {
        const uint64_t received = downloadedBytes();
        const double percent = m_total_bytes > 0 ? received * 100.0 / m_total_bytes : 0.0;
        const int percent_int = static_cast<int>(percent);
        m_progress->setRange(0, 100);
        m_progress->setValue(percent_int);
        m_progress_percent->setText(tr("%1%").arg(QString::number(percent, 'f', 1)));
        m_progress_stats->setText(formatDownloadProgressText(received, m_total_bytes));

        const qint64 now_ms = QDateTime::currentMSecsSinceEpoch();
        const qint64 interval_ms = now_ms - m_last_progress_ms;
        if (interval_ms >= 500) {
            const uint64_t delta_bytes = received > m_last_progress_bytes ? received - m_last_progress_bytes : 0;
            if (delta_bytes > 0) {
                const double instant_speed = delta_bytes * 1000.0 / interval_ms;
                m_smoothed_bytes_per_sec = m_smoothed_bytes_per_sec <= 0
                    ? instant_speed
                    : m_smoothed_bytes_per_sec * 0.7 + instant_speed * 0.3;
            }
            m_last_progress_bytes = received;
            m_last_progress_ms = now_ms;
        }

        if (received >= m_total_bytes) {
            m_progress_eta->setText(tr("Finishing download…"));
        } else if (m_smoothed_bytes_per_sec > 0) {
            const uint64_t remaining_bytes = m_total_bytes - received;
            const qint64 eta_seconds = static_cast<qint64>(remaining_bytes / m_smoothed_bytes_per_sec);
            m_progress_eta->setText(tr("%1 remaining at %2/s")
                .arg(FormatRemainingTime(eta_seconds))
                .arg(FormatTransferRate(m_smoothed_bytes_per_sec)));
        } else {
            m_progress_eta->setText(tr("Estimating time remaining…"));
        }
    }

    void refreshDownloadProgressLayout()
    {
        layout()->activate();
        adjustSize();
        if (height() < minimumHeight()) {
            resize(width(), minimumHeight());
        }
    }

    void showDownloadProgressUi(bool visible)
    {
        m_progress->setVisible(visible);
        m_progress_percent->setVisible(visible);
        m_progress_stats->setVisible(visible);
        m_progress_eta->setVisible(visible);
        if (visible) {
            refreshDownloadProgressLayout();
        }
    }

    void beginProcessingPhase(const QString& status, const QString& detail)
    {
        showDownloadProgressUi(true);
        setStatusText(status);
        m_progress->setRange(0, 0);
        m_progress_percent->setText(QString());
        m_progress_stats->setText(detail);
        m_progress_eta->setText(tr("Please wait…"));
        refreshDownloadProgressLayout();
        QApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    }

    void updateProcessingPhase(int percent, const QString& detail)
    {
        if (percent < 0) {
            m_progress->setRange(0, 0);
            m_progress_percent->setText(QString());
        } else {
            m_progress->setRange(0, 100);
            m_progress->setValue(percent);
            m_progress_percent->setText(tr("%1%").arg(percent));
        }
        if (!detail.isEmpty()) {
            m_progress_stats->setText(detail);
        }
        m_progress_eta->setText(tr("Please wait…"));
        refreshDownloadProgressLayout();
        QApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    }

    void resetDownloadProgressMetrics()
    {
        const qint64 now_ms = QDateTime::currentMSecsSinceEpoch();
        m_last_progress_ms = now_ms;
        m_last_progress_bytes = downloadedBytes();
        m_smoothed_bytes_per_sec = 0;
        m_stall_checkpoint_bytes = m_last_progress_bytes;
        m_stall_checkpoint_ms = now_ms;
        showDownloadProgressUi(true);
        updateDownloadProgressDisplay();
    }

    void resetStallCheckpoint()
    {
        m_stall_checkpoint_bytes = downloadedBytes();
        m_stall_checkpoint_ms = QDateTime::currentMSecsSinceEpoch();
    }

    void checkDownloadStall()
    {
        if (m_cancelled || !m_download_reply || downloadedBytes() >= m_total_bytes) return;

        const uint64_t received = downloadedBytes();
        const qint64 now_ms = QDateTime::currentMSecsSinceEpoch();
        if (received > m_stall_checkpoint_bytes) {
            m_stall_checkpoint_bytes = received;
            m_stall_checkpoint_ms = now_ms;
            return;
        }

        if (now_ms - m_stall_checkpoint_ms < STALL_TIMEOUT_MS) return;

        m_stall_checkpoint_ms = now_ms;
        setStatusText(tr("Download stalled, retrying…"));
        startDownload();
    }

    static QString FormatTransferRate(double bytes_per_sec)
    {
        return FormatArchiveSize(static_cast<quint64>(bytes_per_sec));
    }

    QString FormatRemainingTime(qint64 seconds) const
    {
        if (seconds < 0) {
            return tr("Unknown time");
        }
        if (seconds < 60) {
            return tr("Less than a minute");
        }
        const qint64 hours = seconds / 3600;
        const qint64 minutes = (seconds % 3600) / 60;
        if (hours > 0) {
            return tr("About %1 h %2 m").arg(hours).arg(minutes);
        }
        return tr("About %1 minutes").arg(minutes);
    }

    void setStatusText(const QString& text)
    {
        m_status->setText(text);
        m_status->updateGeometry();
        layout()->activate();
        adjustSize();
        if (height() < minimumHeight()) {
            resize(width(), minimumHeight());
        }
    }

    static QString FormatArchiveSize(quint64 bytes)
    {
        static constexpr quint64 GB_BYTES = 1024ULL * 1024 * 1024;
        if (bytes >= GB_BYTES) {
            return tr("%1 GB").arg(QString::number(bytes / static_cast<double>(GB_BYTES), 'f', 1));
        }
        static constexpr quint64 MB_BYTES = 1024ULL * 1024;
        return tr("%1 MB").arg(bytes / MB_BYTES);
    }

    void promptDeleteDownloadedArchive()
    {
        if (!fs::exists(m_download_path)) return;

        const uint64_t file_size = GetFileSize(m_download_path);
        const QString archive_name = GUIUtil::PathToQString(m_download_path.filename());
        const auto answer = QMessageBox::question(
            this,
            tr("Delete downloaded archive?"),
            tr("The official data package was installed successfully.\n\nDelete %1 (%2) to free disk space?")
                .arg(archive_name)
                .arg(FormatArchiveSize(file_size)),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::Yes);

        if (answer == QMessageBox::Yes) {
            std::error_code ec;
            fs::remove(m_download_path, ec);
        }
    }

    void preparePaths()
    {
        m_download_dir = m_datadir / ".package-download";
        fs::create_directories(m_download_dir);
        const std::string archive_name = ArchiveFilenameFromUri(m_package.download_uri, m_package.id);
        m_download_path = m_download_dir / fs::PathFromString(archive_name);
        m_meta_path = fs::PathFromString(fs::PathToString(m_download_path) + ".download.json");
    }

    QNetworkRequest makeDownloadRequest() const
    {
        QNetworkRequest request(QUrl(QString::fromStdString(m_package.download_uri)));
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
        return request;
    }

    void fail(const QString& message)
    {
        m_last_error = message;
        setStatusText(message);
        m_success = false;
        abortActiveDownload();
        m_progress_timer->stop();
        reject();
    }

    static std::optional<int> HttpStatusCode(const QNetworkReply* reply)
    {
        if (!reply) return std::nullopt;
        const QVariant status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        if (!status.isValid()) return std::nullopt;
        return status.toInt();
    }

    static bool HttpStatusOk(const QNetworkReply* reply)
    {
        const auto status = HttpStatusCode(reply);
        return !status || (*status >= 200 && *status < 300);
    }

    static QString HttpStatusMessage(const QNetworkReply* reply, const QString& fallback)
    {
        const auto status = HttpStatusCode(reply);
        if (status && *status >= 400) {
            return QObject::tr("Download server returned HTTP %1.").arg(*status);
        }
        return fallback;
    }

    void abortActiveDownload()
    {
        if (m_probe_reply) {
            m_probe_reply->abort();
            m_probe_reply = nullptr;
        }
        if (m_download_reply) {
            m_recovering_stall = true;
            m_download_reply->abort();
            m_download_reply->deleteLater();
            m_download_reply = nullptr;
            m_recovering_stall = false;
        }
        m_download_output.close();
    }

    void probeDownload()
    {
        QNetworkRequest request = makeDownloadRequest();
        m_probe_reply = m_manager->head(request);
        connect(m_probe_reply, &QNetworkReply::finished, this, &PackageDownloadDialog::onHeadProbeFinished);
    }

    void probeDownloadWithGet()
    {
        QNetworkRequest request = makeDownloadRequest();
        request.setRawHeader("Range", "bytes=0-0");
        m_probe_reply = m_manager->get(request);
        connect(m_probe_reply, &QNetworkReply::finished, this, &PackageDownloadDialog::onGetProbeFinished);
    }

    void startDownloadAfterProbe(uint64_t total_bytes, bool supports_ranges)
    {
        if (m_package.archive_size_bytes > 0) {
            total_bytes = m_package.archive_size_bytes;
        }

        if (total_bytes == 0) {
            fail(tr("Could not determine download size from the server."));
            return;
        }

        m_total_bytes = total_bytes;
        m_supports_ranges = supports_ranges;
        if (!initDownload()) return;

        resetDownloadProgressMetrics();
        setStatusText(tr("Downloading %1…").arg(QString::fromStdString(m_package.id)));
        m_progress_timer->start();
        startDownload();
    }

    void onHeadProbeFinished()
    {
        if (m_cancelled) return;

        uint64_t total_bytes{0};
        bool supports_ranges{false};
        bool head_usable{false};

        if (m_probe_reply) {
            if (m_probe_reply->error() == QNetworkReply::NoError && HttpStatusOk(m_probe_reply)) {
                const QVariant length_header = m_probe_reply->header(QNetworkRequest::ContentLengthHeader);
                if (length_header.isValid()) {
                    total_bytes = length_header.toULongLong();
                }
                const QByteArray accept_ranges = m_probe_reply->rawHeader("Accept-Ranges");
                supports_ranges = accept_ranges.compare("bytes", Qt::CaseInsensitive) == 0;
                head_usable = total_bytes > 0;
            }
        }

        if (m_probe_reply) {
            m_probe_reply->deleteLater();
            m_probe_reply = nullptr;
        }

        if (head_usable) {
            startDownloadAfterProbe(total_bytes, supports_ranges);
            return;
        }

        probeDownloadWithGet();
    }

    void onGetProbeFinished()
    {
        if (m_cancelled) return;

        uint64_t total_bytes{0};
        bool supports_ranges{false};

        if (m_probe_reply) {
            const auto status = HttpStatusCode(m_probe_reply);
            if (status && *status == 206) {
                if (const auto total = ParseContentRangeTotal(m_probe_reply->rawHeader("Content-Range"))) {
                    total_bytes = *total;
                }
                supports_ranges = true;
            } else if (m_probe_reply->error() == QNetworkReply::NoError && status && *status == 200) {
                const QVariant length_header = m_probe_reply->header(QNetworkRequest::ContentLengthHeader);
                if (length_header.isValid()) {
                    total_bytes = length_header.toULongLong();
                }
            } else if (status && *status >= 400) {
                fail(tr("The download URL returned HTTP %1.\n\n%2")
                    .arg(*status)
                    .arg(QString::fromStdString(m_package.download_uri)));
                m_probe_reply->deleteLater();
                m_probe_reply = nullptr;
                return;
            } else if (m_probe_reply->error() != QNetworkReply::NoError) {
                fail(tr("Could not probe download URL: %1").arg(m_probe_reply->errorString()));
                m_probe_reply->deleteLater();
                m_probe_reply = nullptr;
                return;
            }

            const QByteArray accept_ranges = m_probe_reply->rawHeader("Accept-Ranges");
            if (accept_ranges.compare("bytes", Qt::CaseInsensitive) == 0) {
                supports_ranges = true;
            }
        }
        if (m_probe_reply) {
            m_probe_reply->deleteLater();
            m_probe_reply = nullptr;
        }

        startDownloadAfterProbe(total_bytes, supports_ranges);
    }

    struct DownloadMetaIdentity {
        std::string package_id;
        std::string archive_sha256_hex;
        uint64_t total_bytes{0};
    };

    std::optional<DownloadMetaIdentity> readDownloadMetaIdentity() const
    {
        if (!fs::exists(m_meta_path)) return std::nullopt;
        std::ifstream meta_file{m_meta_path};
        if (!meta_file) return std::nullopt;
        const std::string contents((std::istreambuf_iterator<char>(meta_file)), std::istreambuf_iterator<char>());
        UniValue meta;
        if (!meta.read(contents) || !meta.isObject()) return std::nullopt;

        try {
            DownloadMetaIdentity identity;
            identity.package_id = meta.find_value("package_id").get_str();
            identity.archive_sha256_hex = meta.find_value("archive_sha256").get_str();
            identity.total_bytes = meta.find_value("total_bytes").getInt<uint64_t>();
            return identity;
        } catch (const std::runtime_error&) {
            return std::nullopt;
        }
    }

    bool metaIdentityMatchesPackage(const DownloadMetaIdentity& identity) const
    {
        if (identity.package_id != m_package.id) return false;
        if (identity.archive_sha256_hex != StandardSha256Hex(m_package.archive_sha256)) return false;
        if (identity.total_bytes == m_total_bytes) return true;
        if (m_package.archive_size_bytes > 0 && identity.total_bytes == m_package.archive_size_bytes) {
            return m_total_bytes == m_package.archive_size_bytes || m_total_bytes == 0;
        }
        return false;
    }

    bool downloadMetaMatches() const
    {
        const auto identity = readDownloadMetaIdentity();
        return identity && metaIdentityMatchesPackage(*identity);
    }

    void saveDownloadMeta()
    {
        UniValue meta(UniValue::VOBJ);
        meta.pushKV("package_id", m_package.id);
        meta.pushKV("download_uri", m_package.download_uri);
        meta.pushKV("archive_sha256", StandardSha256Hex(m_package.archive_sha256));
        meta.pushKV("total_bytes", static_cast<int64_t>(m_total_bytes));

        std::ofstream meta_file{m_meta_path};
        if (meta_file) {
            meta_file << meta.write();
        }
    }

    void clearPartialDownload()
    {
        const std::string base = fs::PathToString(m_download_path);
        for (int i = 0; ; ++i) {
            const fs::path part = fs::PathFromString(strprintf("%s.part.%04d", base, i));
            if (!fs::exists(part)) break;
            fs::remove(part);
        }
        fs::remove(m_download_path);
        fs::remove(m_meta_path);
    }

    bool migrateLegacyParallelParts()
    {
        const std::string base = fs::PathToString(m_download_path);
        std::vector<fs::path> parts;
        for (int i = 0; ; ++i) {
            const fs::path part = fs::PathFromString(strprintf("%s.part.%04d", base, i));
            if (!fs::exists(part)) break;
            parts.push_back(part);
        }
        if (parts.empty()) return true;

        const uint64_t existing = GetFileSize(m_download_path);
        if (existing > 0) {
            for (const fs::path& part : parts) {
                fs::remove(part);
            }
            return true;
        }

        std::ofstream out{m_download_path, std::ios::binary | std::ios::trunc};
        if (!out) {
            fail(tr("Cannot write download file while migrating previous partial download."));
            return false;
        }

        for (const fs::path& part : parts) {
            if (!AppendFileToFile(part, out)) {
                fail(tr("Failed to migrate a previous partial download."));
                return false;
            }
            fs::remove(part);
        }
        return true;
    }

    bool initDownload()
    {
        const uint64_t existing = GetFileSize(m_download_path);
        const auto identity = readDownloadMetaIdentity();
        const bool identity_matches = identity && metaIdentityMatchesPackage(*identity);

        if (identity_matches) {
            if (!migrateLegacyParallelParts()) return false;
        } else if (existing > 0 && existing < m_total_bytes) {
            // Partial download: keep the file unless meta identifies a different package.
            if (identity &&
                (identity->package_id != m_package.id ||
                 identity->archive_sha256_hex != StandardSha256Hex(m_package.archive_sha256))) {
                clearPartialDownload();
            }
        } else if (existing == 0) {
            clearPartialDownload();
        }
        // existing >= m_total_bytes: keep complete file and proceed to verification.

        if (GetFileSize(m_download_path) > m_total_bytes) {
            if (!TruncateFile(m_download_path, m_total_bytes)) {
                fs::remove(m_download_path);
            }
        }

        saveDownloadMeta();
        return true;
    }

    uint64_t downloadedBytes() const
    {
        return std::min(GetFileSize(m_download_path), m_total_bytes);
    }

    void startDownload()
    {
        if (m_download_reply) {
            m_recovering_stall = true;
            m_download_reply->abort();
            m_download_reply->deleteLater();
            m_download_reply = nullptr;
            m_recovering_stall = false;
        }
        m_download_output.close();

        uint64_t existing = GetFileSize(m_download_path);
        if (existing > m_total_bytes) {
            TruncateFile(m_download_path, m_total_bytes);
            existing = m_total_bytes;
        }
        if (existing >= m_total_bytes) {
            onDownloadComplete();
            return;
        }

        m_bytes_at_request_start = existing;
        const bool resuming = existing > 0;

        QNetworkRequest request = makeDownloadRequest();
        if (resuming) {
            request.setRawHeader("Range", QByteArray("bytes=") + QByteArray::number(existing) + '-');
        }

        m_download_output.setFileName(GUIUtil::PathToQString(m_download_path));
        const QIODevice::OpenMode mode = existing > 0 ? QIODevice::Append : QIODevice::WriteOnly;
        if (!m_download_output.open(mode)) {
            fail(tr("Cannot write to download path."));
            return;
        }

        m_download_reply = m_manager->get(request);
        connect(m_download_reply, &QNetworkReply::readyRead, this, [this]() {
            if (m_download_reply) {
                m_download_output.write(m_download_reply->readAll());
                m_download_output.flush();
            }
        });
        connect(m_download_reply, &QNetworkReply::finished, this, [this, resuming]() {
            onDownloadFinished(resuming);
        });

        resetStallCheckpoint();
    }

    void onDownloadFinished(bool resuming)
    {
        if (m_cancelled) return;
        if (!m_download_reply) return;

        const QNetworkReply::NetworkError error = m_download_reply->error();
        const QString error_string = m_download_reply->errorString();
        const bool http_ok = HttpStatusOk(m_download_reply);
        const QString http_error = HttpStatusMessage(m_download_reply, tr("Download failed."));
        const auto status = HttpStatusCode(m_download_reply);
        m_download_reply->deleteLater();
        m_download_reply = nullptr;
        m_download_output.close();

        if (error != QNetworkReply::NoError) {
            if (error == QNetworkReply::OperationCanceledError) {
                if (!m_cancelled && !m_recovering_stall) {
                    saveDownloadMeta();
                    startDownload();
                }
                return;
            }
            saveDownloadMeta();
            fail(tr("Download failed: %1").arg(error_string));
            return;
        }

        if (!http_ok) {
            saveDownloadMeta();
            fail(http_error);
            return;
        }

        if (status && *status == 200 && resuming) {
            TruncateFile(m_download_path, m_bytes_at_request_start);
            if (++m_range_resume_retries > MAX_RANGE_RESUME_RETRIES) {
                saveDownloadMeta();
                fail(tr("Download server ignored byte-range resume requests too many times. Remove %1 and try again.")
                    .arg(GUIUtil::PathToQString(m_download_dir)));
                return;
            }
            saveDownloadMeta();
            startDownload();
            return;
        }

        m_range_resume_retries = 0;

        const uint64_t file_size = GetFileSize(m_download_path);
        if (file_size > m_total_bytes) {
            TruncateFile(m_download_path, m_total_bytes);
        }

        if (downloadedBytes() < m_total_bytes) {
            saveDownloadMeta();
            startDownload();
            return;
        }

        onDownloadComplete();
    }

    void onDownloadComplete()
    {
        m_progress_timer->stop();
        fs::remove(m_meta_path);
        verifyAndExtract();
    }

    void verifyAndExtract()
    {
        m_progress_timer->stop();

        const ProgressPumpFn pump = [this](int percent, const QString& detail) {
            updateProcessingPhase(percent, detail);
        };

        beginProcessingPhase(tr("Verifying download…"), tr("Checking file size…"));

        const uint64_t file_size = GetFileSize(m_download_path);
        if (file_size != m_total_bytes) {
            fail(tr("Downloaded file size mismatch: got %1 bytes, expected %2 bytes.")
                .arg(file_size)
                .arg(m_total_bytes));
            return;
        }

        beginProcessingPhase(tr("Verifying download…"), tr("Computing SHA256 hash…"));
        uint256 file_hash;
        if (!HashFileSha256(m_download_path, file_hash, m_total_bytes, [&](int percent, const QString&) {
                updateProcessingPhase(percent, tr("Computing SHA256 hash… %1%").arg(percent));
            })) {
            fail(tr("Could not compute SHA256 hash of the downloaded file."));
            return;
        }
        if (file_hash != m_package.archive_sha256) {
            if (file_size > 0 && file_size < 1024 * 1024) {
                fail(tr("Downloaded file failed hash verification. The server may have returned an error page instead of the archive (got %1 bytes). Check that the download URL is correct and the package is published.")
                    .arg(file_size));
            } else {
                fail(tr("Downloaded file failed hash verification.\n\nExpected: %1\nActual:   %2\n\nIf the download completed fully, the archive_sha256 in the package config may be wrong.")
                    .arg(QString::fromStdString(StandardSha256Hex(m_package.archive_sha256)))
                    .arg(QString::fromStdString(StandardSha256Hex(file_hash))));
            }
            return;
        }

        beginProcessingPhase(tr("Extracting data package…"), tr("This may take several minutes…"));

        QString extract_error;
        if (!ExtractArchive(m_download_path, m_datadir, extract_error, pump)) {
            fail(extract_error);
            return;
        }

        beginProcessingPhase(tr("Extracting data package…"), tr("Validating extracted data…"));

        QString validate_error;
        if (!ValidateExtractedPackage(m_datadir, m_package, validate_error)) {
            fail(validate_error);
            return;
        }

        showDownloadProgressUi(true);
        setStatusText(tr("Official data package installed successfully."));
        m_progress->setRange(0, 100);
        m_progress->setValue(100);
        m_progress_percent->setText(tr("100%"));
        m_progress_stats->setText(tr("Installation complete."));
        m_progress_eta->setText(QString());
        QApplication::processEvents();
        promptDeleteDownloadedArchive();
        m_success = true;
        accept();
    }

    OfficialDataPackage m_package;
    fs::path m_datadir;
    fs::path m_download_dir;
    fs::path m_download_path;
    fs::path m_meta_path;

    QNetworkAccessManager* m_manager{nullptr};
    QNetworkReply* m_probe_reply{nullptr};
    QNetworkReply* m_download_reply{nullptr};
    QFile m_download_output;

    uint64_t m_total_bytes{0};
    uint64_t m_bytes_at_request_start{0};
    bool m_supports_ranges{false};
    int m_range_resume_retries{0};

    QLabel* m_status{nullptr};
    QProgressBar* m_progress{nullptr};
    QLabel* m_progress_percent{nullptr};
    QLabel* m_progress_stats{nullptr};
    QLabel* m_progress_eta{nullptr};
    QTimer* m_progress_timer{nullptr};
    qint64 m_last_progress_ms{0};
    uint64_t m_last_progress_bytes{0};
    double m_smoothed_bytes_per_sec{0};
    bool m_cancelled{false};
    bool m_recovering_stall{false};
    bool m_success{false};
    QString m_last_error;
    uint64_t m_stall_checkpoint_bytes{0};
    qint64 m_stall_checkpoint_ms{0};
};

#include <qt/packagedownloader.moc>

} // namespace

bool PackageDownloader::runBlocking(const OfficialDataPackage& package, const QString& data_dir, QWidget* parent)
{
    PackageDownloadDialog dialog(package, GUIUtil::QStringToPath(data_dir), parent);
    if (dialog.exec() != QDialog::Accepted || !dialog.succeeded()) {
        const QString detail = dialog.lastError();
        const QString message = detail.isEmpty()
            ? QObject::tr("Failed to install the official data package. You can try again or choose to sync from the network instead.")
            : QObject::tr("Failed to install the official data package:\n\n%1\n\nYou can try again or choose to sync from the network instead.").arg(detail);
        QMessageBox::critical(parent, QApplication::applicationName(), message);
        return false;
    }
    return true;
}
