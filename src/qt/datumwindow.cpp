// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license.
#include <qt/datumwindow.h>

#include <mining/datum_bridge.h>

#include <QCloseEvent>
#include <QDateTime>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHideEvent>
#include <QLabel>
#include <QSettings>
#include <QShowEvent>
#include <QTableWidget>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace {
QLabel* ValueLabel()
{
    auto* label = new QLabel(QStringLiteral("—"));
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    label->setWordWrap(true);
    return label;
}

QString TimeText(uint64_t milliseconds)
{
    if (!milliseconds) return QStringLiteral("—");
    return QDateTime::fromMSecsSinceEpoch(milliseconds).toString(Qt::ISODate);
}

QString DurationText(uint64_t milliseconds)
{
    if (!milliseconds) return QStringLiteral("—");
    const uint64_t seconds = milliseconds / 1000;
    const uint64_t days = seconds / 86400;
    const uint64_t hours = (seconds / 3600) % 24;
    const uint64_t minutes = (seconds / 60) % 60;
    const uint64_t remaining = seconds % 60;
    if (days) return QStringLiteral("%1d %2h %3m").arg(days).arg(hours).arg(minutes);
    if (hours) return QStringLiteral("%1h %2m %3s").arg(hours).arg(minutes).arg(remaining);
    return QStringLiteral("%1m %2s").arg(minutes).arg(remaining);
}

QString AgeText(uint64_t milliseconds, uint64_t now)
{
    return milliseconds && now >= milliseconds ? DurationText(now - milliseconds) + QObject::tr(" ago") : QStringLiteral("—");
}

QString HashrateText(double ths)
{
    if (ths >= 1000000) return QStringLiteral("%1 EH/s").arg(ths / 1000000, 0, 'f', 2);
    if (ths >= 1000) return QStringLiteral("%1 PH/s").arg(ths / 1000, 0, 'f', 2);
    if (ths >= 1) return QStringLiteral("%1 TH/s").arg(ths, 0, 'f', 2);
    return QStringLiteral("%1 GH/s").arg(ths * 1000, 0, 'f', 1);
}

void AddRow(QFormLayout* form, const QString& name, QLabel*& value)
{
    value = ValueLabel();
    form->addRow(name, value);
}
} // namespace

DatumWindow::DatumWindow(QWidget* parent) : QWidget(parent, Qt::Window), m_timer(new QTimer(this))
{
    setObjectName(QStringLiteral("datumWindow"));
    setWindowTitle(tr("DATUM Mining Status"));
    setMinimumSize(900, 600);
    resize(1100, 720);

    auto* layout = new QVBoxLayout(this);
    m_warning = new QLabel;
    m_warning->setWordWrap(true);
    m_warning->setStyleSheet(QStringLiteral("QLabel { color: #b45309; font-weight: 600; padding: 6px; }"));
    m_warning->hide();
    layout->addWidget(m_warning);

    auto* tabs = new QTabWidget;
    layout->addWidget(tabs);

    auto* overview = new QWidget;
    auto* overview_layout = new QVBoxLayout(overview);
    auto* runtime_group = new QGroupBox(tr("Runtime and Network"));
    auto* runtime = new QFormLayout(runtime_group);
    AddRow(runtime, tr("Status"), m_status);
    AddRow(runtime, tr("DATUM uptime"), m_uptime);
    AddRow(runtime, tr("Stratum listener"), m_listen);
    AddRow(runtime, tr("Authentication"), m_auth);
    AddRow(runtime, tr("Port mapping"), m_mapping);
    AddRow(runtime, tr("Active payout address"), m_payout);
    AddRow(runtime, tr("Configured payout address"), m_configured_payout);
    AddRow(runtime, tr("Active Coinbase tag"), m_coinbase_tag);
    AddRow(runtime, tr("Configured Coinbase tag"), m_configured_coinbase_tag);
    overview_layout->addWidget(runtime_group);

    auto* mining_group = new QGroupBox(tr("Mining Overview"));
    auto* mining = new QFormLayout(mining_group);
    AddRow(mining, tr("Share difficulty"), m_difficulty);
    AddRow(mining, tr("Miners"), m_clients);
    AddRow(mining, tr("Estimated hashrate"), m_hashrate);
    AddRow(mining, tr("Session shares"), m_shares);
    AddRow(mining, tr("Last accepted share"), m_last_share);
    overview_layout->addWidget(mining_group);
    overview_layout->addStretch();
    tabs->addTab(overview, tr("Overview"));

    auto* miners_page = new QWidget;
    auto* miners_layout = new QVBoxLayout(miners_page);
    m_miners = new QTableWidget;
    m_miners->setColumnCount(11);
    m_miners->setHorizontalHeaderLabels({tr("Worker"), tr("Remote IP"), tr("Miner"), tr("Status"), tr("Connected"), tr("Difficulty"), tr("Est. hashrate"), tr("Accepted"), tr("Rejected"), tr("Reject rate"), tr("Last share")});
    m_miners->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_miners->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_miners->setAlternatingRowColors(true);
    m_miners->verticalHeader()->hide();
    m_miners->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_miners->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    miners_layout->addWidget(m_miners);
    tabs->addTab(miners_page, tr("Miners"));

    auto* job_page = new QWidget;
    auto* job_layout = new QVBoxLayout(job_page);
    auto* job_group = new QGroupBox(tr("Current Job"));
    auto* job = new QFormLayout(job_group);
    AddRow(job, tr("Height"), m_height);
    AddRow(job, tr("Job ID"), m_job_id);
    AddRow(job, tr("Job age"), m_job_age);
    AddRow(job, tr("Previous block hash"), m_prev_hash);
    AddRow(job, tr("nBits"), m_nbits);
    AddRow(job, tr("Network difficulty"), m_network_difficulty);
    AddRow(job, tr("Template"), m_template);
    AddRow(job, tr("Coinbase value"), m_coinbase);
    AddRow(job, tr("Last template result"), m_template_result);
    job_layout->addWidget(job_group);

    auto* diagnostics_group = new QGroupBox(tr("Block Submission and Diagnostics"));
    auto* diagnostics = new QFormLayout(diagnostics_group);
    AddRow(diagnostics, tr("Block candidates"), m_candidates);
    AddRow(diagnostics, tr("Last block result"), m_block_result);
    AddRow(diagnostics, tr("Last share rejection"), m_rejection);
    job_layout->addWidget(diagnostics_group);
    job_layout->addStretch();
    tabs->addTab(job_page, tr("Job and Diagnostics"));

    connect(m_timer, &QTimer::timeout, this, [this] { refresh(); });
    m_timer->setInterval(1000);

    const QByteArray geometry{QSettings().value(QStringLiteral("DatumWindowGeometry")).toByteArray()};
    if (!geometry.isEmpty()) restoreGeometry(geometry);
}

void DatumWindow::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    refresh();
    m_timer->start();
}

void DatumWindow::hideEvent(QHideEvent* event)
{
    m_timer->stop();
    QWidget::hideEvent(event);
}

void DatumWindow::closeEvent(QCloseEvent* event)
{
    m_timer->stop();
    QSettings().setValue(QStringLiteral("DatumWindowGeometry"), saveGeometry());
    QWidget::closeEvent(event);
}

void DatumWindow::refresh()
{
    const mining::DatumStatusSnapshot status{mining::GetDatumStatusSnapshot()};
    const uint64_t now = QDateTime::currentMSecsSinceEpoch();
    m_status->setText(QString::fromStdString(status.status));
    m_uptime->setText(status.running && status.session_started_ms ? DurationText(now - status.session_started_ms) : QStringLiteral("—"));
    m_listen->setText(QStringLiteral("%1:%2").arg(QString::fromStdString(status.listen)).arg(status.port));
    m_auth->setText(status.auth_required ? tr("Required") : tr("Disabled"));
    QString mapping = status.mapping_requested ? (status.mapping_active ? tr("Active") : tr("Not active")) : tr("Not requested");
    if (!status.mapping_protocol.empty()) mapping += QStringLiteral(" · ") + QString::fromStdString(status.mapping_protocol);
    if (!status.mapping_external.empty()) mapping += QStringLiteral(" · ") + QString::fromStdString(status.mapping_external);
    if (status.mapping_lifetime) mapping += tr(" · lifetime %1s").arg(status.mapping_lifetime);
    if (!status.mapping_error.empty()) mapping += QStringLiteral(" · ") + QString::fromStdString(status.mapping_error);
    m_mapping->setText(mapping);
    m_payout->setText(status.payout_address.empty() ? QStringLiteral("—") : QString::fromStdString(status.payout_address));
    QString configured_payout = status.configured_payout_address.empty() ? QStringLiteral("—") : QString::fromStdString(status.configured_payout_address);
    m_configured_payout->setText(configured_payout);
    m_coinbase_tag->setText(status.coinbase_tag.empty() ? QStringLiteral("—") : QString::fromStdString(status.coinbase_tag));
    QString configured_coinbase_tag = status.configured_coinbase_tag.empty() ? QStringLiteral("—") : QString::fromStdString(status.configured_coinbase_tag);
    m_configured_coinbase_tag->setText(configured_coinbase_tag);

    const bool public_listener = status.listen == "0.0.0.0" || status.listen == "::";
    if (status.enabled && public_listener && !status.auth_required) {
        m_warning->setText(tr("Warning: Stratum is listening publicly without authentication."));
        m_warning->show();
    } else {
        m_warning->hide();
    }

    m_difficulty->setText(QString::number(status.share_difficulty));
    m_clients->setText(tr("%1 connected · %2 subscribed · %3 authorized").arg(status.clients).arg(status.subscribed_clients).arg(status.authorized_clients));
    m_hashrate->setText(HashrateText(status.estimated_hashrate_ths) + tr(" (estimated from accepted shares)"));
    const uint64_t total = status.session_accepted_shares + status.session_rejected_shares;
    const double reject_rate = total ? 100.0 * status.session_rejected_shares / total : 0.0;
    m_shares->setText(tr("%1 accepted · %2 rejected · %3% rejected").arg(status.session_accepted_shares).arg(status.session_rejected_shares).arg(reject_rate, 0, 'f', 2));
    m_last_share->setText(status.last_share_time_ms ? TimeText(status.last_share_time_ms) + QStringLiteral(" · ") + AgeText(status.last_share_time_ms, now) : QStringLiteral("—"));

    m_height->setText(status.current_height ? QString::number(status.current_height) : QStringLiteral("—"));
    m_job_id->setText(status.job_id.empty() ? QStringLiteral("—") : QString::fromStdString(status.job_id));
    m_job_age->setText(AgeText(status.job_created_ms, now));
    m_prev_hash->setText(status.previous_block_hash.empty() ? QStringLiteral("—") : QString::fromStdString(status.previous_block_hash));
    m_nbits->setText(status.nbits ? QStringLiteral("%1").arg(status.nbits, 8, 16, QLatin1Char('0')) : QStringLiteral("—"));
    m_network_difficulty->setText(status.network_difficulty ? QString::number(status.network_difficulty, 'g', 12) : QStringLiteral("—"));
    m_template->setText(status.job_id.empty() ? QStringLiteral("—") : tr("%1 transactions · %2 bytes · %3 weight").arg(status.transaction_count).arg(status.template_size).arg(status.template_weight));
    m_coinbase->setText(status.job_id.empty() ? QStringLiteral("—") : tr("%1 sat").arg(status.coinbase_value));
    QString template_result = status.last_template_update_ms ? TimeText(status.last_template_update_ms) + QStringLiteral(" · ") + (status.last_template_success ? tr("success") : tr("error")) : QStringLiteral("—");
    if (!status.last_template_error.empty()) template_result += QStringLiteral(" · ") + QString::fromStdString(status.last_template_error);
    m_template_result->setText(template_result);
    m_candidates->setText(tr("%1 candidates · %2 accepted · %3 rejected").arg(status.block_candidates).arg(status.block_submissions_accepted).arg(status.block_submissions_rejected));
    QString block_result = status.last_block_time_ms ? TimeText(status.last_block_time_ms) : QStringLiteral("—");
    if (!status.last_block_hash.empty()) block_result += QStringLiteral(" · ") + QString::fromStdString(status.last_block_hash);
    if (!status.last_block_result.empty()) block_result += QStringLiteral(" · ") + QString::fromStdString(status.last_block_result);
    m_block_result->setText(block_result);
    QString rejection = status.last_rejected_share_time_ms ? TimeText(status.last_rejected_share_time_ms) : QStringLiteral("—");
    if (!status.last_rejected_share_reason.empty()) rejection += QStringLiteral(" · ") + QString::fromStdString(status.last_rejected_share_reason);
    const uint64_t rejection_count = status.rejected_unknown_work + status.rejected_high_hash + status.rejected_stale + status.rejected_duplicate + status.rejected_other;
    if (rejection_count) rejection += tr(" · unknown %1, high hash %2, stale %3, duplicate %4, other %5")
        .arg(status.rejected_unknown_work).arg(status.rejected_high_hash).arg(status.rejected_stale).arg(status.rejected_duplicate).arg(status.rejected_other);
    m_rejection->setText(rejection);

    m_miners->setRowCount(status.miners.size());
    for (int row = 0; row < static_cast<int>(status.miners.size()); ++row) {
        const auto& miner = status.miners[row];
        const uint64_t miner_total = miner.accepted_shares + miner.rejected_shares;
        const double miner_reject_rate = miner_total ? 100.0 * miner.rejected_shares / miner_total : 0.0;
        const QString state = miner.authorized ? tr("Authorized") : miner.subscribed ? tr("Subscribed") : tr("Connected");
        const QStringList values{
            miner.worker.empty() ? QStringLiteral("—") : QString::fromStdString(miner.worker),
            QString::fromStdString(miner.remote_host), QString::fromStdString(miner.user_agent), state,
            miner.connected_since_ms ? DurationText(now - miner.connected_since_ms) : QStringLiteral("—"),
            QString::number(miner.current_difficulty), HashrateText(miner.estimated_hashrate_ths),
            QString::number(miner.accepted_shares), QString::number(miner.rejected_shares),
            QStringLiteral("%1%").arg(miner_reject_rate, 0, 'f', 2), AgeText(miner.last_share_time_ms, now)};
        for (int column = 0; column < values.size(); ++column) {
            m_miners->setItem(row, column, new QTableWidgetItem(values[column]));
        }
    }
}
