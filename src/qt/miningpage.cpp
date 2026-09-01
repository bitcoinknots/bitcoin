// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license.
#include <qt/miningpage.h>

#include <mining/datum_bridge.h>

#include <QAbstractItemView>
#include <QDateTime>
#include <QFont>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHideEvent>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QPair>
#include <QScrollArea>
#include <QShowEvent>
#include <QSizePolicy>
#include <QTableWidget>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QVector>

#include <algorithm>
#include <cmath>
#include <limits>

namespace {
constexpr uint64_t HOUR_MS{60 * 60 * 1000};
constexpr uint64_t DAY_MS{24 * HOUR_MS};
constexpr uint64_t SAMPLE_INTERVAL_MS{60 * 1000};
constexpr uint64_t HASHRATE_WINDOW_MS{5 * SAMPLE_INTERVAL_MS};
constexpr int MAX_SAMPLES{1440};
constexpr double HASHES_PER_DIFFICULTY{4294967296.0};

QLabel* ValueLabel()
{
    auto* label = new QLabel(QStringLiteral("—"));
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    label->setWordWrap(true);
    label->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
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

void AddRow(QFormLayout* form, const QString& name, QLabel*& value)
{
    value = ValueLabel();
    form->addRow(name, value);
}

QFrame* MetricCard(const QString& title, QLabel*& value, const QString& detail, QLabel** detail_label = nullptr, QWidget* accessory = nullptr)
{
    auto* card = new QFrame;
    card->setFrameShape(QFrame::StyledPanel);
    card->setMinimumHeight(62);
    card->setMaximumHeight(72);
    auto* card_layout = new QHBoxLayout(card);
    card_layout->setContentsMargins(10, 5, 10, 5);
    card_layout->setSpacing(8);
    auto* layout = new QVBoxLayout;
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    auto* heading = new QLabel(title);
    QFont heading_font = heading->font();
    heading_font.setPointSize(std::max(8, heading_font.pointSize() - 1));
    heading->setFont(heading_font);
    layout->addWidget(heading);
    value = ValueLabel();
    QFont value_font = value->font();
    value_font.setPointSize(value_font.pointSize() + 5);
    value->setFont(value_font);
    layout->addWidget(value);
    auto* description = new QLabel(detail);
    QFont description_font = description->font();
    description_font.setPointSize(std::max(8, description_font.pointSize() - 1));
    description->setFont(description_font);
    description->setWordWrap(true);
    description->setProperty("secondary", true);
    layout->addWidget(description);
    card_layout->addLayout(layout, 1);
    if (accessory) card_layout->addWidget(accessory, 0, Qt::AlignVCenter);
    if (detail_label) *detail_label = description;
    return card;
}

void SetSummaryRow(QTableWidget* table, int row, const QString& metric, const QString& value, const QString& description)
{
    table->setItem(row, 0, new QTableWidgetItem(metric));
    table->setItem(row, 1, new QTableWidgetItem(value));
    table->setItem(row, 2, new QTableWidgetItem(description));
}
} // namespace

QString MiningHashrateText(double ths)
{
    if (!std::isfinite(ths) || ths < 0) return QStringLiteral("—");
    if (ths >= 1000000) return QStringLiteral("%1 EH/s").arg(ths / 1000000, 0, 'f', 2);
    if (ths >= 1000) return QStringLiteral("%1 PH/s").arg(ths / 1000, 0, 'f', 2);
    if (ths >= 1) return QStringLiteral("%1 TH/s").arg(ths, 0, 'f', 2);
    if (ths >= 0.001) return QStringLiteral("%1 GH/s").arg(ths * 1000, 0, 'f', 1);
    if (ths >= 0.000001) return QStringLiteral("%1 MH/s").arg(ths * 1000000, 0, 'f', 1);
    if (ths >= 0.000000001) return QStringLiteral("%1 kH/s").arg(ths * 1000000000, 0, 'f', 1);
    const double hs{ths * 1000000000000};
    return hs >= 1 ? QStringLiteral("%1 H/s").arg(hs, 0, 'f', 1)
                   : QStringLiteral("%1 H/s").arg(hs, 0, 'g', 3);
}

std::optional<double> MiningNetworkHashrateThs(double network_difficulty)
{
    if (!std::isfinite(network_difficulty) || network_difficulty <= 0) return std::nullopt;
    const double network_ths = network_difficulty * HASHES_PER_DIFFICULTY / 600.0 / 1.0e12;
    if (!std::isfinite(network_ths) || network_ths <= 0) return std::nullopt;
    return network_ths;
}

std::optional<double> MiningChancePerBlockPercent(double miner_hashrate_ths, double network_difficulty)
{
    const auto network_ths{MiningNetworkHashrateThs(network_difficulty)};
    if (!network_ths || !std::isfinite(miner_hashrate_ths) || miner_hashrate_ths <= 0) return std::nullopt;
    return std::min(1.0, miner_hashrate_ths / *network_ths) * 100.0;
}

QString MiningChanceText(const std::optional<double>& percent)
{
    if (!percent || !std::isfinite(*percent) || *percent < 0) return QStringLiteral("—");
    if (*percent >= 100) return QStringLiteral("100%");
    return *percent >= 0.01 ? QStringLiteral("%1%").arg(*percent, 0, 'f', 4)
                            : QStringLiteral("%1%").arg(*percent, 0, 'g', 3);
}

QString MiningHashrateStateText(MiningHashrateState state)
{
    switch (state) {
    case MiningHashrateState::Disabled: return QObject::tr("Disabled");
    case MiningHashrateState::Stopped: return QObject::tr("Stopped");
    case MiningHashrateState::CollectingBaseline: return QObject::tr("Collecting baseline");
    case MiningHashrateState::NoAcceptedShares: return QObject::tr("No accepted shares in the last 5 minutes");
    case MiningHashrateState::Ready: return QObject::tr("Ready · rolling estimate over up to 5 minutes");
    }
    return QStringLiteral("—");
}

QString MiningSummaryMetricText(int row)
{
    switch (row) {
    case 0: return QObject::tr("Accepted shares");
    case 1: return QObject::tr("Rejected shares");
    case 2: return QObject::tr("Stale / obsolete shares");
    case 3: return QObject::tr("Other rejected shares");
    case 4: return QObject::tr("Best Share");
    case 5: return QObject::tr("Block submissions");
    }
    return QString{};
}

QString MiningBestShareText(uint64_t difficulty)
{
    if (!difficulty) return QStringLiteral("—");
    struct Unit {
        uint64_t divisor;
        const char* suffix;
    };
    const auto format_scaled = [](double value) {
        const int decimals = value >= 100 ? 0 : value >= 10 ? 1 : 2;
        QString text = QString::number(value, 'f', decimals);
        while (text.endsWith(QLatin1Char('0'))) text.chop(1);
        if (text.endsWith(QLatin1Char('.'))) text.chop(1);
        return text;
    };
    static constexpr Unit units[]{{1000000000000000000ULL, "E"}, {1000000000000000ULL, "P"}, {1000000000000ULL, "T"}, {1000000000ULL, "G"}, {1000000ULL, "M"}};
    for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); ++i) {
        double scaled = static_cast<double>(difficulty) / units[i].divisor;
        if (scaled < 1) continue;
        const int decimals = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
        double rounded = std::round(scaled * std::pow(10.0, decimals)) / std::pow(10.0, decimals);
        if (rounded >= 1000 && i > 0) {
            scaled = static_cast<double>(difficulty) / units[i - 1].divisor;
            return format_scaled(std::max(1.0, scaled)) + QLatin1String(units[i - 1].suffix);
        }
        return format_scaled(scaled) + QLatin1String(units[i].suffix);
    }
    return QString::number(difficulty);
}

MiningHashrateAxis MiningHashrateAxisFor(double maximum_ths)
{
    if (!std::isfinite(maximum_ths) || maximum_ths <= 0) return {};
    struct Unit {
        double ths;
        const char* text;
    };
    static constexpr Unit units[]{{1000000, "EH/s"}, {1000, "PH/s"}, {1, "TH/s"}, {0.001, "GH/s"}, {0.000001, "MH/s"}, {0.000000001, "kH/s"}, {0.000000000001, "H/s"}};
    const Unit* selected = &units[sizeof(units) / sizeof(units[0]) - 1];
    for (const auto& unit : units) {
        if (maximum_ths / unit.ths >= 10) {
            selected = &unit;
            break;
        }
    }

    const double numeric_maximum = maximum_ths / selected->ths;
    const double target_step = numeric_maximum / 4.0;
    double magnitude{100};
    while (target_step > 5 * magnitude) magnitude *= 10;
    const double tick = target_step <= magnitude ? magnitude
                      : target_step <= 2 * magnitude ? 2 * magnitude
                      : target_step <= 5 * magnitude ? 5 * magnitude
                                                     : 10 * magnitude;
    double axis_maximum = std::ceil(numeric_maximum / tick) * tick;
    if (axis_maximum <= numeric_maximum * (1 + 1e-12)) axis_maximum += tick;
    return {axis_maximum * selected->ths, tick * selected->ths, selected->ths, QString::fromLatin1(selected->text)};
}

void MiningHashrateTracker::resume()
{
    m_active = true;
    resetWindow();
}

void MiningHashrateTracker::pause(uint64_t now_ms)
{
    if (m_active) appendGap(now_ms);
    m_active = false;
    resetWindow();
}

MiningHashrateResult MiningHashrateTracker::update(uint64_t now_ms, bool enabled, bool running, uint64_t session_started_ms, uint32_t authorized_miners, uint64_t accepted_difficulty)
{
    if (!m_active) return m_result;

    auto unavailable = [&](MiningHashrateState state) {
        appendGap(now_ms);
        resetWindow();
        m_result.state = state;
        return m_result;
    };
    if (!enabled) return unavailable(MiningHashrateState::Disabled);
    if (!running) return unavailable(MiningHashrateState::Stopped);
    if (!authorized_miners) return unavailable(MiningHashrateState::CollectingBaseline);

    const bool counter_regressed = !m_checkpoints.empty() && accepted_difficulty < m_checkpoints.back().accepted_difficulty;
    const bool clock_regressed = !m_checkpoints.empty() && now_ms < m_checkpoints.back().timestamp_ms;
    if (m_session_started_ms != session_started_ms || counter_regressed || clock_regressed) {
        appendGap(clock_regressed ? m_checkpoints.back().timestamp_ms : now_ms);
        resetWindow();
        m_session_started_ms = session_started_ms;
    }

    if (m_checkpoints.empty()) {
        m_session_started_ms = session_started_ms;
        m_checkpoints.push_back({now_ms, accepted_difficulty});
        m_result.state = MiningHashrateState::CollectingBaseline;
        return m_result;
    }

    if (now_ms - m_checkpoints.back().timestamp_ms < SAMPLE_INTERVAL_MS) {
        if (accepted_difficulty > m_checkpoints.back().accepted_difficulty && !m_result.hashrate_ths) {
            m_result.state = MiningHashrateState::CollectingBaseline;
        }
        return m_result;
    }
    m_checkpoints.push_back({now_ms, accepted_difficulty});
    const uint64_t cutoff = now_ms > HASHRATE_WINDOW_MS ? now_ms - HASHRATE_WINDOW_MS : 0;
    while (m_checkpoints.size() > 1 && m_checkpoints.front().timestamp_ms < cutoff) m_checkpoints.remove(0);

    const WorkCheckpoint& first{m_checkpoints.front()};
    const WorkCheckpoint& last{m_checkpoints.back()};
    const uint64_t elapsed_ms{last.timestamp_ms - first.timestamp_ms};
    const uint64_t accepted_delta{last.accepted_difficulty - first.accepted_difficulty};
    if (elapsed_ms < SAMPLE_INTERVAL_MS) {
        m_result.state = MiningHashrateState::CollectingBaseline;
        m_result.hashrate_ths.reset();
        return m_result;
    }
    if (!accepted_delta) {
        appendGap(now_ms);
        m_result.state = MiningHashrateState::NoAcceptedShares;
        m_result.hashrate_ths.reset();
        return m_result;
    }

    const long double elapsed_seconds{elapsed_ms / 1000.0L};
    const double hashrate_ths{static_cast<double>(accepted_delta * static_cast<long double>(HASHES_PER_DIFFICULTY) / elapsed_seconds / 1.0e12L)};
    if (!std::isfinite(hashrate_ths) || hashrate_ths <= 0) return unavailable(MiningHashrateState::NoAcceptedShares);
    m_result.state = MiningHashrateState::Ready;
    m_result.hashrate_ths = hashrate_ths;
    appendHistory(now_ms, hashrate_ths);
    return m_result;
}

void MiningHashrateTracker::resetWindow()
{
    m_session_started_ms = 0;
    m_checkpoints.clear();
    m_result.hashrate_ths.reset();
}

void MiningHashrateTracker::appendGap(uint64_t now_ms)
{
    if (!m_history.empty() && m_history.back().hashrate_ths) {
        m_history.push_back({now_ms, std::nullopt});
        pruneHistory(now_ms);
    }
}

void MiningHashrateTracker::appendHistory(uint64_t now_ms, double hashrate_ths)
{
    m_history.push_back({now_ms, hashrate_ths});
    pruneHistory(now_ms);
}

void MiningHashrateTracker::pruneHistory(uint64_t now_ms)
{
    const uint64_t cutoff = now_ms > DAY_MS ? now_ms - DAY_MS : 0;
    while (!m_history.empty() && (m_history.front().timestamp_ms < cutoff || m_history.size() > MAX_SAMPLES)) m_history.remove(0);
}

class HashrateGraphWidget final : public QWidget
{
public:
    explicit HashrateGraphWidget(QWidget* parent = nullptr) : QWidget(parent)
    {
        setMinimumHeight(104);
        setMaximumHeight(126);
        setObjectName(QStringLiteral("miningHashrateGraph"));
    }

    void setSamples(const QVector<MiningHashrateSample>& samples)
    {
        m_samples = samples;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.fillRect(rect(), palette().base());
        QColor grid_color = palette().text().color();
        grid_color.setAlpha(55);
        painter.setPen(grid_color);
        painter.drawRect(rect().adjusted(0, 0, -1, -1));

        const QRectF plot = rect().adjusted(102, 10, -10, -23);
        const uint64_t now = QDateTime::currentMSecsSinceEpoch();
        const uint64_t start = now > DAY_MS ? now - DAY_MS : 0;
        int valid_samples{0};
        double observed_maximum{0};
        for (const auto& sample : m_samples) {
            if (!sample.hashrate_ths) continue;
            ++valid_samples;
            observed_maximum = std::max(observed_maximum, *sample.hashrate_ths);
        }

        QDateTime tick_time = QDateTime::fromMSecsSinceEpoch(start).toLocalTime();
        int tick_hour = (tick_time.time().hour() / 6 + 1) * 6;
        QDate tick_date = tick_time.date();
        if (tick_hour >= 24) {
            tick_date = tick_date.addDays(1);
            tick_hour = 0;
        }
        tick_time = QDateTime(tick_date, QTime(tick_hour, 0), Qt::LocalTime);
        while (tick_time.toMSecsSinceEpoch() <= static_cast<qint64>(now)) {
            const double x = plot.left() + (tick_time.toMSecsSinceEpoch() - static_cast<qint64>(start)) / static_cast<double>(DAY_MS) * plot.width();
            painter.setPen(grid_color);
            painter.drawLine(QPointF(x, plot.top()), QPointF(x, plot.bottom()));
            painter.setPen(palette().text().color());
            painter.drawText(QRectF(x - 28, plot.bottom() + 2, 56, 18), Qt::AlignHCenter, tick_time.toString(QStringLiteral("HH:mm")));
            tick_time = tick_time.addSecs(6 * 60 * 60);
        }

        const MiningHashrateAxis axis{MiningHashrateAxisFor(observed_maximum)};
        if (valid_samples) {
            for (double tick = 0; tick <= axis.maximum_ths + axis.tick_ths / 2; tick += axis.tick_ths) {
                const double y = plot.bottom() - tick / axis.maximum_ths * plot.height();
                painter.setPen(grid_color);
                painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y));
                painter.setPen(palette().text().color());
                const QString label = QStringLiteral("%1 %2").arg(std::llround(tick / axis.unit_ths)).arg(axis.unit);
                painter.drawText(QRectF(2, y - 9, 96, 18), Qt::AlignRight | Qt::AlignVCenter, label);
            }
        }
        painter.setPen(grid_color);
        painter.drawLine(plot.bottomLeft(), plot.bottomRight());
        painter.drawLine(plot.bottomLeft(), plot.topLeft());

        if (!valid_samples) {
            painter.setPen(palette().text().color());
            painter.drawText(plot, Qt::AlignCenter, tr("Waiting for hashrate samples…"));
            return;
        }

        const auto current_hashrate = !m_samples.empty() ? m_samples.back().hashrate_ths : std::nullopt;
        QPainterPath path;
        bool first{true};
        uint64_t previous_timestamp{0};
        for (const auto& sample : m_samples) {
            if (!sample.hashrate_ths) {
                first = true;
                previous_timestamp = 0;
                continue;
            }
            if (previous_timestamp && sample.timestamp_ms > previous_timestamp + 2 * SAMPLE_INTERVAL_MS) first = true;
            const double elapsed = sample.timestamp_ms > start ? static_cast<double>(sample.timestamp_ms - start) : 0.0;
            const double x = plot.left() + std::min(1.0, elapsed / DAY_MS) * plot.width();
            const double y = plot.bottom() - (*sample.hashrate_ths / axis.maximum_ths) * plot.height();
            if (first) {
                path.moveTo(x, y);
                first = false;
            } else {
                path.lineTo(x, y);
            }
            previous_timestamp = sample.timestamp_ms;
        }
        painter.setPen(QPen(palette().highlight().color(), 2));
        painter.drawPath(path);
        if (valid_samples == 1 || current_hashrate) painter.drawEllipse(path.currentPosition(), 2.5, 2.5);
    }

private:
    QVector<MiningHashrateSample> m_samples;
};

class ChanceGraphWidget final : public QWidget
{
public:
    explicit ChanceGraphWidget(QWidget* parent = nullptr) : QWidget(parent)
    {
        setFixedSize(86, 52);
        setObjectName(QStringLiteral("miningChanceGraph"));
    }

    void setSamples(const QVector<MiningHashrateSample>& samples, double network_difficulty)
    {
        m_samples = samples;
        m_network_difficulty = network_difficulty;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        const QRectF plot = rect().adjusted(2, 3, -2, -3);
        QColor axis = palette().text().color();
        axis.setAlpha(65);
        painter.setPen(axis);
        painter.drawLine(plot.bottomLeft(), plot.bottomRight());
        painter.drawLine(plot.bottomRight(), plot.topRight());

        if (m_network_difficulty <= 0 || m_samples.empty()) return;
        constexpr int MAX_POINTS{24};
        const int first = std::max(0, m_samples.size() - MAX_POINTS);
        QVector<std::optional<double>> chances;
        double maximum{0};
        for (int i = first; i < m_samples.size(); ++i) {
            const auto chance = m_samples[i].hashrate_ths ? MiningChancePerBlockPercent(*m_samples[i].hashrate_ths, m_network_difficulty) : std::nullopt;
            chances.push_back(chance);
            if (chance) maximum = std::max(maximum, *chance);
        }
        if (maximum <= 0) return;
        maximum = std::min(100.0, maximum * 1.1);

        QColor bar = palette().highlight().color();
        bar.setAlpha(140);
        painter.setPen(Qt::NoPen);
        painter.setBrush(bar);
        const double slot_width = plot.width() / MAX_POINTS;
        const double first_x = plot.right() - chances.size() * slot_width;
        for (int i = 0; i < chances.size(); ++i) {
            if (!chances[i]) continue;
            const double height = plot.height() * (*chances[i] / maximum);
            painter.drawRect(QRectF(first_x + i * slot_width, plot.bottom() - height, std::max(1.0, slot_width - 1), height));
        }
    }

private:
    QVector<MiningHashrateSample> m_samples;
    double m_network_difficulty{0};
};

MiningPage::MiningPage(QWidget* parent) : QWidget(parent), m_timer(new QTimer(this))
{
    setObjectName(QStringLiteral("miningPage"));
    auto* layout = new QVBoxLayout(this);
    m_warning = new QLabel;
    m_warning->setWordWrap(true);
    m_warning->setStyleSheet(QStringLiteral("QLabel { color: #b45309; font-weight: 600; padding: 6px; }"));
    m_warning->hide();
    layout->addWidget(m_warning);

    auto* tabs = new QTabWidget;
    tabs->setObjectName(QStringLiteral("miningDetailTabs"));
    tabs->setDocumentMode(true);
    layout->addWidget(tabs);

    auto* dashboard_scroll = new QScrollArea;
    dashboard_scroll->setWidgetResizable(true);
    dashboard_scroll->setFrameShape(QFrame::NoFrame);
    dashboard_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* dashboard = new QWidget;
    auto* dashboard_layout = new QVBoxLayout(dashboard);
    dashboard_layout->setContentsMargins(8, 8, 8, 8);
    dashboard_layout->setSpacing(7);
    auto* title = new QLabel(tr("Bitcoin Purity Mining Console"));
    title->setAlignment(Qt::AlignCenter);
    QFont title_font = title->font();
    title_font.setPointSize(title_font.pointSize() + 7);
    title->setFont(title_font);
    dashboard_layout->addWidget(title);
    auto* status_line = new QHBoxLayout;
    status_line->addStretch();
    status_line->addWidget(new QLabel(tr("Status:")));
    m_dashboard_status = ValueLabel();
    m_dashboard_status->setObjectName(QStringLiteral("miningDashboardStatus"));
    m_dashboard_status->setWordWrap(false);
    QFont status_font = m_dashboard_status->font();
    status_font.setBold(true);
    m_dashboard_status->setFont(status_font);
    status_line->addWidget(m_dashboard_status);
    dashboard_layout->addLayout(status_line);

    auto* cards = new QGridLayout;
    cards->setContentsMargins(0, 0, 0, 0);
    cards->setHorizontalSpacing(8);
    cards->setVerticalSpacing(6);
    cards->addWidget(MetricCard(tr("Estimated Miner Hashrate"), m_dashboard_hashrate, QString(), &m_dashboard_hashrate_detail), 0, 0);
    m_chance_graph = new ChanceGraphWidget;
    cards->addWidget(MetricCard(tr("Chance per Block"), m_dashboard_chance, QString(), &m_dashboard_chance_detail, m_chance_graph), 0, 1);
    cards->addWidget(MetricCard(tr("Current Block Number"), m_dashboard_height, tr("Current DATUM job height")), 1, 0);
    m_dashboard_hashrate->setObjectName(QStringLiteral("miningDashboardHashrate"));
    m_dashboard_hashrate_detail->setObjectName(QStringLiteral("miningDashboardHashrateDetail"));
    m_dashboard_chance->setObjectName(QStringLiteral("miningDashboardChance"));
    m_dashboard_height->setObjectName(QStringLiteral("miningDashboardHeight"));
    cards->setColumnStretch(0, 1);
    cards->setColumnStretch(1, 1);
    dashboard_layout->addLayout(cards);

    auto* graph_group = new QGroupBox(tr("Hashrate Trend over Time (Last 24h)"));
    graph_group->setAlignment(Qt::AlignHCenter);
    auto* graph_layout = new QVBoxLayout(graph_group);
    graph_layout->setContentsMargins(8, 7, 8, 7);
    m_graph = new HashrateGraphWidget;
    graph_layout->addWidget(m_graph);
    dashboard_layout->addWidget(graph_group);

    auto* summary_group = new QGroupBox(tr("Mining Performance Summary"));
    summary_group->setAlignment(Qt::AlignHCenter);
    auto* summary_layout = new QVBoxLayout(summary_group);
    summary_layout->setContentsMargins(8, 7, 8, 7);
    m_summary = new QTableWidget(6, 3);
    m_summary->setObjectName(QStringLiteral("miningShareSummary"));
    m_summary->setHorizontalHeaderLabels({tr("Metric"), tr("Value"), tr("Description")});
    m_summary->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_summary->setSelectionMode(QAbstractItemView::NoSelection);
    m_summary->setAlternatingRowColors(true);
    m_summary->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_summary->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_summary->verticalHeader()->hide();
    m_summary->verticalHeader()->setDefaultSectionSize(22);
    m_summary->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_summary->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_summary->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_summary->setFixedHeight(164);
    summary_layout->addWidget(m_summary);
    dashboard_layout->addWidget(summary_group);
    dashboard_layout->addStretch();
    dashboard_scroll->setWidget(dashboard);
    tabs->addTab(dashboard_scroll, tr("Mining Dashboard"));

    auto* overview = new QWidget;
    auto* overview_layout = new QVBoxLayout(overview);
    auto* runtime_group = new QGroupBox(tr("Runtime and Network"));
    auto* runtime = new QFormLayout(runtime_group);
    AddRow(runtime, tr("Status"), m_status);
    AddRow(runtime, tr("DATUM uptime"), m_uptime);
    AddRow(runtime, tr("Stratum listener"), m_listen);
    AddRow(runtime, tr("Authentication"), m_auth);
    AddRow(runtime, tr("Port mapping"), m_mapping);
    AddRow(runtime, tr("Payout address"), m_payout);
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
    job->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    AddRow(job, tr("Height"), m_height);
    AddRow(job, tr("Job ID"), m_job_id);
    AddRow(job, tr("Job age"), m_job_age);
    AddRow(job, tr("Previous block hash"), m_prev_hash);
    AddRow(job, tr("nBits"), m_nbits);
    AddRow(job, tr("Network difficulty"), m_network_difficulty);
    AddRow(job, tr("Template"), m_template);
    AddRow(job, tr("Coinbase value"), m_coinbase);
    AddRow(job, tr("Last template result"), m_template_result);
    m_height->setObjectName(QStringLiteral("miningJobHeight"));
    m_job_id->setObjectName(QStringLiteral("miningJobId"));
    m_network_difficulty->setObjectName(QStringLiteral("miningJobNetworkDifficulty"));
    m_template->setObjectName(QStringLiteral("miningJobTemplate"));
    job_layout->addWidget(job_group);

    auto* diagnostics_group = new QGroupBox(tr("Block Submission and Diagnostics"));
    auto* diagnostics = new QFormLayout(diagnostics_group);
    diagnostics->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    AddRow(diagnostics, tr("Block candidates"), m_candidates);
    AddRow(diagnostics, tr("Last block result"), m_block_result);
    AddRow(diagnostics, tr("Last share rejection"), m_rejection);
    job_layout->addWidget(diagnostics_group);
    job_layout->addStretch();
    tabs->addTab(job_page, tr("Job and Diagnostics"));

    connect(m_timer, &QTimer::timeout, this, [this] { refresh(); });
    m_timer->setInterval(1000);
}

void MiningPage::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    m_hashrate_tracker.resume();
    refresh();
    m_timer->start();
}

void MiningPage::hideEvent(QHideEvent* event)
{
    m_timer->stop();
    m_hashrate_tracker.pause(QDateTime::currentMSecsSinceEpoch());
    QWidget::hideEvent(event);
}

void MiningPage::refresh()
{
    const mining::DatumStatusSnapshot status{mining::GetDatumStatusSnapshot()};
    const uint64_t now = QDateTime::currentMSecsSinceEpoch();
    const bool collecting{status.running && status.status != "Stopping"};
    const MiningHashrateResult hashrate{m_hashrate_tracker.update(now, status.enabled, collecting, status.session_started_ms, status.authorized_clients, status.session_accepted_difficulty)};
    m_dashboard_status->setText(MiningHashrateStateText(hashrate.state));
    m_dashboard_hashrate->setText(hashrate.hashrate_ths ? MiningHashrateText(*hashrate.hashrate_ths) : QStringLiteral("—"));
    m_dashboard_hashrate_detail->setText(MiningHashrateStateText(hashrate.state));
    const bool valid_job{collecting && !status.job_id.empty() && status.current_height > 0};
    m_dashboard_height->setText(valid_job ? QString::number(status.current_height) : QStringLiteral("—"));
    const auto chance{hashrate.hashrate_ths && valid_job ? MiningChancePerBlockPercent(*hashrate.hashrate_ths, status.network_difficulty) : std::nullopt};
    m_dashboard_chance->setText(MiningChanceText(chance));
    const auto network_ths{valid_job ? MiningNetworkHashrateThs(status.network_difficulty) : std::nullopt};
    if (!network_ths) {
        m_dashboard_chance_detail->setText(tr("Network difficulty unavailable"));
    } else {
        m_dashboard_chance_detail->setText(tr("Estimated network hashrate: %1").arg(MiningHashrateText(*network_ths)));
    }
    m_graph->setSamples(m_hashrate_tracker.history());
    m_chance_graph->setSamples(m_hashrate_tracker.history(), valid_job ? status.network_difficulty : 0);

    const uint64_t other_rejections = status.rejected_unknown_work + status.rejected_high_hash + status.rejected_duplicate + status.rejected_other;
    SetSummaryRow(m_summary, 0, MiningSummaryMetricText(0), QString::number(status.session_accepted_shares), tr("Session accepted valid shares"));
    SetSummaryRow(m_summary, 1, MiningSummaryMetricText(1), QString::number(status.session_rejected_shares), tr("Session rejected shares"));
    SetSummaryRow(m_summary, 2, MiningSummaryMetricText(2), QString::number(status.rejected_stale), tr("Rejected stale shares"));
    SetSummaryRow(m_summary, 3, MiningSummaryMetricText(3), QString::number(other_rejections), tr("Unknown work, high hash, duplicate, and other"));
    SetSummaryRow(m_summary, 4, MiningSummaryMetricText(4), MiningBestShareText(status.session_best_share_difficulty), tr("Highest achieved difficulty among accepted shares"));
    SetSummaryRow(m_summary, 5, MiningSummaryMetricText(5), tr("%1 blocks accepted / %2 rejected").arg(status.block_submissions_accepted).arg(status.block_submissions_rejected), tr("%1 block candidates submitted").arg(status.block_candidates));

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

    const bool public_listener = status.listen == "0.0.0.0" || status.listen == "::";
    if (status.enabled && public_listener && !status.auth_required) {
        m_warning->setText(tr("Warning: Stratum is listening publicly without authentication."));
        m_warning->show();
    } else {
        m_warning->hide();
    }

    m_difficulty->setText(QString::number(status.share_difficulty));
    m_clients->setText(tr("%1 connected · %2 subscribed · %3 authorized").arg(status.clients).arg(status.subscribed_clients).arg(status.authorized_clients));
    m_hashrate->setText(hashrate.hashrate_ths ? MiningHashrateText(*hashrate.hashrate_ths) + tr(" · rolling estimate over up to 5 minutes") : QStringLiteral("—"));
    const uint64_t total = status.session_accepted_shares + status.session_rejected_shares;
    const double reject_rate = total ? 100.0 * status.session_rejected_shares / total : 0.0;
    m_shares->setText(tr("%1 accepted · %2 rejected · %3% rejected").arg(status.session_accepted_shares).arg(status.session_rejected_shares).arg(reject_rate, 0, 'f', 2));
    m_last_share->setText(status.last_share_time_ms ? TimeText(status.last_share_time_ms) + QStringLiteral(" · ") + AgeText(status.last_share_time_ms, now) : QStringLiteral("—"));

    m_height->setText(valid_job ? QString::number(status.current_height) : QStringLiteral("—"));
    m_job_id->setText(valid_job ? QString::fromStdString(status.job_id) : QStringLiteral("—"));
    m_job_age->setText(valid_job ? AgeText(status.job_created_ms, now) : QStringLiteral("—"));
    m_prev_hash->setText(valid_job && !status.previous_block_hash.empty() ? QString::fromStdString(status.previous_block_hash) : QStringLiteral("—"));
    m_nbits->setText(valid_job && status.nbits ? QStringLiteral("%1").arg(status.nbits, 8, 16, QLatin1Char('0')) : QStringLiteral("—"));
    m_network_difficulty->setText(valid_job && status.network_difficulty > 0 ? QString::number(status.network_difficulty, 'g', 12) : QStringLiteral("—"));
    m_template->setText(valid_job ? tr("%1 transactions · %2 bytes · %3 weight").arg(status.transaction_count).arg(status.template_size).arg(status.template_weight) : QStringLiteral("—"));
    m_coinbase->setText(valid_job ? tr("%1 sat").arg(status.coinbase_value) : QStringLiteral("—"));
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
            QString::number(miner.current_difficulty), MiningHashrateText(miner.estimated_hashrate_ths),
            QString::number(miner.accepted_shares), QString::number(miner.rejected_shares),
            QStringLiteral("%1%").arg(miner_reject_rate, 0, 'f', 2), AgeText(miner.last_share_time_ms, now)};
        for (int column = 0; column < values.size(); ++column) {
            m_miners->setItem(row, column, new QTableWidgetItem(values[column]));
        }
    }
}
