// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license.
#ifndef BITCOIN_QT_MININGPAGE_H
#define BITCOIN_QT_MININGPAGE_H

#include <QString>
#include <QVector>
#include <QWidget>

#include <cstdint>
#include <optional>

enum class MiningHashrateState {
    Disabled,
    Stopped,
    CollectingBaseline,
    NoAcceptedShares,
    Ready,
};

struct MiningHashrateSample {
    uint64_t timestamp_ms;
    std::optional<double> hashrate_ths;
};

struct MiningHashrateResult {
    MiningHashrateState state{MiningHashrateState::Disabled};
    std::optional<double> hashrate_ths;
};

struct MiningHashrateAxis {
    double maximum_ths{0};
    double tick_ths{0};
    double unit_ths{1};
    QString unit;
};

class MiningHashrateTracker
{
public:
    void resume();
    void pause(uint64_t now_ms);
    MiningHashrateResult update(uint64_t now_ms, bool enabled, bool running, uint64_t session_started_ms, uint32_t authorized_miners, uint64_t accepted_difficulty);
    const QVector<MiningHashrateSample>& history() const { return m_history; }

private:
    struct WorkCheckpoint {
        uint64_t timestamp_ms;
        uint64_t accepted_difficulty;
    };

    void resetWindow();
    void appendGap(uint64_t now_ms);
    void appendHistory(uint64_t now_ms, double hashrate_ths);
    void pruneHistory(uint64_t now_ms);

    bool m_active{false};
    uint64_t m_session_started_ms{0};
    MiningHashrateResult m_result;
    QVector<WorkCheckpoint> m_checkpoints;
    QVector<MiningHashrateSample> m_history;
};

std::optional<double> MiningNetworkHashrateThs(double network_difficulty);
std::optional<double> MiningChancePerBlockPercent(double miner_hashrate_ths, double network_difficulty);
QString MiningHashrateText(double hashrate_ths);
QString MiningChanceText(const std::optional<double>& percent);
QString MiningHashrateStateText(MiningHashrateState state);
QString MiningSummaryMetricText(int row);
QString MiningBestShareText(uint64_t difficulty);
MiningHashrateAxis MiningHashrateAxisFor(double maximum_ths);

class HashrateGraphWidget;
class ChanceGraphWidget;
class QLabel;
class QHideEvent;
class QShowEvent;
class QTableWidget;
class QTimer;

class MiningPage final : public QWidget
{
public:
    explicit MiningPage(QWidget* parent = nullptr);

protected:
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;

private:
    void refresh();

    QTimer* m_timer;
    MiningHashrateTracker m_hashrate_tracker;
    QLabel* m_warning;
    QLabel* m_dashboard_status;
    QLabel* m_dashboard_hashrate;
    QLabel* m_dashboard_hashrate_detail;
    QLabel* m_dashboard_height;
    QLabel* m_dashboard_chance;
    QLabel* m_dashboard_chance_detail;
    ChanceGraphWidget* m_chance_graph;
    HashrateGraphWidget* m_graph;
    QTableWidget* m_summary;
    QLabel* m_status;
    QLabel* m_uptime;
    QLabel* m_listen;
    QLabel* m_auth;
    QLabel* m_mapping;
    QLabel* m_payout;
    QLabel* m_difficulty;
    QLabel* m_clients;
    QLabel* m_hashrate;
    QLabel* m_shares;
    QLabel* m_last_share;
    QLabel* m_height;
    QLabel* m_job_id;
    QLabel* m_job_age;
    QLabel* m_prev_hash;
    QLabel* m_nbits;
    QLabel* m_network_difficulty;
    QLabel* m_template;
    QLabel* m_coinbase;
    QLabel* m_template_result;
    QLabel* m_candidates;
    QLabel* m_block_result;
    QLabel* m_rejection;
    QTableWidget* m_miners;
};

#endif // BITCOIN_QT_MININGPAGE_H
