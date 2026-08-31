// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license.
#ifndef BITCOIN_QT_DATUMWINDOW_H
#define BITCOIN_QT_DATUMWINDOW_H

#include <QWidget>

class QLabel;
class QShowEvent;
class QHideEvent;
class QCloseEvent;
class QTableWidget;
class QTimer;

class DatumWindow final : public QWidget
{
public:
    explicit DatumWindow(QWidget* parent = nullptr);

protected:
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;
    void closeEvent(QCloseEvent* event) override;

private:
    void refresh();

    QTimer* m_timer;
    QLabel* m_warning;
    QLabel* m_status;
    QLabel* m_uptime;
    QLabel* m_listen;
    QLabel* m_auth;
    QLabel* m_mapping;
    QLabel* m_payout;
    QLabel* m_configured_payout;
    QLabel* m_coinbase_tag;
    QLabel* m_configured_coinbase_tag;
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

#endif // BITCOIN_QT_DATUMWINDOW_H
