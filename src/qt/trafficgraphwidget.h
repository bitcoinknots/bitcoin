// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TRAFFICGRAPHWIDGET_H
#define BITCOIN_QT_TRAFFICGRAPHWIDGET_H

#include <QQueue>
#include <QWidget>

#include <chrono>
#include <string>

class ClientModel;
namespace interfaces {
class Node;
}

QT_BEGIN_NAMESPACE
class QMouseEvent;
class QPaintEvent;
class QPainterPath;
class QTimer;
QT_END_NAMESPACE

static constexpr int VALUES_SIZE = 13;

class TrafficGraphWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TrafficGraphWidget(QWidget* parent = nullptr);
    void setClientModel(ClientModel* model);
    bool GraphRangeBump() const { return m_bump_value; }
    unsigned int getCurrentRangeIndex() const { return m_value; }
    quint64 getBaselineBytesRecv() const { return m_baseline_bytes_recv; }
    quint64 getBaselineBytesSent() const { return m_baseline_bytes_sent; }

protected:
    void paintEvent(QPaintEvent*) override;
    int y_value(float value) const;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;

public Q_SLOTS:
    void updateStuff();
    int setGraphRange(int value);

private:
    void saveData();
    void paintPath(QPainterPath& path, const QQueue<float>& samples);
    bool loadDataFromBinary();
    bool loadData();
    void updateRates(int value);
    void updateFmax();

    QTimer* m_timer{nullptr};
    float fMax{0.0f};
    float m_range{5};
    QQueue<float> m_samples_in[VALUES_SIZE] = {};
    QQueue<float> m_samples_out[VALUES_SIZE] = {};
    QQueue<int64_t> m_time_stamp[VALUES_SIZE] = {};
    quint64 m_last_bytes_in[VALUES_SIZE] = {};
    quint64 m_last_bytes_out[VALUES_SIZE] = {};
    int64_t m_last_time[VALUES_SIZE] = {};
    int m_values[VALUES_SIZE] = {5, 10, 20, 45, 90, 3*60, 6*60, 12*60, 24*60, 3*24*60, 7*24*60, 14*24*60, 28*24*60};
    int64_t m_offset[VALUES_SIZE] = {};
    ClientModel* m_client_model{nullptr};
    std::string m_data_dir;
    interfaces::Node* m_node{nullptr};
    quint64 m_baseline_bytes_recv{0};
    quint64 m_baseline_bytes_sent{0};
    int64_t m_last_save_ms{0};

    int m_value{0};
    bool m_bump_value{false};
    bool m_toggle{true};
    int m_tt_point{-1};
    int m_x_offset{0};
    int m_y_offset{0};
    int64_t m_tt_time{0};
};

#endif // BITCOIN_QT_TRAFFICGRAPHWIDGET_H
