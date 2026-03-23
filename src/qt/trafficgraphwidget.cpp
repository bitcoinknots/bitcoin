// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/trafficgraphwidget.h>

#include <interfaces/node.h>
#include <logging.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <streams.h>
#include <util/fs.h>
#include <util/fs_helpers.h>

#include <QColor>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QTimer>
#include <QToolTip>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>

#define DESIRED_SAMPLES         800

#define XMARGIN                 10
#define YMARGIN                 10

TrafficGraphWidget::TrafficGraphWidget(QWidget* parent)
    : QWidget(parent)
{
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &TrafficGraphWidget::updateStuff);
    m_timer->setInterval(75);
    m_timer->start();
    setMouseTracking(true);
}

void TrafficGraphWidget::setClientModel(ClientModel* model)
{
    m_client_model = model;
    if (!model) {
        saveData();
        m_node = nullptr;
        return;
    }

    m_data_dir = model->dataDir().toStdString();
    m_node = &model->node();

    if (m_samples_in[0].empty() && m_samples_out[0].empty()) {
        loadData();
    }

    const quint64 bytes_in = model->node().getTotalBytesRecv();
    const quint64 bytes_out = model->node().getTotalBytesSent();
    const int64_t now = GetTime<std::chrono::milliseconds>().count();
    for (int i = 0; i < VALUES_SIZE; ++i) {
        m_last_bytes_in[i] = bytes_in;
        m_last_bytes_out[i] = bytes_out;
        m_last_time[i] = now - m_timer->interval();
    }
    m_last_save_ms = now;
}

int TrafficGraphWidget::y_value(float value) const
{
    int h = height() - YMARGIN * 2;
    return YMARGIN + h - (h * 1.0 * (m_toggle ? (std::pow(value, 0.30102) / std::pow(fMax, 0.30102)) : (value / fMax)));
}

void TrafficGraphWidget::paintPath(QPainterPath& path, const QQueue<float>& samples)
{
    int sampleCount = samples.size();
    if (sampleCount <= 0) return;

    int h = height() - YMARGIN * 2;
    int w = width() - XMARGIN * 2;
    int x = XMARGIN + w;
    path.moveTo(x, YMARGIN + h);
    for (int i = 0; i < sampleCount; ++i) {
        double ratio = static_cast<double>(i) * m_values[m_value] / m_range / DESIRED_SAMPLES;
        x = XMARGIN + w - static_cast<int>(w * ratio);
        path.lineTo(x, y_value(samples.at(i)));
    }
    path.lineTo(x, YMARGIN + h);
}

void TrafficGraphWidget::mousePressEvent(QMouseEvent* event)
{
    QWidget::mousePressEvent(event);
    m_toggle = !m_toggle;
    update();
}

static float floatmax(float a, float b)
{
    if (a > b) return a;
    return b;
}

void TrafficGraphWidget::mouseMoveEvent(QMouseEvent* event)
{
    QWidget::mouseMoveEvent(event);
    static int last_x = -1;
    static int last_y = -1;
    int x = event->x();
    int y = event->y();
    m_x_offset = event->globalX() - x;
    m_y_offset = event->globalY() - y;
    if (last_x == x && last_y == y) return;

    int h = height() - YMARGIN * 2;
    int w = width() - XMARGIN * 2;
    int i = (w + XMARGIN - x) * DESIRED_SAMPLES / w;
    unsigned int smallest_distance = 50;
    int closest_i = -1;
    int sampleSize = m_time_stamp[m_value].size();
    if (sampleSize && i >= -10 && i < sampleSize + 2 && y <= h + YMARGIN + 3) {
        for (int test_i = std::max(i - 2, 0); test_i < std::min(i + 10, sampleSize); test_i++) {
            float val = floatmax(m_samples_in[m_value].at(test_i), m_samples_out[m_value].at(test_i));
            int y_data = y_value(val);
            unsigned int distance = abs(y - y_data);
            if (distance < smallest_distance) {
                smallest_distance = distance;
                closest_i = test_i;
            }
        }
    }
    if (m_tt_point != closest_i) {
        m_tt_point = closest_i;
        update();
    }
    last_x = x;
    last_y = y;
}

void TrafficGraphWidget::paintEvent(QPaintEvent*)
{
    QPainter painter(this);
    painter.fillRect(rect(), Qt::black);

    if (fMax <= 0.0f) return;

    QColor axisCol(Qt::gray);
    int h = height() - YMARGIN * 2;
    painter.setPen(axisCol);
    painter.drawLine(XMARGIN, YMARGIN + h, width() - XMARGIN, YMARGIN + h);

    int base = std::floor(std::log10(fMax));
    float val = std::pow(10.0f, base);

    const QString units = tr("kB/s");
    const float yMarginText = 2.0;

    if (fMax / val <= (m_toggle ? 10.0f : 3.0f)) {
        float oldval = val;
        val = std::pow(10.0f, base - 1);
        painter.setPen(axisCol.darker());
        painter.drawText(XMARGIN, y_value(val)-yMarginText, QString("%1 %2").arg(val).arg(units));
        if (m_toggle) {
            int yy = y_value(val * 0.1);
            painter.drawText(XMARGIN, yy - yMarginText, QString("%1 %2").arg(val * 0.1).arg(units));
            painter.drawLine(XMARGIN, yy, width() - XMARGIN, yy);
        }
        int count = 1;
        for (float y = val; y < (!m_toggle || fMax / val < 20 ? fMax : oldval); y += val, count++) {
            if (count % 10 == 0) continue;
            int yy = y_value(y);
            painter.drawLine(XMARGIN, yy, width() - XMARGIN, yy);
        }
        val = oldval;
    }

    painter.setPen(axisCol);
    for (float y = val; y < fMax; y += val) {
        int yy = y_value(y);
        painter.drawLine(XMARGIN, yy, width() - XMARGIN, yy);
    }
    painter.drawText(XMARGIN, y_value(val) - yMarginText, QString("%1 %2").arg(val).arg(units));

    painter.setRenderHint(QPainter::Antialiasing);
    if (!m_samples_in[m_value].empty()) {
        QPainterPath p;
        paintPath(p, m_samples_in[m_value]);
        painter.fillPath(p, QColor(0, 255, 0, 128));
        painter.setPen(Qt::green);
        painter.drawPath(p);
    }
    if (!m_samples_out[m_value].empty()) {
        QPainterPath p;
        paintPath(p, m_samples_out[m_value]);
        painter.fillPath(p, QColor(255, 0, 0, 128));
        painter.setPen(Qt::red);
        painter.drawPath(p);
    }
    int sampleCount = m_time_stamp[m_value].size();
    if (m_tt_point >= 0 && m_tt_point < sampleCount) {
        painter.setPen(Qt::yellow);
        int w = width() - XMARGIN * 2;
        double ratio = static_cast<double>(m_tt_point) * m_values[m_value] / m_range / DESIRED_SAMPLES;
        int x = XMARGIN + w - static_cast<int>(w * ratio);
        int y = y_value(floatmax(m_samples_in[m_value].at(m_tt_point), m_samples_out[m_value].at(m_tt_point)));
        painter.drawEllipse(QPointF(x, y), 3, 3);
        QString strTime;
        int64_t sampleTime = m_time_stamp[m_value].at(m_tt_point);
        int age = GetTime() - sampleTime / 1000;
        if (age < 60*60*23)
            strTime = QString::fromStdString(FormatISO8601Time(sampleTime / 1000));
        else
            strTime = QString::fromStdString(FormatISO8601DateTime(sampleTime / 1000));
        int milliseconds_between_samples = 1000;
        if (m_tt_point > 0) {
            milliseconds_between_samples = std::min(milliseconds_between_samples, int(m_time_stamp[m_value].at(m_tt_point - 1) - sampleTime));
        }
        if (m_tt_point + 1 < sampleCount) {
            milliseconds_between_samples = std::min(milliseconds_between_samples, int(sampleTime - m_time_stamp[m_value].at(m_tt_point + 1)));
        }
        if (milliseconds_between_samples < 1000) {
            strTime += QString::fromStdString(strprintf(".%03d", (sampleTime % 1000)));
        }
        QString strData = tr("In") + " " + GUIUtil::formatBytesps(m_samples_in[m_value].at(m_tt_point) * 1000) + "\n" + tr("Out") + " " + GUIUtil::formatBytesps(m_samples_out[m_value].at(m_tt_point) * 1000);
        QToolTip::showText(QPoint(x + m_x_offset, y + m_y_offset), strTime + "\n. " + strData);
        QToolTip::showText(QPoint(x + m_x_offset, y + m_y_offset), strTime + "\n  " + strData);
        m_tt_time = GetTime();
    } else {
        QToolTip::hideText();
    }
}

void TrafficGraphWidget::updateFmax()
{
    float tmax = 0.0f;
    for (const float f : m_samples_in[m_value]) {
        if (f > tmax) tmax = f;
    }
    for (const float f : m_samples_out[m_value]) {
        if (f > tmax) tmax = f;
    }
    fMax = tmax;
}

void TrafficGraphWidget::updateStuff()
{
    if (!m_client_model) return;

    int64_t expected_gap = m_timer->interval();
    int64_t now = GetTime<std::chrono::milliseconds>().count();
    static int64_t last_jump_time = 0;
    int64_t time_offset = 0;

    if (!m_time_stamp[0].empty()) {
        int64_t last_time = m_time_stamp[0].front();
        int64_t actual_gap = now - last_time;
        if (actual_gap >= 1000 + expected_gap && last_time != last_jump_time) {
            time_offset = actual_gap - expected_gap;
            last_jump_time = last_time;
        }
    }

    bool update_needed = false;

    for (int i = 0; i < VALUES_SIZE; i++) {
        int64_t msecs_per_sample = static_cast<int64_t>(m_values[i]) * 60000 / DESIRED_SAMPLES;
        if (time_offset) {
            m_offset[i] += time_offset;
            if (m_offset[i] > now - m_last_time[i]) m_offset[i] = now - m_last_time[i];
        }
        if (now > (m_last_time[i] + msecs_per_sample + m_offset[i] - expected_gap / 2)) {
            m_offset[i] = 0;
            updateRates(i);
            if (i == m_value) {
                if (m_tt_point >=0 && m_tt_point < DESIRED_SAMPLES) {
                    m_tt_point++;
                    if (m_tt_point >= DESIRED_SAMPLES) m_tt_point = -1;
                }
                update_needed = true;
            }
        }
    }

    if (!QToolTip::isVisible() || !isVisible() || window()->isMinimized()) {
        if (m_tt_point >= 0) {
            m_tt_point = -1;
            update_needed = true;
        }
    } else if (m_tt_point >= 0 && GetTime() >= m_tt_time + 9) {
        update_needed = true;
    }

    if (update_needed) {
        updateFmax();
        update();
    }

    if (!m_data_dir.empty() && now - m_last_save_ms >= 60000) {
        saveData();
        m_last_save_ms = now;
    }
}

void TrafficGraphWidget::updateRates(int i)
{
    int64_t now = GetTime<std::chrono::milliseconds>().count();
    quint64 bytesIn = m_client_model->node().getTotalBytesRecv();
    quint64 bytesOut = m_client_model->node().getTotalBytesSent();

    // Counters should be monotonic. If they reset (restart/load edge), rebase to avoid spike artifacts.
    if (m_last_time[i] <= 0 || bytesIn < m_last_bytes_in[i] || bytesOut < m_last_bytes_out[i]) {
        m_last_bytes_in[i] = bytesIn;
        m_last_bytes_out[i] = bytesOut;
        m_last_time[i] = now;
        return;
    }

    int64_t actual_gap = now - m_last_time[i];
    if (actual_gap <= 0) return;
    float in_rate_kilobytes_per_msec = static_cast<float>(bytesIn - m_last_bytes_in[i]) / actual_gap;
    float out_rate_kilobytes_per_msec = static_cast<float>(bytesOut - m_last_bytes_out[i]) / actual_gap;
    m_samples_in[i].push_front(in_rate_kilobytes_per_msec);
    m_samples_out[i].push_front(out_rate_kilobytes_per_msec);
    m_time_stamp[i].push_front(now);
    m_last_time[i] = now;
    m_last_bytes_in[i] = bytesIn;
    m_last_bytes_out[i] = bytesOut;

    static int8_t fFull[VALUES_SIZE] = {};
    if (fFull[i] == 0 && m_time_stamp[i].size() <= DESIRED_SAMPLES) {
        fFull[i] = -1;
    }
    while (m_time_stamp[i].size() > DESIRED_SAMPLES) {
        if (m_tt_point < 0 && m_value == i && i < VALUES_SIZE - 1 && fFull[i] < 0) {
            m_bump_value = true;
        }
        fFull[i] = 1;
        m_samples_in[i].pop_back();
        m_samples_out[i].pop_back();
        m_time_stamp[i].pop_back();
    }
}

int TrafficGraphWidget::setGraphRange(int value)
{
    if (!value) {
        m_bump_value = false;
        value = m_value + 2;
    }

    value--;
    m_value = std::min(value, VALUES_SIZE - 1);
    m_range = m_values[m_value];
    m_tt_point = -1;
    updateFmax();
    update();

    return m_values[m_value];
}

void TrafficGraphWidget::saveData()
{
    if (m_data_dir.empty()) return;

    try {
        const fs::path path_traffic_graph{fs::PathFromString(m_data_dir) / "trafficgraph.dat"};
        FILE* file = fsbridge::fopen(path_traffic_graph, "wb");
        if (!file) {
            const std::string file_path{fs::PathToString(path_traffic_graph)};
            LogPrintf("TrafficGraphWidget: failed to open file for writing: %s\n", file_path.c_str());
            return;
        }
        AutoFile file_out{file};
        if (file_out.IsNull()) return;

        file_out << static_cast<uint32_t>(1); // version

        // Always persist effective totals so autosave is crash-safe.
        quint64 total_bytes_recv = m_baseline_bytes_recv;
        quint64 total_bytes_sent = m_baseline_bytes_sent;
        if (m_node) {
            total_bytes_recv += m_node->getTotalBytesRecv();
            total_bytes_sent += m_node->getTotalBytesSent();
        }
        file_out << VARINT(total_bytes_recv) << VARINT(total_bytes_sent);

        for (int i = 0; i < VALUES_SIZE; ++i) {
            file_out << VARINT(static_cast<uint32_t>(m_time_stamp[i].size()));

            for (int j = 0; j < m_samples_in[i].size(); ++j) {
                const float value = m_samples_in[i].at(j);
                uint32_t uint_value;
                std::memcpy(&uint_value, &value, sizeof(value));
                file_out << uint_value;
            }

            for (int j = 0; j < m_samples_out[i].size(); ++j) {
                const float value = m_samples_out[i].at(j);
                uint32_t uint_value;
                std::memcpy(&uint_value, &value, sizeof(value));
                file_out << uint_value;
            }

            for (int j = 0; j < m_time_stamp[i].size(); ++j) {
                file_out << VARINT(static_cast<uint64_t>(m_time_stamp[i].at(j)));
            }

            file_out << VARINT(static_cast<uint64_t>(m_offset[i]));
        }
    } catch (const std::exception& e) {
        LogPrintf("TrafficGraphWidget: error saving data: %s\n", e.what());
    }
}

bool TrafficGraphWidget::loadDataFromBinary()
{
    if (m_data_dir.empty()) return false;

    try {
        const fs::path path_traffic_graph{fs::PathFromString(m_data_dir) / "trafficgraph.dat"};
        FILE* file = fsbridge::fopen(path_traffic_graph, "rb");
        if (!file) return false;

        AutoFile file_in{file};
        if (file_in.IsNull()) return false;

        uint32_t version = 0;
        file_in >> version;
        if (version != 1) return false;

        quint64 total_bytes_recv = 0;
        quint64 total_bytes_sent = 0;
        file_in >> VARINT(total_bytes_recv) >> VARINT(total_bytes_sent);
        m_baseline_bytes_recv = total_bytes_recv;
        m_baseline_bytes_sent = total_bytes_sent;

        for (int i = 0; i < VALUES_SIZE; ++i) {
            m_samples_in[i].clear();
            m_samples_out[i].clear();
            m_time_stamp[i].clear();
            m_offset[i] = 0;
        }

        for (int i = 0; i < VALUES_SIZE; ++i) {
            uint32_t sample_size = 0;
            file_in >> VARINT(sample_size);
            if (sample_size > DESIRED_SAMPLES) sample_size = DESIRED_SAMPLES;

            for (uint32_t j = 0; j < sample_size; ++j) {
                uint32_t uint_value = 0;
                file_in >> uint_value;
                float value = 0.0f;
                std::memcpy(&value, &uint_value, sizeof(value));
                m_samples_in[i].push_back(value);
            }

            for (uint32_t j = 0; j < sample_size; ++j) {
                uint32_t uint_value = 0;
                file_in >> uint_value;
                float value = 0.0f;
                std::memcpy(&value, &uint_value, sizeof(value));
                m_samples_out[i].push_back(value);
            }

            for (uint32_t j = 0; j < sample_size; ++j) {
                uint64_t time_ms = 0;
                file_in >> VARINT(time_ms);
                m_time_stamp[i].push_back(static_cast<int64_t>(time_ms));
            }

            uint64_t offset = 0;
            file_in >> VARINT(offset);
            m_offset[i] = static_cast<int64_t>(offset);
        }

        return true;
    } catch (const std::exception& e) {
        LogPrintf("TrafficGraphWidget: error loading data: %s\n", e.what());
        return false;
    }
}

bool TrafficGraphWidget::loadData()
{
    const bool success = loadDataFromBinary();
    if (!success) return false;

    int first_non_full_band = VALUES_SIZE - 1;
    for (int i = 0; i < VALUES_SIZE; ++i) {
        if (m_time_stamp[i].size() < DESIRED_SAMPLES) {
            first_non_full_band = i;
            break;
        }
    }

    if (first_non_full_band > 0) {
        m_value = first_non_full_band - 1;
        m_bump_value = true;
        m_range = m_values[m_value];
    }

    return true;
}
