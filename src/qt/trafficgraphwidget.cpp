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
#include <QFocusEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QSlider>
#include <QTimer>
#include <QToolTip>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <limits>

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
    setFocusPolicy(Qt::StrongFocus);
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
    m_new_value = m_value;
    m_range = m_values[m_value];
    updateFmax();
    fMax = m_new_fmax;
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
    focusSlider(Qt::MouseFocusReason);
    QWidget::mousePressEvent(event);
    m_toggle = !m_toggle;
    update();
}

void TrafficGraphWidget::mouseReleaseEvent(QMouseEvent* event)
{
    QWidget::mouseReleaseEvent(event);
    focusSlider(Qt::MouseFocusReason);
}

void TrafficGraphWidget::focusInEvent(QFocusEvent* event)
{
    QWidget::focusInEvent(event);
    focusSlider(Qt::OtherFocusReason);
}

void TrafficGraphWidget::focusSlider(Qt::FocusReason reason)
{
    QWidget* parent = parentWidget();
    if (parent) {
        QSlider* slider = parent->findChild<QSlider*>("sldGraphRange");
        if (slider) slider->setFocus(reason);
    }
}

void TrafficGraphWidget::mouseMoveEvent(QMouseEvent* event)
{
    QWidget::mouseMoveEvent(event);
    static int last_x = -1, last_y = -1;
    int x = event->x(), y = event->y();
    m_x_offset = event->globalX() - x;
    m_y_offset = event->globalY() - y;
    if (last_x == x && last_y == y) return;

    int h = height() - YMARGIN * 2, w = width() - XMARGIN * 2;
    int i = (w + XMARGIN - x) * DESIRED_SAMPLES / w, closest_i = -1;
    unsigned int smallest_distance = 50;
    int sampleSize = m_time_stamp[m_value].size();
    bool is_in_series = true;
    if (sampleSize && i >= -10 && i < sampleSize + 2 && y <= h + YMARGIN + 3) {
        for (int test_i = std::max(i - 2, 0); test_i < std::min(i + 10, sampleSize); test_i++) {
            float in_val = m_samples_in[m_value].at(test_i), out_val = m_samples_out[m_value].at(test_i);
            int y_in = y_value(in_val), y_out = y_value(out_val);
            unsigned int distance_in = abs(y - y_in), distance_out = abs(y - y_out);
            unsigned int min_distance = std::min(distance_in, distance_out);
            if (min_distance < smallest_distance) {
                smallest_distance = min_distance;
                closest_i = test_i;
                is_in_series = distance_in <= distance_out;
            }
        }
    }
    if (m_tt_point != closest_i || m_tt_in_series != is_in_series) {
        m_tt_point = closest_i;
        m_tt_in_series = is_in_series;
        update();
    }
    last_x = x;
    last_y = y;
}

void TrafficGraphWidget::drawTooltipPoint(QPainter& painter)
{
    int w = width() - XMARGIN * 2;
    double ratio = static_cast<double>(m_tt_point) * m_values[m_value] / m_range / DESIRED_SAMPLES;
    int x = XMARGIN + w - static_cast<int>(w * ratio);
    float in_sample = m_samples_in[m_value].at(m_tt_point);
    float out_sample = m_samples_out[m_value].at(m_tt_point);
    float selected_sample = m_tt_in_series ? in_sample : out_sample;
    int y = y_value(selected_sample);
    painter.setPen(Qt::yellow);
    painter.drawEllipse(QPointF(x, y), 3, 3);

    QString str_time;
    int64_t sample_time;
    if (m_tt_point + 1 < m_time_stamp[m_value].size()) {
        sample_time = m_time_stamp[m_value].at(m_tt_point + 1);
    } else {
        str_time = "to ";
        sample_time = m_time_stamp[m_value].at(m_tt_point);
    }
    int age = GetTime() - sample_time / 1000;
    if (age < 60 * 60 * 23) {
        str_time += QString::fromStdString(FormatISO8601Time(sample_time / 1000));
    } else {
        str_time += QString::fromStdString(FormatISO8601DateTime(sample_time / 1000));
    }
    int n_duration = m_time_stamp[m_value].at(m_tt_point) - sample_time;
    if (n_duration > 0) {
        if (n_duration > 9999) {
            str_time += " +" + GUIUtil::formatDurationStr(std::chrono::seconds{(n_duration + 500) / 1000});
        } else {
            str_time += " +" + GUIUtil::formatPingTime(std::chrono::microseconds{n_duration * 1000});
        }
    }
    QString str_data = tr("In") + " " + GUIUtil::formatBytesps(in_sample * 1000) + " " + tr("Out") + " " + GUIUtil::formatBytesps(out_sample * 1000);
    QToolTip::showText(QPoint(x + m_x_offset, y + m_y_offset), str_time + "\n. " + str_data);
    QToolTip::showText(QPoint(x + m_x_offset, y + m_y_offset), str_time + "\n  " + str_data);
    m_tt_time = GetTime();
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
    if (m_tt_point >= 0 && m_tt_point < m_time_stamp[m_value].size() && isVisible() && !window()->isMinimized()) {
        drawTooltipPoint(painter);
    } else {
        QToolTip::hideText();
    }
}

void TrafficGraphWidget::updateFmax()
{
    float tmax = 0.0f;
    for (const float f : m_samples_in[m_new_value]) {
        if (f > tmax) tmax = f;
    }
    for (const float f : m_samples_out[m_new_value]) {
        if (f > tmax) tmax = f;
    }
    m_new_fmax = tmax;
}

static bool update_num(float new_val, float& current, float& increment, int length)
{
    if (new_val <= 0 || current == new_val || length <= 0) return false;

    if (std::abs(increment) <= std::abs(0.8f * current) / length) {
        if (new_val > current) {
            increment = 1.0f * (current + 1) / length;
        } else {
            increment = -1.0f * (current + 1) / length;
        }
        if (std::abs(increment) > std::abs(new_val - current)) {
            increment = 0;
            current = new_val;
            return true;
        }
    } else {
        if ((increment > 0 && current + increment * 2 > new_val) || (increment < 0 && current + increment * 2 < new_val)) {
            increment = increment / 2;
        } else if ((increment > 0 && current + increment * 8 < new_val) || (increment < 0 && current + increment * 8 > new_val)) {
            increment = increment * 2;
        }
    }

    if (std::abs(increment) < 0.8f * current / length) {
        if ((increment >= 0 && new_val > current) || (increment <= 0 && new_val < current)) {
            current = new_val;
            increment = 0;
        }
    } else {
        current += increment;
    }
    if (current <= 0.0f) current = 0.0001f;
    return true;
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
            if (i == m_new_value) {
                updateFmax();
            }
        }
    }

    static float y_increment = 0.0f;
    static float x_increment = 0.0f;
    if (update_num(m_new_fmax, fMax, y_increment, height() - YMARGIN * 2)) {
        update_needed = true;
    }

    int next_value = m_value;
    if (update_num(m_values[m_new_value], m_range, x_increment, width() - XMARGIN * 2)) {
        if (m_values[m_new_value] > m_range && m_values[m_value] < m_range) {
            next_value = m_value + 1;
        } else if (m_value > 0 && m_values[m_new_value] <= m_range && m_values[m_value - 1] > m_range * 0.99f) {
            next_value = m_value - 1;
        }
        update_needed = true;
    } else if (m_value != m_new_value) {
        next_value = m_new_value;
        update_needed = true;
    }

    if (next_value != m_value) {
        if (m_tt_point >= 0 && m_tt_point < m_time_stamp[m_value].size()) {
            m_tt_point = findClosestPointByTimestamp(m_value, m_tt_point, next_value);
        } else {
            m_tt_point = -1;
        }
        m_value = next_value;
    }

    if (!QToolTip::isVisible() || !isVisible() || window()->isMinimized()) {
        if (m_tt_point >= 0) {
            m_tt_point = -1;
            update_needed = true;
        }
    } else if (m_tt_point >= 0 && GetTime() >= m_tt_time + 9) {
        update_needed = true;
    }

    if (update_needed) update();

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
    int old_value = m_new_value;
    m_new_value = std::min(value, VALUES_SIZE - 1);
    if (m_new_value != old_value) {
        updateFmax();
    }

    return m_values[m_new_value];
}

int TrafficGraphWidget::findClosestPointByTimestamp(int sourceRange, int sourcePoint, int targetRange) const
{
    if (sourcePoint < 0 || sourcePoint >= m_time_stamp[sourceRange].size() || m_time_stamp[targetRange].empty()) {
        return -1;
    }

    bool is_peak = false;
    bool is_dip = false;
    float source_value = m_tt_in_series ? m_samples_in[sourceRange].at(sourcePoint) : m_samples_out[sourceRange].at(sourcePoint);
    if (sourcePoint > 0 && sourcePoint < m_time_stamp[sourceRange].size() - 1) {
        float prev = m_tt_in_series ? m_samples_in[sourceRange].at(sourcePoint - 1) : m_samples_out[sourceRange].at(sourcePoint - 1);
        float next = m_tt_in_series ? m_samples_in[sourceRange].at(sourcePoint + 1) : m_samples_out[sourceRange].at(sourcePoint + 1);
        is_peak = source_value > prev && source_value > next;
        is_dip = source_value < prev && source_value < next;
    }

    int64_t source_timestamp = m_time_stamp[sourceRange].at(sourcePoint);
    int closest_point = -1;
    int64_t min_difference = std::numeric_limits<int64_t>::max();
    for (int i = 0; i < m_time_stamp[targetRange].size(); ++i) {
        int64_t diff = std::abs(m_time_stamp[targetRange].at(i) - source_timestamp);
        if (diff < min_difference) {
            min_difference = diff;
            closest_point = i;
        }
    }

    if (closest_point >= 0 && (is_peak || is_dip)) {
        int best_point = closest_point;
        float best_value = m_tt_in_series ? m_samples_in[targetRange].at(closest_point) : m_samples_out[targetRange].at(closest_point);
        uint64_t avg_sample_interval = (m_values[targetRange] * 60 * 1000) / DESIRED_SAMPLES;
        uint64_t time_window = avg_sample_interval * 3;
        for (int i = 0; i < m_time_stamp[targetRange].size(); ++i) {
            uint64_t time_diff = static_cast<uint64_t>(std::abs(m_time_stamp[targetRange].at(i) - source_timestamp));
            if (time_diff <= time_window) {
                float current_value = m_tt_in_series ? m_samples_in[targetRange].at(i) : m_samples_out[targetRange].at(i);
                if ((is_peak && current_value > best_value) || (is_dip && current_value < best_value)) {
                    best_point = i;
                    best_value = current_value;
                }
            }
        }
        closest_point = best_point;
    }

    return closest_point;
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
