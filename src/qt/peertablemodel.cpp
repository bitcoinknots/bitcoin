// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/peertablemodel.h>

#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/platformstyle.h>

#include <interfaces/node.h>

#include <utility>

#include <QBrush>
#include <QDebug>
#include <QFont>
#include <QFontInfo>
#include <QImage>
#include <QPainter>
#include <QPixmap>
#include <QList>
#include <QTimer>

bool NodeLessThan::operator()(const CNodeCombinedStats &left, const CNodeCombinedStats &right) const
{
    const CNodeStats *pLeft = &(left.nodeStats);
    const CNodeStats *pRight = &(right.nodeStats);

    if (order == Qt::DescendingOrder)
        std::swap(pLeft, pRight);

    switch(column)
    {
    case PeerTableModel::NetNodeId:
        return pLeft->nodeid < pRight->nodeid;
    case PeerTableModel::Address:
        return pLeft->addrName.compare(pRight->addrName) < 0;
    case PeerTableModel::Direction:
        return pLeft->fInbound > pRight->fInbound;
    case PeerTableModel::ConnectionType:
        return pLeft->m_conn_type < pRight->m_conn_type;
    case PeerTableModel::Subversion:
        return pLeft->cleanSubVer.compare(pRight->cleanSubVer) < 0;
    case PeerTableModel::Ping:
        return pLeft->m_min_ping_usec < pRight->m_min_ping_usec;
    case PeerTableModel::Sent:
        return pLeft->nSendBytes < pRight->nSendBytes;
    case PeerTableModel::Received:
        return pLeft->nRecvBytes < pRight->nRecvBytes;
    }

    return false;
}

// private implementation
class PeerTablePriv
{
public:
    /** Local cache of peer information */
    QList<CNodeCombinedStats> cachedNodeStats;
    /** Column to sort nodes by (default to unsorted) */
    int sortColumn{-1};
    /** Order (ascending or descending) to sort nodes by */
    Qt::SortOrder sortOrder;
    /** Index of rows by node ID */
    std::map<NodeId, int> mapNodeRows;

    /** Pull a full list of peers from vNodes into our cache */
    void refreshPeers(interfaces::Node& node)
    {
        {
            cachedNodeStats.clear();

            interfaces::Node::NodesStats nodes_stats;
            node.getNodesStats(nodes_stats);
            cachedNodeStats.reserve(nodes_stats.size());
            for (const auto& node_stats : nodes_stats)
            {
                CNodeCombinedStats stats;
                stats.nodeStats = std::get<0>(node_stats);
                stats.fNodeStateStatsAvailable = std::get<1>(node_stats);
                stats.nodeStateStats = std::get<2>(node_stats);
                cachedNodeStats.append(stats);
            }
        }

        if (sortColumn >= 0)
            // sort cacheNodeStats (use stable sort to prevent rows jumping around unnecessarily)
            std::stable_sort(cachedNodeStats.begin(), cachedNodeStats.end(), NodeLessThan(sortColumn, sortOrder));

        // build index map
        mapNodeRows.clear();
        int row = 0;
        for (const CNodeCombinedStats& stats : cachedNodeStats)
            mapNodeRows.insert(std::pair<NodeId, int>(stats.nodeStats.nodeid, row++));
    }

    int size() const
    {
        return cachedNodeStats.size();
    }

    CNodeCombinedStats *index(int idx)
    {
        if (idx >= 0 && idx < cachedNodeStats.size())
            return &cachedNodeStats[idx];

        return nullptr;
    }
};

PeerTableModel::PeerTableModel(interfaces::Node& node, const PlatformStyle& platform_style, QObject* parent) :
    QAbstractTableModel(parent),
    m_node(node),
    m_platform_style(platform_style),
    timer(nullptr)
{
    columns << tr("id", "Peer table, referring to node id") << "" << tr("Node/Service") << tr("Type") << tr("Ping") << tr("Sent") << tr("Received") << tr("User Agent");
    priv.reset(new PeerTablePriv());

    // set up timer for auto refresh
    timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &PeerTableModel::refresh);
    timer->setInterval(MODEL_UPDATE_DELAY);

    DrawIcons();

    // load initial data
    refresh();
}

PeerTableModel::~PeerTableModel()
{
    // Intentionally left empty
}

void PeerTableModel::DrawIcons()
{
    static constexpr auto SIZE = 32;
    static constexpr auto ARROW_HEIGHT = SIZE * 2 / 3;
    QImage icon_in(SIZE, SIZE, QImage::Format_Alpha8);
    icon_in.fill(Qt::transparent);
    QImage icon_out(icon_in);
    QPainter icon_in_painter(&icon_in);
    QPainter icon_out_painter(&icon_out);

    // Arrow
    auto DrawArrow = [](const int x, QPainter& icon_painter) {
        icon_painter.setBrush(Qt::SolidPattern);
        QPoint shape[] = {
            {x, ARROW_HEIGHT / 2},
            {(SIZE-1) - x,  0},
            {(SIZE-1) - x, ARROW_HEIGHT-1},
        };
        icon_painter.drawConvexPolygon(shape, 3);
    };
    DrawArrow(0, icon_in_painter);
    DrawArrow(SIZE-1, icon_out_painter);

    {
        const QString label_in  = tr("IN" , "Label on inbound connection icon");
        const QString label_out = tr("OUT", "Label on outbound connection icon");
        QImage scratch(SIZE, SIZE, QImage::Format_Alpha8);
        QPainter scratch_painter(&scratch);
        QFont font;  // NOTE: Application default font
        font.setBold(true);
        auto CheckSize = [&](const QImage& icon, const QString& text, const bool align_right) {
            // Make sure it's at least able to fit (width only)
            if (scratch_painter.boundingRect(0, 0, SIZE, SIZE, 0, text).width() > SIZE) {
                return false;
            }

            // Draw text on the scratch image
            // NOTE: QImage::fill doesn't like QPainter being active
            scratch_painter.setCompositionMode(QPainter::CompositionMode_Source);
            scratch_painter.fillRect(0, 0, SIZE, SIZE, Qt::transparent);
            scratch_painter.setCompositionMode(QPainter::CompositionMode_SourceOver);
            scratch_painter.drawText(0, SIZE, text);

            int text_offset_x = 0;
            if (align_right) {
                // Figure out how far right we can shift it
                for (int col = SIZE-1; col >= 0; --col) {
                    bool any_pixels = false;
                    for (int row = SIZE-1; row >= 0; --row) {
                        int opacity = qAlpha(scratch.pixel(col, row));
                        if (opacity > 0) {
                            any_pixels = true;
                            break;
                        }
                    }
                    if (any_pixels) {
                        text_offset_x = (SIZE-1) - col;
                        break;
                    }
                }
            }

            // Check if there's any overlap
            for (int row = 0; row < SIZE; ++row) {
                for (int col = text_offset_x; col < SIZE; ++col) {
                    int opacity = qAlpha(icon.pixel(col, row));
                    if (col >= text_offset_x) {
                        opacity += qAlpha(scratch.pixel(col - text_offset_x, row));
                    }
                    if (opacity > 0xff) {
                        // Overlap found, we're done
                        return false;
                    }
                }
            }
            return true;
        };
        int font_size = SIZE;
        while (font_size > 1) {
            font.setPixelSize(--font_size);
            scratch_painter.setFont(font);
            if (CheckSize(icon_in , label_in , /* align_right= */ false) &&
                CheckSize(icon_out, label_out, /* align_right= */ true)) break;
        }
        icon_in_painter .drawText(0, 0, SIZE, SIZE, Qt::AlignLeft  | Qt::AlignBottom, label_in);
        icon_out_painter.drawText(0, 0, SIZE, SIZE, Qt::AlignRight | Qt::AlignBottom, label_out);
    }
    m_icon_conn_in  = m_platform_style.TextColorIcon(QIcon(QPixmap::fromImage(icon_in)));
    m_icon_conn_out = m_platform_style.TextColorIcon(QIcon(QPixmap::fromImage(icon_out)));
}

void PeerTableModel::updatePalette()
{
    m_icon_conn_in  = m_platform_style.TextColorIcon(m_icon_conn_in);
    m_icon_conn_out = m_platform_style.TextColorIcon(m_icon_conn_out);
    const auto num_rows = priv->size();
    if (num_rows == 0) return;
    Q_EMIT dataChanged(
        createIndex(0, Direction),
        createIndex(num_rows - 1, Direction),
        QVector<int>{Qt::DecorationRole}
    );
}

void PeerTableModel::startAutoRefresh()
{
    timer->start();
}

void PeerTableModel::stopAutoRefresh()
{
    timer->stop();
}

int PeerTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int PeerTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant PeerTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    CNodeCombinedStats *rec = static_cast<CNodeCombinedStats*>(index.internalPointer());

    if (role == Qt::DisplayRole) {
        switch(index.column())
        {
        case NetNodeId:
            return (qint64)rec->nodeStats.nodeid;
        case Address:
            return QString::fromStdString(rec->nodeStats.addrName);
        case ConnectionType:
            return GUIUtil::ConnectionTypeToShortQString(rec->nodeStats.m_conn_type, rec->nodeStats.fRelayTxes);
        case Subversion:
            return QString::fromStdString(rec->nodeStats.cleanSubVer);
        case Ping:
            return GUIUtil::formatPingTime(rec->nodeStats.m_min_ping_usec);
        case Sent:
            return GUIUtil::formatBytes(rec->nodeStats.nSendBytes);
        case Received:
            return GUIUtil::formatBytes(rec->nodeStats.nRecvBytes);
        }
    } else if (role == Qt::TextAlignmentRole) {
        switch (index.column()) {
            case NetNodeId:
            case Direction:
            case ConnectionType:
            case Ping:
            case Sent:
            case Received:
                return QVariant(Qt::AlignRight | Qt::AlignVCenter);
            default:
                return QVariant();
        }
    } else if (index.column() == Direction && role == Qt::DecorationRole) {
        return rec->nodeStats.fInbound ? m_icon_conn_in : m_icon_conn_out;
    }

    return QVariant();
}

QVariant PeerTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole && section < columns.size())
        {
            return columns[section];
        }
    }
    return QVariant();
}

Qt::ItemFlags PeerTableModel::flags(const QModelIndex &index) const
{
    if (!index.isValid()) return Qt::NoItemFlags;

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    return retval;
}

QModelIndex PeerTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    CNodeCombinedStats *data = priv->index(row);

    if (data)
        return createIndex(row, column, data);
    return QModelIndex();
}

const CNodeCombinedStats *PeerTableModel::getNodeStats(int idx)
{
    return priv->index(idx);
}

void PeerTableModel::refresh()
{
    Q_EMIT layoutAboutToBeChanged();
    priv->refreshPeers(m_node);
    Q_EMIT layoutChanged();
}

int PeerTableModel::getRowByNodeId(NodeId nodeid)
{
    std::map<NodeId, int>::iterator it = priv->mapNodeRows.find(nodeid);
    if (it == priv->mapNodeRows.end())
        return -1;

    return it->second;
}

void PeerTableModel::sort(int column, Qt::SortOrder order)
{
    priv->sortColumn = column;
    priv->sortOrder = order;
    refresh();
}
