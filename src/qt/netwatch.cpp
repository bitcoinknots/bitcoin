// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "netwatch.h"

#include "bitcoinunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "networkstyle.h"

#include "base58.h"
#include "chain.h"
#include "chainparams.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/standard.h"
#include "sync.h"
#include "utiltime.h"
#include "validation.h"
#include "validationinterface.h"

#include <algorithm>
#include <memory>
#include <type_traits>

#include <QAbstractTableModel>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QWidget>
#include <QVBoxLayout>

namespace {

bool IsDatacarrier(const CTxOut& txout)
{
    return (txout.scriptPubKey[0] == OP_RETURN && txout.nValue == 0);
}

size_t CountNonDatacarrierOutputs(const CTransactionRef& tx)
{
    size_t count = 0;
    for (auto& txout : tx->vout) {
        if (IsDatacarrier(txout)) {
            continue;
        }
        ++count;
    }
    return count;
}

const CTxOut* GetNonDatacarrierOutput(const CTransactionRef& tx, const size_t txout_index)
{
    size_t count = 0;
    for (auto& txout : tx->vout) {
        if (IsDatacarrier(txout)) {
            continue;
        }
        if (count == txout_index) {
            return &txout;
        }
        ++count;
    }
    return NULL;
}

}

const QString LogEntry::LogEntryTypeAbbreviation(const LogEntryType LET)
{
    switch (LET) {
        case LET_BLOCK: return QObject::tr("Blk", "Tx Watch: Block type abbreviation");
        case LET_TX:    return QObject::tr("Txn", "Tx Watch: Transaction type abbreviation");
    }
    return QString();
}

void LogEntry::init(const LogEntry& other)
{
    if (!other.data) {
        data = NULL;
        return;
    }
    const meta_t n = *(meta_t*)other.data;
    const int32_t relTimestamp = n & rel_ts_mask;
    switch (n >> 30) {
        case 1:  // CBlockIndex*
            init(relTimestamp, other.getBlockIndex());
            break;
        case 2:  // CTransactionRef
        {
            CTransactionWeakref ptx(*other.get<CTransactionRef>());
            init(relTimestamp, ptx, false);
            break;
        }
        case 3:  // CTransactionWeakref
            init(relTimestamp, *other.get<CTransactionWeakref>(), true);
            break;
    }
}

LogEntry::LogEntry(const LogEntry& other)
{
    init(other);
}

void LogEntry::init(int32_t relTimestamp, const CBlockIndex& blockindex)
{
    relTimestamp &= rel_ts_mask;
    size_t alignment;
    const size_t sz = data_sizeof<CBlockIndex*>(alignment);
    data = (uint8_t*)::operator new(sz);
    *((meta_t*)data) = relTimestamp | (1 << 30);
    *((const CBlockIndex**)&data[alignment]) = &blockindex;
}

LogEntry::LogEntry(int32_t relTimestamp, const CBlockIndex& blockindex)
{
    init(relTimestamp, blockindex);
}

void LogEntry::init(int32_t relTimestamp, const CTransactionWeakref& tx, bool weak)
{
    relTimestamp &= rel_ts_mask;

    // Allocate enough space for either, so we can convert between them
    size_t alignment_shared, alignment_weak;
    const size_t sz = std::max(data_sizeof<CTransactionRef>(alignment_shared), data_sizeof<CTransactionWeakref>(alignment_weak));
    data = (uint8_t*)::operator new(sz);

    uint32_t type;
    if (weak) {
        //std::allocator<std::weak_ptr<CTransaction>>::construct(data + alignment_weak, tx);
        new (data + alignment_weak) CTransactionWeakref(tx);
        type = 3;
    } else {
        new (data + alignment_shared) CTransactionRef(tx.lock());
        type = 2;
    }
    *((meta_t*)data) = relTimestamp | (type << 30);
}

LogEntry::LogEntry(int32_t relTimestamp, const CTransactionWeakref& tx, bool weak)
{
    init(relTimestamp, tx, weak);
}

LogEntry::LogEntry(int32_t relTimestamp, const CTransactionRef& tx, bool weak)
{
    CTransactionWeakref ptx(tx);
    init(relTimestamp, ptx, weak);
}

void LogEntry::clear()
{
    if (!data) {
        return;
    }
    const meta_t n = *(meta_t*)data;
    switch (n >> 30) {
        case 1:  // CBlockIndex*
            break;
        case 2:  // CTransactionRef
            get<CTransactionRef>()->~CTransactionRef();
            break;
        case 3:  // CTransactionWeakref
            get<CTransactionWeakref>()->~CTransactionWeakref();
            break;
    }
    delete data;
}

LogEntry::~LogEntry()
{
    clear();
}

LogEntry& LogEntry::operator=(const LogEntry& other)
{
    if (this != &other) {
        clear();
        init(other);
    }
    return *this;
}

LogEntry::operator bool() const
{
    return data;
}

int32_t LogEntry::getRelTimestamp() const
{
    const meta_t n = *(meta_t*)data;
    return n & rel_ts_mask;
}

uint64_t LogEntry::getTimestamp(uint64_t now) const
{
    uint64_t ts = (now & ~rel_ts_mask64) | getRelTimestamp();
    if (ts > now) {
        ts -= (rel_ts_mask64 + 1);
    }
    return ts;
}

LogEntry::LogEntryType LogEntry::getType() const
{
    const meta_t n = *(meta_t*)data;
    return (n >> 31) ? LET_TX : LET_BLOCK;
}

const CBlockIndex& LogEntry::getBlockIndex() const
{
    return **(get<const CBlockIndex*>());
}

CTransactionRef LogEntry::getTransactionRef() const
{
    const meta_t n = *(meta_t*)data;
    if ((n >> 30) & 1) {
        return get<CTransactionWeakref>()->lock();
    } else {
        return *get<CTransactionRef>();
    }
}

bool LogEntry::isWeak() const
{
    const meta_t n = *(meta_t*)data;
    return ((n >> 30) == 3);
}

bool LogEntry::expired() const
{
    if (isWeak()) {
        return get<CTransactionWeakref>()->expired();
    }
    return false;
}

void LogEntry::makeWeak()
{
    const meta_t n = *(meta_t*)data;
    if ((n >> 30) != 2) {
        return;
    }
    CTransactionRef * const ptx_old = get<CTransactionRef>();
    CTransactionRef tx = *ptx_old;  // save a copy
    ptx_old->~CTransactionRef();
    CTransactionWeakref * const ptx_new = get<CTransactionWeakref>();
    new (ptx_new) CTransactionWeakref(tx);
    *((meta_t*)data) |= (3 << 30);
}

NetWatchLogModel::NetWatchLogModel(QWidget *parent) :
    QAbstractTableModel(parent),
    widget(parent),
    clientModel(NULL),
    logpos(0),
    logskip(0),
    currentSearch(NULL)
{
    GetMainSignals().UpdatedBlockTip.connect(boost::bind(&NetWatchLogModel::LogBlock, this, _1));
    GetMainSignals().AcceptedTransaction.connect(boost::bind(&NetWatchLogModel::LogTransaction, this, _1));
}

NetWatchLogModel::~NetWatchLogModel()
{
    GetMainSignals().UpdatedBlockTip.disconnect(boost::bind(&NetWatchLogModel::LogBlock, this, _1));
    GetMainSignals().AcceptedTransaction.disconnect(boost::bind(&NetWatchLogModel::LogTransaction, this, _1));
}

int NetWatchLogModel::rowCount(const QModelIndex& parent) const
{
    LOCK(cs);
    return log.size() - logskip;
}

int NetWatchLogModel::columnCount(const QModelIndex& parent) const
{
    return NWLMHeaderCount;
}

QVariant NetWatchLogModel::data(const CBlockIndex& blockindex, int txout_index, const Header header) const
{
    switch (header) {
        case NWLMH_TYPE:
            return LogEntry::LogEntryTypeAbbreviation(LogEntry::LET_BLOCK);
        case NWLMH_ID:
            return QString::fromStdString(blockindex.GetBlockHash().GetHex());
        case NWLMH_ADDR:
        case NWLMH_VALUE: {
            if (blockindex.nTx == 0 || !(blockindex.nStatus & BLOCK_HAVE_DATA)) {
                return QVariant();
            }
            CBlock block;
            if (!ReadBlockFromDisk(block, &blockindex, Params().GetConsensus())) {
                // Indicate error somehow?
                return QVariant();
            }
            assert(block.vtx.size());
            return data(block.vtx[0], txout_index, header);
        }
        case NWLMH_TIME: ;  // Not valid here
    }
    return QVariant();
}

QVariant NetWatchLogModel::data(const CTransactionRef& tx, int txout_index, const Header header) const
{
    switch (header) {
        case NWLMH_TYPE:
            return LogEntry::LogEntryTypeAbbreviation(LogEntry::LET_TX);
        case NWLMH_ID:
            return QString::fromStdString(tx->GetHash().GetHex());
        case NWLMH_ADDR: {
            const CTxOut *ptxout = GetNonDatacarrierOutput(tx, txout_index);
            if (!ptxout) {
                // Only datacarriers
                ptxout = &tx->vout[0];
            }
            CTxDestination txdest;
            if (ptxout->scriptPubKey[0] == OP_RETURN && ptxout->nValue > 0) {
                return tr("(Burn)", "Tx Watch: Provably burned value in transaction");
            } else if (!ExtractDestination(ptxout->scriptPubKey, txdest)) {
                return tr("(Unknown)", "Tx Watch: Unknown transaction output type");
            }
            return QString::fromStdString(CBitcoinAddress(txdest).ToString());
        }
        case NWLMH_VALUE: {
            const CTxOut *ptxout = GetNonDatacarrierOutput(tx, txout_index);
            if (!ptxout) {
                ptxout = &tx->vout[0];
            }
            if (clientModel) {
                return BitcoinUnits::format(clientModel->getOptionsModel()->getDisplayUnit(), ptxout->nValue);
            } else {
                return qlonglong(ptxout->nValue);
            }
        }
        case NWLMH_TIME: ;  // Not valid here
    }
    return QVariant();
}

const LogEntry& NetWatchLogModel::getLogEntryRow(int row) const
{
    AssertLockHeld(cs);
    size_t pos = (logpos + row) % log.size();
    return log[pos];
}

LogEntry& NetWatchLogModel::getLogEntryRow(int row)
{
    AssertLockHeld(cs);
    size_t pos = (logpos + row) % log.size();
    return log[pos];
}

bool NetWatchLogModel::isLogRowContinuation(int row) const
{
    AssertLockHeld(cs);
    return !getLogEntryRow(row);
}

const LogEntry& NetWatchLogModel::findLogEntry(int row, int& out_entry_row) const
{
    AssertLockHeld(cs);
    out_entry_row = 0;
    while (row && isLogRowContinuation(row)) {
        --row;
        ++out_entry_row;
    }
    return getLogEntryRow(row);
}

QVariant NetWatchLogModel::data(const QModelIndex& index, int role) const
{
    const Header header = Header(index.column());
    switch (role) {
        case Qt::DisplayRole:
            break;
        case Qt::BackgroundRole: {
            if (!data(index, Qt::DisplayRole).isValid()) {
                return widget->palette().brush(QPalette::WindowText);
            }
            LogEntry::LogEntryType type;
            {
                int entry_row;
                LOCK(cs);
                const LogEntry& le = findLogEntry(index.row(), entry_row);
                type = le.getType();
            }
            if (type == LogEntry::LET_BLOCK) {
                return widget->palette().brush(QPalette::AlternateBase);
            }
            return QVariant();
        }
        case Qt::ForegroundRole: {
            if (index.column() < 3) {
                bool iscont;
                {
                    LOCK(cs);
                    iscont = isLogRowContinuation(index.row());
                }
                if (iscont) {
                    QBrush brush = widget->palette().brush(QPalette::WindowText);
                    QColor color = brush.color();
                    color.setAlpha(color.alpha() / 2);
                    brush.setColor(color);
                    return brush;
                }
            }
            return QVariant();
        }
        case Qt::TextAlignmentRole:
            if (header == NWLMH_VALUE) {
                return QVariant(Qt::AlignRight | Qt::AlignVCenter);
            }
            return QVariant();
        case Qt::FontRole:
            if (header == NWLMH_ID) {
                return GUIUtil::fixedPitchFont();
            }
            return QVariant();
        default:
            return QVariant();
    }
    int entry_row;
    LOCK(cs);
    const LogEntry& le = findLogEntry(index.row(), entry_row);
    if (header == NWLMH_TIME) {
        return GUIUtil::dateTimeStr(le.getTimestamp(GetTime()));
    }
    const LogEntry::LogEntryType type = le.getType();
    if (type == LogEntry::LET_BLOCK) {
        return data(le.getBlockIndex(), entry_row, header);
    }
    if (header == NWLMH_TYPE) {
        return LogEntry::LogEntryTypeAbbreviation(LogEntry::LET_TX);
    }

    if (le.expired()) {
        return QVariant();
    }
    return data(le.getTransactionRef(), entry_row, header);
}

QVariant NetWatchLogModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QVariant();
    }
    switch (section) {
        case NWLMH_TIME:  return tr("Time"   , "NetWatch: Time header");
        case NWLMH_TYPE:  return tr("Type"   , "NetWatch: Type header");
        case NWLMH_ID:    return tr("Id"     , "NetWatch: Block hash / Txid header");
        case NWLMH_ADDR:  return tr("Address", "NetWatch: Address header");
        case NWLMH_VALUE:
            if (clientModel) {
                return BitcoinUnits::getAmountColumnTitle(clientModel->getOptionsModel()->getDisplayUnit());
            } else {
                // Used only for sizing of the column
                return BitcoinUnits::getAmountColumnTitle(BitcoinUnits::mBTC);
            }
    }
    return QVariant();
}

NetWatchLogSearch::NetWatchLogSearch(const QString& _query, int displayunit) :
    query(_query)
{
    const QRegExp reHex("^[\\da-f]+$", Qt::CaseInsensitive, QRegExp::RegExp2);
    const QRegExp reType("^(T(xn?)?|B(lk?)?)$", Qt::CaseInsensitive, QRegExp::RegExp2);

    fCheckType = query.length() < 4 && reType.exactMatch(query);
    fCheckId = query.length() <= 64 && reHex.exactMatch(query);
    fCheckAddr = query.length() <= nLongestAddress;
    CAmount val;
    fCheckValue = BitcoinUnits::parse(displayunit, query, &val) && val >= 0 && val <= BitcoinUnits::maxMoney();
}

bool NetWatchLogSearch::match(const NetWatchLogModel& model, int row) const
{
    if (model.data(model.index(row, NetWatchLogModel::NWLMH_TIME)).toString().contains(query)) {
        return true;
    } else if (fCheckType && model.data(model.index(row, NetWatchLogModel::NWLMH_TYPE)).toString().contains(query, Qt::CaseInsensitive)) {
        return true;
    } else if (fCheckId && model.data(model.index(row, NetWatchLogModel::NWLMH_ID)).toString().contains(query, Qt::CaseInsensitive)) {
        return true;
    } else if (fCheckAddr && model.data(model.index(row, NetWatchLogModel::NWLMH_ADDR)).toString().contains(query, Qt::CaseInsensitive)) {
        return true;
    } else if (fCheckValue && model.data(model.index(row, NetWatchLogModel::NWLMH_VALUE)).toString().contains(query)) {
        return true;
    }
    return false;
}

void NetWatchLogModel::searchRows(const QString& query, QList<int>& results)
{
    const auto currentUnit = clientModel->getOptionsModel()->getDisplayUnit();
    NetWatchLogSearch *newsearch = new NetWatchLogSearch(query, currentUnit);
    LOCK(cs);
    if (currentSearch) {
        delete currentSearch;
    }
    currentSearch = newsearch;

    bool fAdding = false;
    const size_t rows_used = rowCount();
    for (size_t row = 0; row < rows_used; ++row) {
        if (isLogRowContinuation(row) || newsearch->fCheckAddr || newsearch->fCheckValue) {
            // Check for a match
            fAdding = newsearch->match(*this, row);
        }
        if (fAdding) {
            results.append(row);
        }
    }
}

void NetWatchLogModel::searchDisable() {
    LOCK(cs);
    delete currentSearch;
    currentSearch = NULL;
}

void NetWatchLogModel::log_append(const LogEntry& le, size_t& rows_used)
{
    AssertLockHeld(cs);
    if (logskip) {
    // Replace a deleted row
        getLogEntryRow(rows_used) = le;
        --logskip;
    } else {

    // Haven't filled up yet, so just push_back
    if (!logpos) {
        qWarning("Haven't filled up yet, so just push_back...");
    }

    log.push_back(le);

    }
    ++rows_used;
    if (rows_used > max_nonweak_txouts) {
        LogEntry& old_le = getLogEntryRow(rows_used - max_nonweak_txouts - 1);
        if (old_le) {
            old_le.makeWeak();
        }
    }
}

void NetWatchLogModel::LogAddEntry(const LogEntry& le, size_t vout_count)
{
    if (vout_count < 1) {
        vout_count = 1;
    }
    const QModelIndex dummy;
    LOCK(cs);
    size_t rows_to_remove = 0;
    if (vout_count >= max_vout_per_tx) {
        vout_count = max_vout_per_tx;
    }
    size_t rows_used = rowCount();
    if (rows_used > logsizelimit - vout_count) {
        rows_to_remove = (rows_used + vout_count) - logsizelimit;
    }
    if (rows_to_remove) {
        // Don't orphan continuation entries
        while (isLogRowContinuation(rows_to_remove)) {
            ++rows_to_remove;
        }

        beginRemoveRows(dummy, 0, rows_to_remove - 1);
        logpos = (logpos + rows_to_remove) % log.size();
        logskip += rows_to_remove;
        endRemoveRows();

        rows_used = rowCount();
    }

    const LogEntry cont_le;
    const int first_new_row = rows_used, last_new_row = rows_used + vout_count - 1;
    beginInsertRows(dummy, first_new_row, last_new_row);
    log_append(le, rows_used);
    for (size_t i = 1; i < vout_count; ++i) {
        log_append(cont_le, rows_used);
    }
    endInsertRows();

    if (currentSearch) {
        QList<int> new_matches;
        if (currentSearch->fCheckAddr || currentSearch->fCheckValue) {
            for (int row = first_new_row; row <= last_new_row; ++row) {
                if (currentSearch->match(*this, row)) {
                    new_matches.append(row);
                }
            }
        } else if (currentSearch->match(*this, first_new_row)) {
            for (int row = first_new_row; row <= last_new_row; ++row) {
                new_matches.append(row);
            }
        }
        if (!new_matches.isEmpty()) {
            Q_EMIT moreSearchResults(new_matches);
        }
    }
}

void NetWatchLogModel::LogBlock(const CBlockIndex* pblockindex)
{
    CBlock block;
    if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
        // Indicate error somehow?
        return;
    }
    assert(block.vtx.size());
    const size_t vout_count = CountNonDatacarrierOutputs(block.vtx[0]);
    LogAddEntry(LogEntry(GetTime(), *pblockindex), vout_count);
}

void NetWatchLogModel::LogTransaction(const CTransactionRef& tx)
{
    const size_t vout_count = CountNonDatacarrierOutputs(tx);
    LogAddEntry(LogEntry(GetTime(), tx), vout_count);
}

void NetWatchLogModel::setClientModel(ClientModel *model)
{
    if (clientModel) {
        disconnect(clientModel->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
    }
    clientModel = model;
    if (model) {
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
    }
    updateDisplayUnit();
}

void NetWatchLogModel::updateDisplayUnit()
{
    Q_EMIT headerDataChanged(Qt::Horizontal, NWLMH_VALUE, NWLMH_VALUE);
    Q_EMIT dataChanged(index(0, NWLMH_VALUE), index(rowCount() - 1, NWLMH_VALUE));
}

int NetWatchLogTestModel::rowCount(const QModelIndex& parent) const
{
    return 2;
}

QVariant NetWatchLogTestModel::data(const QModelIndex& index, int role) const
{
    const NetWatchLogModel::Header header = NetWatchLogModel::Header(index.column());
    if (role == Qt::FontRole && header == NWLMH_ID) {
        return GUIUtil::fixedPitchFont();
    } else if (role != Qt::DisplayRole) {
        return QVariant();
    }
    switch (header) {
        case NWLMH_TIME:
            return GUIUtil::dateTimeStr(GetTime());
        case NWLMH_TYPE:
            return LogEntry::LogEntryTypeAbbreviation(LogEntry::LogEntryType(index.row()));
        case NWLMH_ID:
            return QString(64, '0');
        case NWLMH_ADDR:
            return QString(nLongestAddress, 'W');
        case NWLMH_VALUE:
            return "20000000.00000000";
    }
    return QVariant();
}

GuiNetWatch::GuiNetWatch(const PlatformStyle *platformStyle, const NetworkStyle *networkStyle, QWidget *parent) :
    QWidget(parent),
    dontCancelSearch(false)
{
    QVBoxLayout * const layout = new QVBoxLayout(this);

    leSearch = new QLineEdit(this);
#if QT_VERSION >= 0x040700
    leSearch->setPlaceholderText("Search");
#endif
    layout->addWidget(leSearch);

    tvLog = new QTableView(this);
    tvLog->verticalHeader()->hide();
    tvLog->setSizePolicy(QSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored));
    tvLog->setSelectionBehavior(QAbstractItemView::SelectRows);
    tvLog->setTabKeyNavigation(false);
    tvLog->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);

    {
        NetWatchLogTestModel testmodel;
        tvLog->setModel(&testmodel);
        tvLog->resizeColumnsToContents();

        modelLog = new NetWatchLogModel(this);
        tvLog->setModel(modelLog);
    }
    layout->addWidget(tvLog);

    setWindowTitle(tr(PACKAGE_NAME) + " - " + tr("Network Watch") + " " + networkStyle->getTitleAddText());
    setMinimumSize(640, 480);
    resize(layout->contentsMargins().left() + (tvLog->frameWidth() * 2) + tvLog->columnViewportPosition(NetWatchLogModel::NWLMHeaderCount-1) + tvLog->columnWidth(NetWatchLogModel::NWLMHeaderCount-1) + tvLog->verticalScrollBar()->size().width() + layout->contentsMargins().right(), 480);
    setWindowIcon(networkStyle->getTrayAndWindowIcon());

    connect(leSearch, SIGNAL(textChanged(const QString&)), this, SLOT(doSearch(const QString&)));

    connect(modelLog, SIGNAL(rowsRemoved(const QModelIndex&, int, int)), this, SLOT(rowsRemoved(const QModelIndex&, int, int)));
    connect(modelLog, SIGNAL(rowsAboutToBeInserted(const QModelIndex&, int, int)), this, SLOT(aboutToInsert()));
    connect(modelLog, SIGNAL(rowsInserted(const QModelIndex&, int, int)), this, SLOT(maybeScrollToBottom()));
    connect(modelLog, SIGNAL(moreSearchResults(const QList<int>&)), this, SLOT(moreSearchResults(const QList<int>&)));

    connect(tvLog->selectionModel(), SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)), this, SLOT(maybeCancelSearch()));

    setLayout(layout);
}

void GuiNetWatch::setClientModel(ClientModel *model)
{
    modelLog->setClientModel(model);
}

void GuiNetWatch::rowsRemoved(const QModelIndex& parent, int start, int end)
{
    if (tvLog->verticalScrollBar()->value() >= tvLog->verticalScrollBar()->maximum()) {
        return;
    }
    // Maintain the current viewed entries in place
    int scrollpos = tvLog->verticalScrollBar()->value();
    if (start < scrollpos) {
        scrollpos -= std::max(0, 1 + end - start);
        tvLog->verticalScrollBar()->setValue(scrollpos);
    }
}

void GuiNetWatch::aboutToInsert()
{
    adjustscroll = (tvLog->verticalScrollBar()->value() >= tvLog->verticalScrollBar()->maximum());
}

void GuiNetWatch::maybeScrollToBottom()
{
    if (adjustscroll) {
        tvLog->scrollToBottom();
    }
}

void GuiNetWatch::doSearch(const QString& query)
{
    if (query.isEmpty()) {
        modelLog->searchDisable();
        leSearch->setStyleSheet("");
        return;
    }
    QList<int> results;
    modelLog->searchRows(query, results);
    if (results.isEmpty()) {
        leSearch->setStyleSheet(STYLE_INVALID);
        return;
    }
    leSearch->setStyleSheet(STYLE_ACTIVE);
    QItemSelectionModel& sel = *tvLog->selectionModel();
    dontCancelSearch = true;
    sel.clear();
    Q_FOREACH (int row, results) {
        sel.select(modelLog->index(row, 0), QItemSelectionModel::Rows | QItemSelectionModel::Select);
    }
    dontCancelSearch = false;
    tvLog->scrollTo(modelLog->index(results.back(), NetWatchLogModel::NWLMH_ID));
}

void GuiNetWatch::moreSearchResults(const QList<int>& rows)
{
    leSearch->setStyleSheet(STYLE_ACTIVE);
    QItemSelectionModel& sel = *tvLog->selectionModel();
    dontCancelSearch = true;
    Q_FOREACH (int row, rows) {
        sel.select(modelLog->index(row, 0), QItemSelectionModel::Rows | QItemSelectionModel::Select);
    }
    dontCancelSearch = false;
}

void GuiNetWatch::maybeCancelSearch()
{
    if (dontCancelSearch) {
        return;
    }
    leSearch->setStyleSheet("");
    modelLog->searchDisable();
}
