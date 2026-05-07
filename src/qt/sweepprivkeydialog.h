// Copyright (c) 2026-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SWEEPPRIVKEYDIALOG_H
#define BITCOIN_QT_SWEEPPRIVKEYDIALOG_H

#include <QDialog>

#include <thread>

class WalletModel;

namespace Ui {
    class SweepPrivKeyDialog;
}

class SweepPrivKeyDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SweepPrivKeyDialog(QWidget *parent = nullptr);
    ~SweepPrivKeyDialog();

    void setModel(WalletModel *model);
    void reject() override;

private Q_SLOTS:
    void on_sweepButton_clicked();
    void on_clearButton_clicked();
    void handleResult(bool success, const QString& message);

Q_SIGNALS:
    void sweepComplete(bool success, const QString& message);

private:
    Ui::SweepPrivKeyDialog *ui;
    WalletModel *model{nullptr};
    std::thread m_sweep_thread;
};

#endif // BITCOIN_QT_SWEEPPRIVKEYDIALOG_H
