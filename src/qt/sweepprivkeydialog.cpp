// Copyright (c) 2026-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/sweepprivkeydialog.h>
#include <qt/forms/ui_sweepprivkeydialog.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <univalue.h>

#include <QMessageBox>
#include <QUrl>

SweepPrivKeyDialog::SweepPrivKeyDialog(QWidget *parent) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::SweepPrivKeyDialog)
{
    ui->setupUi(this);
    ui->privkeyEdit->setUndoRedoEnabled(false);
    connect(ui->closeButton, &QPushButton::clicked, this, &QDialog::close);
    connect(this, &SweepPrivKeyDialog::sweepComplete, this, &SweepPrivKeyDialog::handleResult);
}

SweepPrivKeyDialog::~SweepPrivKeyDialog()
{
    if (m_sweep_thread.joinable()) {
        m_sweep_thread.join();
    }
    ui->privkeyEdit->setPlainText(QString(ui->privkeyEdit->toPlainText().size(), '\0'));
    delete ui;
}

void SweepPrivKeyDialog::setModel(WalletModel *_model)
{
    this->model = _model;
    if (!_model) return;

    ui->walletSelector->clear();
    const std::string current_name = _model->getWalletName().toStdString();
    for (auto& wallet : _model->node().walletLoader().getWallets()) {
        const std::string name = wallet->getWalletName();
        ui->walletSelector->addItem(name.empty() ? tr("[default wallet]") : QString::fromStdString(name),
                                    QString::fromStdString(name));
        if (name == current_name) {
            ui->walletSelector->setCurrentIndex(ui->walletSelector->count() - 1);
        }
    }
    const bool multi = ui->walletSelector->count() > 1;
    ui->walletSelector->setVisible(multi);
    ui->walletLabel->setVisible(multi);
}

void SweepPrivKeyDialog::reject()
{
    on_clearButton_clicked();
    QDialog::reject();
}

void SweepPrivKeyDialog::on_sweepButton_clicked()
{
    if (!model) return;

    QString keyText = ui->privkeyEdit->toPlainText().trimmed();
    if (keyText.isEmpty()) {
        ui->statusLabel->setText(tr("Please enter at least one private key."));
        return;
    }

    QStringList keyLines = keyText.split('\n', Qt::SkipEmptyParts);
    UniValue privkeys(UniValue::VARR);
    for (const QString& line : keyLines) {
        QString trimmed = line.trimmed();
        if (!trimmed.isEmpty()) {
            privkeys.push_back(trimmed.toStdString());
            trimmed.fill('\0');
        }
    }
    keyText.fill('\0');

    if (privkeys.empty()) {
        ui->statusLabel->setText(tr("Please enter at least one private key."));
        return;
    }

    UniValue options(UniValue::VOBJ);
    options.pushKV("privkeys", privkeys);

    QString label = ui->labelEdit->text().trimmed();
    if (!label.isEmpty()) {
        options.pushKV("label", label.toStdString());
    }

    UniValue params(UniValue::VARR);
    params.push_back(options);

    const QString selectedName = ui->walletSelector->currentData().toString();
    QByteArray encodedName = QUrl::toPercentEncoding(selectedName);
    std::string uri = "/wallet/" + std::string(encodedName.constData(), encodedName.length());

    ui->sweepButton->setEnabled(false);
    ui->closeButton->setEnabled(false);
    ui->statusLabel->setText(tr("Sweeping..."));

    if (m_sweep_thread.joinable()) {
        m_sweep_thread.join();
    }

    const QString sweep_failed = tr("Sweep failed");
    WalletModel* m = model;
    m_sweep_thread = std::thread([this, m, params, uri, sweep_failed]() {
        try {
            UniValue result = m->node().executeRpc("sweepprivkeys", params, uri);
            QString txid = QString::fromStdString(result.get_str());
            Q_EMIT sweepComplete(true, txid);
        } catch (const UniValue& e) {
            QString errorMsg;
            if (e.isObject() && e.exists("message")) {
                errorMsg = QString::fromStdString(e["message"].get_str());
            } else {
                errorMsg = sweep_failed;
            }
            Q_EMIT sweepComplete(false, errorMsg);
        } catch (const std::exception&) {
            Q_EMIT sweepComplete(false, sweep_failed);
        }
    });
}

void SweepPrivKeyDialog::handleResult(bool success, const QString& message)
{
    if (m_sweep_thread.joinable()) {
        m_sweep_thread.join();
    }

    if (success) {
        ui->statusLabel->setText(tr("Success! Transaction ID: %1").arg(message));
        QMessageBox::information(this, tr("Sweep Successful"),
            tr("Coins swept successfully.\n\nTransaction ID:\n%1").arg(message));
        on_clearButton_clicked();
    } else {
        ui->statusLabel->setText(tr("Error: %1").arg(message));
    }

    ui->sweepButton->setEnabled(true);
    ui->closeButton->setEnabled(true);
}

void SweepPrivKeyDialog::on_clearButton_clicked()
{
    ui->privkeyEdit->setPlainText(QString(ui->privkeyEdit->toPlainText().size(), '\0'));
    ui->privkeyEdit->clear();
    ui->labelEdit->clear();
    ui->statusLabel->clear();
}
