// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/pairingpage.h>
#include <qt/qrimagewidget.h>

#include <QEvent>
#include <QFormLayout>
#include <QLabel>
#include <QLayout>
#include <QLineEdit>

PairingPage::PairingPage(QWidget *parent) :
    QWidget(parent)
{
    QVBoxLayout *layout = new QVBoxLayout(this);

    m_label_experimental = new QLabel(this);
    m_label_experimental->setMargin(3);
    m_label_experimental->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_label_experimental->setWordWrap(true);
    m_label_experimental->setText(tr("Pairing is an experimental feature that currently only works when Tor is enabled. It is expected that the pairing address below will change with future updates, and you may need to re-pair after upgrading."));
    layout->addWidget(m_label_experimental);
    updateThemeStyles();

    QLabel *label_summary = new QLabel(this);
    label_summary->setText(tr("Below you will find information to pair other software or devices with this node:"));
    layout->addWidget(label_summary);

    QFormLayout *form_layout = new QFormLayout();
    m_onion_address = new QLineEdit(this);
    m_onion_address->setReadOnly(true);
    form_layout->addRow(tr("Onion address: "), m_onion_address);

    layout->addLayout(form_layout);

    m_qrcode = new QRImageWidget(this);
#ifdef USE_QRCODE
    layout->addWidget(m_qrcode);
#endif

    layout->addStretch();

    refresh();
}

void PairingPage::changeEvent(QEvent* e)
{
    if (e->type() == QEvent::PaletteChange) {
        updateThemeStyles();
    }

    QWidget::changeEvent(e);
}

void PairingPage::setClientModel(ClientModel *client_model)
{
    if (m_client_model) {
        disconnect(m_client_model, &ClientModel::networkLocalChanged, this, &PairingPage::refresh);
    }
    m_client_model = client_model;
    if (client_model) {
        connect(client_model, &ClientModel::networkLocalChanged, this, &PairingPage::refresh);
    }
    refresh();
}

void PairingPage::refresh()
{
    QString onion;
    if (m_client_model && m_client_model->getTorInfo(onion)) {
        m_onion_address->setText(onion);
        m_onion_address->setEnabled(true);
        QString uri = QString("bitcoin-p2p://") + onion;
        m_qrcode->setQR(uri);
        m_qrcode->setVisible(true);
    } else {
        m_onion_address->setText(tr("(not connected)"));
        m_onion_address->setEnabled(false);
        m_qrcode->setVisible(false);
    }
}

void PairingPage::updateThemeStyles()
{
    if (m_label_experimental) {
        m_label_experimental->setStyleSheet(GUIUtil::getThemedWarningLabelStyle(palette()));
    }
}
