// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#ifdef ENABLE_DATUM

#include <qt/datumcoinbasetag.h>
#include <qt/datumcoinbasetag_words.h>

#include <common/args.h>
#include <mining/datum_bridge.h>

#include <QDialog>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRandomGenerator>
#include <QVBoxLayout>

#include <array>
#include <string>

namespace DatumCoinbaseTagUtil {
namespace {

using DatumCoinbaseTagWords::WOW_ADVERBS;
using DatumCoinbaseTagWords::WOW_ADJECTIVES;
using DatumCoinbaseTagWords::WOW_NOUNS;

bool HasConfigUnsafeWhitespace(const std::string& value)
{
    constexpr std::string_view whitespace{" \t\r\n"};
    return value.find_first_of("\r\n") != std::string::npos ||
        (!value.empty() && (whitespace.find(value.front()) != std::string_view::npos ||
                            whitespace.find(value.back()) != std::string_view::npos));
}

void ConnectRandomButton(QPushButton* random_button, QLineEdit* tag_edit)
{
    QObject::connect(random_button, &QPushButton::clicked, tag_edit, [tag_edit] {
        tag_edit->setText(GenerateRandomWowTag());
        tag_edit->setFocus();
        tag_edit->selectAll();
    });
}

} // namespace

QString GenerateRandomWowTag()
{
    auto& rng{*QRandomGenerator::global()};
    const QString adverb{WOW_ADVERBS[rng.bounded(static_cast<int>(WOW_ADVERBS.size()))]};
    const QString adjective{WOW_ADJECTIVES[rng.bounded(static_cast<int>(WOW_ADJECTIVES.size()))]};
    const QString noun{WOW_NOUNS[rng.bounded(static_cast<int>(WOW_NOUNS.size()))]};
    return adverb + QLatin1Char(' ') + adjective + QLatin1Char(' ') + noun;
}

QWidget* CreateInputRow(QWidget* parent, QLineEdit** tag_edit_out)
{
    auto* const row{new QWidget(parent)};
    auto* const layout{new QHBoxLayout(row)};
    layout->setContentsMargins(0, 0, 0, 0);

    auto* const tag_edit{new QLineEdit(row)};
    tag_edit->setToolTip(QObject::tr("Optional operator-controlled coinbase tag, up to 63 bytes."));

    auto* const random_button{new QPushButton(QObject::tr("Random"), row)};
    random_button->setToolTip(QObject::tr("Generate a random WoW-style name (adverb + adjective + noun)."));
    ConnectRandomButton(random_button, tag_edit);

    layout->addWidget(tag_edit);
    layout->addWidget(random_button);

    if (tag_edit_out) *tag_edit_out = tag_edit;
    return row;
}

bool SaveCoinbaseTag(const std::string& tag, std::string& error)
{
    if (HasConfigUnsafeWhitespace(tag)) {
        error = "coinbase tag cannot contain leading or trailing whitespace or newlines";
        return false;
    }
    if (tag.size() > 63) {
        error = "coinbase tag must be at most 63 bytes";
        return false;
    }
    if (tag.empty() || tag == mining::DEFAULT_DATUM_COINBASE_TAG) {
        error = "coinbase tag must be customized";
        return false;
    }

    const mining::DatumStatusSnapshot status{mining::GetDatumStatusSnapshot(/*include_miners=*/false)};
    if (status.running) {
        if (!mining::SetDatumPayoutAndCoinbase(status.payout_address, tag, error)) {
            return false;
        }
    }

    gArgs.ModifyRWConfigFile({{"datumcoinbasetag", tag}}, /*also_settings_json=*/false);
    return true;
}

void MaybePromptOnStartup(QWidget* parent)
{
    if (!gArgs.GetBoolArg("-datum", false)) return;
    if (!mining::IsUnsetOrDefaultDatumCoinbaseTag(gArgs)) return;

    QDialog dialog(parent);
    dialog.setWindowTitle(QObject::tr("Set DATUM Coinbase Tag"));
    dialog.setModal(true);

    auto* const layout{new QVBoxLayout(&dialog)};
    auto* const notice{new QLabel(
        QObject::tr("DATUM is enabled, but your coinbase tag is still unset or using the default value. "
                    "Choose a custom tag to identify your mined blocks. You can change it later in Settings."),
        &dialog)};
    notice->setWordWrap(true);
    layout->addWidget(notice);

    QLineEdit* tag_edit{nullptr};
    layout->addWidget(CreateInputRow(&dialog, &tag_edit));
    tag_edit->setText(QString::fromStdString(gArgs.GetArg("-datumcoinbasetag", std::string{mining::DEFAULT_DATUM_COINBASE_TAG})));

    auto* const buttons{new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, &dialog)};
    buttons->button(QDialogButtonBox::Save)->setText(QObject::tr("Save"));
    buttons->button(QDialogButtonBox::Cancel)->setText(QObject::tr("Not Now"));
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);

    if (dialog.exec() != QDialog::Accepted) return;

    const std::string tag{tag_edit->text().toUtf8().toStdString()};
    std::string error;
    if (!SaveCoinbaseTag(tag, error)) {
        QMessageBox::critical(parent, QObject::tr("Invalid DATUM Coinbase Tag"),
                              QString::fromStdString(error));
    }
}

} // namespace DatumCoinbaseTagUtil

#endif // ENABLE_DATUM
