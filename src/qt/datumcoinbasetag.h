// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license.
#ifndef BITCOIN_QT_DATUMCOINBASETAG_H
#define BITCOIN_QT_DATUMCOINBASETAG_H

#include <QString>

class QLineEdit;
class QWidget;

namespace DatumCoinbaseTagUtil {

/** Generate a random World of Warcraft-style name (adjective + noun). */
QString GenerateRandomWowTag();

/** Create a line edit with a random-name button for coinbase tag entry. */
QWidget* CreateInputRow(QWidget* parent, QLineEdit** tag_edit_out);

/** Validate and persist a coinbase tag to the config file, applying it live when DATUM is running. */
bool SaveCoinbaseTag(const std::string& tag, std::string& error);

/** Prompt the user to choose a coinbase tag when DATUM is enabled but the tag is unset or default. */
void MaybePromptOnStartup(QWidget* parent);

} // namespace DatumCoinbaseTagUtil

#endif // BITCOIN_QT_DATUMCOINBASETAG_H
