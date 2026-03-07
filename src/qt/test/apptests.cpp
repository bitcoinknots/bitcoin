// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/apptests.h>

#include <chainparams.h>
#include <common/args.h>
#include <key.h>
#include <logging.h>
#include <qt/bitcoin.h>
#include <qt/bitcoingui.h>
#include <qt/networkstyle.h>
#include <qt/optionsmodel.h>
#include <qt/rpcconsole.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <QAction>
#include <QCoreApplication>
#include <QEvent>
#include <QLineEdit>
#include <QPalette>
#include <QRegularExpression>
#include <QScopedPointer>
#include <QSignalSpy>
#include <QString>
#include <QTest>
#include <QTextEdit>
#include <QtGlobal>
#include <QtTest/QtTestWidgets>
#include <QtTest/QtTestGui>
#include <QWidget>

namespace {
//! Regex find a string group inside of the console output
QString FindInConsole(const QString& output, const QString& pattern)
{
    const QRegularExpression re(pattern);
    return re.match(output).captured(1);
}

//! Call getblockchaininfo RPC and check first field of JSON output.
void TestRpcCommand(RPCConsole* console)
{
    QTextEdit* messagesWidget = console->findChild<QTextEdit*>("messagesWidget");
    QLineEdit* lineEdit = console->findChild<QLineEdit*>("lineEdit");
    QSignalSpy mw_spy(messagesWidget, &QTextEdit::textChanged);
    QVERIFY(mw_spy.isValid());
    QTest::keyClicks(lineEdit, "getblockchaininfo");
    QTest::keyClick(lineEdit, Qt::Key_Return);
    QVERIFY(mw_spy.wait(1000));
    QCOMPARE(mw_spy.count(), 4);
    const QString output = messagesWidget->toPlainText();
    const QString pattern = QStringLiteral("\"chain\": \"(\\w+)\"");
    QCOMPARE(FindInConsole(output, pattern), QString("regtest"));
}

void ProcessEvents()
{
    QCoreApplication::sendPostedEvents(nullptr, QEvent::ApplicationPaletteChange);
    QCoreApplication::sendPostedEvents(nullptr, QEvent::PaletteChange);
    QCoreApplication::processEvents();
}

void CheckLightPalette(const QPalette& palette)
{
    QCOMPARE(palette.color(QPalette::Window), QColor(245, 245, 245));
    QCOMPARE(palette.color(QPalette::Base), QColor(255, 255, 255));
    QCOMPARE(palette.color(QPalette::Highlight), QColor(247, 147, 26));
    QCOMPARE(palette.color(QPalette::HighlightedText), QColor(32, 32, 32));
}

void CheckDarkPalette(const QPalette& palette)
{
    QCOMPARE(palette.color(QPalette::Window), QColor(53, 53, 53));
    QCOMPARE(palette.color(QPalette::Base), QColor(35, 35, 35));
    QCOMPARE(palette.color(QPalette::Highlight), QColor(247, 147, 26));
    QCOMPARE(palette.color(QPalette::HighlightedText), QColor(24, 24, 24));
}
} // namespace

//! Entry point for BitcoinApplication tests.
void AppTests::appTests()
{
#ifdef Q_OS_MACOS
    if (QApplication::platformName() == "minimal") {
        // Disable for mac on "minimal" platform to avoid crashes inside the Qt
        // framework when it tries to look up unimplemented cocoa functions,
        // and fails to handle returned nulls
        // (https://bugreports.qt.io/browse/QTBUG-49686).
        qWarning() << "Skipping AppTests on mac build with 'minimal' platform set due to Qt bugs. To run AppTests, invoke "
                      "with 'QT_QPA_PLATFORM=cocoa test_bitcoin-qt' on mac, or else use a linux or windows build.";
        return;
    }
#endif

    {
        // Need to ensure datadir is setup so resetting settings can delete the non-existent bitcoin_rw.conf
        std::string error;
        if (!gArgs.ReadConfigFiles(error, true)) {
            qWarning() << "Error in readConfigFiles";
        }
    }

    qRegisterMetaType<interfaces::BlockAndHeaderTipInfo>("interfaces::BlockAndHeaderTipInfo");
    m_app.parameterSetup();
    QVERIFY(m_app.createOptionsModel(/*resetSettings=*/true));
    QScopedPointer<const NetworkStyle> style(NetworkStyle::instantiate(Params().GetChainType()));
    m_app.setupPlatformStyle();
    m_app.createWindow(style.data());
    connect(&m_app, &BitcoinApplication::windowShown, this, &AppTests::guiTests);
    expectCallback("guiTests");
    m_app.baseInitialize();
    m_app.requestInitialize();
    m_app.exec();
    m_app.requestShutdown();
    m_app.exec();

    // Reset global state to avoid interfering with later tests.
    LogInstance().DisconnectTestLogger();
}

//! Entry point for BitcoinGUI tests.
void AppTests::guiTests(BitcoinGUI* window)
{
    HandleCallback callback{"guiTests", *this};
    themeTests(window);
    connect(window, &BitcoinGUI::consoleShown, this, &AppTests::consoleTests);
    expectCallback("consoleTests");
    QAction* action = window->findChild<QAction*>("openRPCConsoleAction");
    action->activate(QAction::Trigger);
}

//! Entry point for RPCConsole tests.
void AppTests::consoleTests(RPCConsole* console)
{
    HandleCallback callback{"consoleTests", *this};
    TestRpcCommand(console);
}

void AppTests::themeTests(QWidget* widget)
{
    const QPalette initial_palette = m_app.palette();
    const bool system_is_dark = GUIUtil::isDarkMode(initial_palette.color(QPalette::Window));
    if (system_is_dark) {
        CheckDarkPalette(initial_palette);
    } else {
        CheckLightPalette(initial_palette);
    }

    m_app.setThemePreference(OptionsModel::ThemePreferenceToInt(OptionsModel::ThemePreference::Light));
    ProcessEvents();
    CheckLightPalette(m_app.palette());
    QCOMPARE(widget->palette().color(QPalette::Window), QColor(245, 245, 245));

    m_app.setThemePreference(OptionsModel::ThemePreferenceToInt(OptionsModel::ThemePreference::Dark));
    ProcessEvents();
    CheckDarkPalette(m_app.palette());
    QCOMPARE(widget->palette().color(QPalette::Window), QColor(53, 53, 53));

    m_app.setThemePreference(OptionsModel::ThemePreferenceToInt(OptionsModel::ThemePreference::System));
    ProcessEvents();
    if (system_is_dark) {
        CheckDarkPalette(m_app.palette());
        QCOMPARE(widget->palette().color(QPalette::Window), QColor(53, 53, 53));
    } else {
        CheckLightPalette(m_app.palette());
        QCOMPARE(widget->palette().color(QPalette::Window), QColor(245, 245, 245));
    }
}

//! Destructor to shut down after the last expected callback completes.
AppTests::HandleCallback::~HandleCallback()
{
    auto& callbacks = m_app_tests.m_callbacks;
    auto it = callbacks.find(m_callback);
    assert(it != callbacks.end());
    callbacks.erase(it);
    if (callbacks.empty()) {
        m_app_tests.m_app.exit(0);
    }
}
