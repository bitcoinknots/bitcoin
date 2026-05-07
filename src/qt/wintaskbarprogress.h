// Copyright (c) 2025 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_WINTASKBARPROGRESS_H
#define BITCOIN_QT_WINTASKBARPROGRESS_H

#include <QAbstractNativeEventFilter>
#include <QObject>
#include <QPointer>

class QWidget;
class QWindow;
struct ITaskbarList3;

class WinTaskbarProgress : public QObject, public QAbstractNativeEventFilter
{
    Q_OBJECT

public:
    explicit WinTaskbarProgress(QObject *parent = nullptr);
    ~WinTaskbarProgress();

    void setWindow(QWidget* widget);
    void setValue(int value);
    void setVisible(bool visible);

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    bool nativeEventFilter(const QByteArray &eventType, void *pMessage, qintptr *pnResult) override;
#else
    bool nativeEventFilter(const QByteArray &eventType, void *pMessage, long *pnResult) override;
#endif

private:
    QPointer<QWindow> m_window;
    int m_value = 0;
    bool m_visible = false;
    ITaskbarList3* m_taskbar_button = nullptr;
    unsigned int m_taskbar_button_created_msg = 0;
    bool m_taskbar_ready = false;

    void updateProgress();
    void initTaskbarButton();
    void releaseTaskbarButton();
};

#endif // BITCOIN_QT_WINTASKBARPROGRESS_H
