// Copyright (c) 2025 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/wintaskbarprogress.h>

#include <QWidget>
#include <QWindow>

#include <windows.h>
#include <shobjidl.h>

WinTaskbarProgress::WinTaskbarProgress(QObject *parent)
    : QObject(parent),
      m_taskbar_button_created_msg(RegisterWindowMessageW(L"TaskbarButtonCreated"))
{
}

WinTaskbarProgress::~WinTaskbarProgress()
{
    releaseTaskbarButton();
}

void WinTaskbarProgress::setWindow(QWidget* widget)
{
    QWindow* window = widget ? widget->windowHandle() : nullptr;
    if (!window) {
        return;
    }
    if (m_window == window) {
        return;
    }

    m_window = window;
    initTaskbarButton();
    updateProgress();
}

void WinTaskbarProgress::setValue(int value)
{
    if (m_value == value) {
        return;
    }

    m_value = value;
    updateProgress();
}

void WinTaskbarProgress::setVisible(bool visible)
{
    if (m_visible == visible) {
        return;
    }

    m_visible = visible;
    updateProgress();
}

void WinTaskbarProgress::updateProgress()
{
    if (!m_taskbar_button || !m_window) {
        return;
    }

    HWND hwnd = reinterpret_cast<HWND>(m_window->winId());
    if (m_visible) {
        m_taskbar_button->SetProgressValue(hwnd, m_value, 100);
        m_taskbar_button->SetProgressState(hwnd, TBPF_NORMAL);
    } else {
        m_taskbar_button->SetProgressState(hwnd, TBPF_NOPROGRESS);
    }
}

void WinTaskbarProgress::initTaskbarButton()
{
    if (m_taskbar_button || !m_window || !m_taskbar_ready) {
        return;
    }

    HRESULT hr = CoCreateInstance(CLSID_TaskbarList, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&m_taskbar_button));

    if (SUCCEEDED(hr)) {
        hr = m_taskbar_button->HrInit();
        if (FAILED(hr)) {
            m_taskbar_button->Release();
            m_taskbar_button = nullptr;
        }
    }
}

void WinTaskbarProgress::releaseTaskbarButton()
{
    if (m_taskbar_button) {
        m_taskbar_button->Release();
        m_taskbar_button = nullptr;
    }
}

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
bool WinTaskbarProgress::nativeEventFilter(const QByteArray &eventType, void *pMessage, qintptr *pnResult)
#else
bool WinTaskbarProgress::nativeEventFilter(const QByteArray &eventType, void *pMessage, long *pnResult)
#endif
{
    Q_UNUSED(pnResult);

    if (eventType != "windows_generic_MSG" && eventType != "windows_dispatcher_MSG") {
        return false;
    }

    MSG *msg = static_cast<MSG *>(pMessage);

    if (m_taskbar_button_created_msg != 0 && msg->message == m_taskbar_button_created_msg) {
        m_taskbar_ready = true;
        if (m_window) {
            initTaskbarButton();
            updateProgress();
        }
    }

    return false;
}
