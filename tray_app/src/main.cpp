#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>

#include <cstdlib>
#include <cwchar>
#include <iterator>
#include <string>

#include "resource.h"

namespace {

constexpr wchar_t kWindowClassName[] = L"TrayAppWindowClass";
constexpr wchar_t kWindowTitle[] = L"Tray Keeper";
constexpr UINT kTrayCallbackMessage = WM_APP + 1;
constexpr UINT kTrayIconId = 1;

HWND g_mainWindow = nullptr;
HMENU g_mainMenu = nullptr;
UINT g_taskbarCreatedMessage = 0;
NOTIFYICONDATAW g_trayIconData{};
bool g_trayIconAdded = false;
bool g_isQuitting = false;

std::wstring GetLastErrorText(DWORD errorCode) {
    if (errorCode == 0) {
        return L"Unknown error";
    }

    wchar_t* buffer = nullptr;
    const DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    std::wstring message = size && buffer ? buffer : L"Unknown error";
    if (buffer) {
        LocalFree(buffer);
    }
    return message;
}

std::wstring BuildUserMutexName() {
    wchar_t userName[256]{};
    DWORD userNameLength = static_cast<DWORD>(std::size(userName));

    if (!GetUserNameW(userName, &userNameLength)) {
        StringCchCopyW(userName, std::size(userName), L"UnknownUser");
    }

    std::wstring name = L"Local\\TrayKeeper.SingleInstance.";
    name += userName;
    return name;
}

bool HasHiddenModeFlag() {
    const int argc = __argc;
    wchar_t** argv = __wargv;

    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--hidden") == 0 ||
            _wcsicmp(argv[i], L"/hidden") == 0 ||
            _wcsicmp(argv[i], L"--background") == 0 ||
            _wcsicmp(argv[i], L"/background") == 0) {
            return true;
        }
    }

    return false;
}

void ShowMainWindow(HWND hwnd) {
    ShowWindow(hwnd, SW_SHOWNORMAL);
    SetForegroundWindow(hwnd);
}

void RemoveTrayIcon() {
    if (g_trayIconAdded) {
        Shell_NotifyIconW(NIM_DELETE, &g_trayIconData);
        g_trayIconAdded = false;
    }
}

bool AddTrayIcon(HWND hwnd) {
    ZeroMemory(&g_trayIconData, sizeof(g_trayIconData));
    g_trayIconData.cbSize = sizeof(g_trayIconData);
    g_trayIconData.hWnd = hwnd;
    g_trayIconData.uID = kTrayIconId;
    g_trayIconData.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_trayIconData.uCallbackMessage = kTrayCallbackMessage;
    g_trayIconData.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_TRAY_APP));
    StringCchCopyW(g_trayIconData.szTip, std::size(g_trayIconData.szTip), L"Tray Keeper");

    const BOOL added = Shell_NotifyIconW(NIM_ADD, &g_trayIconData);
    if (added) {
        g_trayIconAdded = true;
        g_trayIconData.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &g_trayIconData);
        return true;
    }

    return false;
}

void RecreateTrayIcon(HWND hwnd) {
    RemoveTrayIcon();
    AddTrayIcon(hwnd);
}

void QuitApplication(HWND hwnd) {
    g_isQuitting = true;
    RemoveTrayIcon();
    DestroyWindow(hwnd);
}

void ShowTrayContextMenu(HWND hwnd) {
    HMENU menu = CreatePopupMenu();
    if (!menu) {
        return;
    }

    AppendMenuW(menu, MF_STRING, IDM_TRAY_OPEN, L"Открыть");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"Выход");

    POINT cursorPosition{};
    GetCursorPos(&cursorPosition);

    SetForegroundWindow(hwnd);
    TrackPopupMenu(
        menu,
        TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
        cursorPosition.x,
        cursorPosition.y,
        0,
        hwnd,
        nullptr);

    DestroyMenu(menu);
}

HMENU CreateMainWindowMenu() {
    HMENU mainMenu = CreateMenu();
    HMENU fileMenu = CreatePopupMenu();

    AppendMenuW(fileMenu, MF_STRING, IDM_FILE_EXIT, L"Выход");
    AppendMenuW(mainMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"Файл");

    return mainMenu;
}

void DrawCenteredText(HDC hdc, const wchar_t* text, RECT rect, int fontSize, int weight, COLORREF color) {
    HFONT font = CreateFontW(
        fontSize,
        0,
        0,
        0,
        weight,
        FALSE,
        FALSE,
        FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        VARIABLE_PITCH,
        L"Georgia");

    HFONT oldFont = static_cast<HFONT>(SelectObject(hdc, font));
    SetTextColor(hdc, color);
    SetBkMode(hdc, TRANSPARENT);
    DrawTextW(hdc, text, -1, &rect, DT_CENTER | DT_WORDBREAK);
    SelectObject(hdc, oldFont);
    DeleteObject(font);
}

void PaintMainWindow(HWND hwnd) {
    PAINTSTRUCT ps{};
    HDC hdc = BeginPaint(hwnd, &ps);

    RECT clientRect{};
    GetClientRect(hwnd, &clientRect);

    HBRUSH backgroundBrush = CreateSolidBrush(RGB(18, 16, 24));
    FillRect(hdc, &clientRect, backgroundBrush);
    DeleteObject(backgroundBrush);

    HBRUSH panelBrush = CreateSolidBrush(RGB(31, 24, 39));
    HPEN borderPen = CreatePen(PS_SOLID, 2, RGB(120, 37, 70));
    HGDIOBJ oldBrush = SelectObject(hdc, panelBrush);
    HGDIOBJ oldPen = SelectObject(hdc, borderPen);

    RECT panelRect = clientRect;
    InflateRect(&panelRect, -34, -34);
    RoundRect(hdc, panelRect.left, panelRect.top, panelRect.right, panelRect.bottom, 28, 28);

    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(panelBrush);
    DeleteObject(borderPen);

    RECT titleRect = panelRect;
    titleRect.top += 32;
    titleRect.bottom = titleRect.top + 56;
    DrawCenteredText(hdc, L"Tray Keeper", titleRect, 34, FW_BOLD, RGB(232, 212, 236));

    RECT subtitleRect = panelRect;
    subtitleRect.top += 98;
    subtitleRect.left += 36;
    subtitleRect.right -= 36;
    subtitleRect.bottom = subtitleRect.top + 120;

    const wchar_t subtitle[] =
        L"Тёмное Win32-приложение живёт в трее, открывается по левому клику, "
        L"показывает меню по правому клику и не закрывается полностью при нажатии на крестик.";
    DrawCenteredText(hdc, subtitle, subtitleRect, 21, FW_NORMAL, RGB(195, 182, 205));

    RECT footerRect = panelRect;
    footerRect.left += 36;
    footerRect.right -= 36;
    footerRect.bottom -= 34;
    footerRect.top = footerRect.bottom - 64;

    const wchar_t footer[] =
        L"Файл -> Выход завершает приложение.\n"
        L"Запуск без окна: TrayKeeper.exe --hidden";
    DrawCenteredText(hdc, footer, footerRect, 18, FW_NORMAL, RGB(164, 111, 137));

    EndPaint(hwnd, &ps);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == g_taskbarCreatedMessage) {
        RecreateTrayIcon(hwnd);
        return 0;
    }

    switch (message) {
    case WM_CREATE:
        g_mainMenu = CreateMainWindowMenu();
        SetMenu(hwnd, g_mainMenu);
        if (!AddTrayIcon(hwnd)) {
            MessageBoxW(hwnd, L"Не удалось добавить иконку в трей.", kWindowTitle, MB_ICONERROR);
        }
        return 0;

    case kTrayCallbackMessage:
        if (LOWORD(lParam) == WM_LBUTTONUP) {
            ShowMainWindow(hwnd);
        } else if (LOWORD(lParam) == WM_RBUTTONUP || LOWORD(lParam) == WM_CONTEXTMENU) {
            ShowTrayContextMenu(hwnd);
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDM_FILE_EXIT:
        case IDM_TRAY_EXIT:
            QuitApplication(hwnd);
            return 0;
        case IDM_TRAY_OPEN:
            ShowMainWindow(hwnd);
            return 0;
        default:
            return DefWindowProcW(hwnd, message, wParam, lParam);
        }

    case WM_CLOSE:
        if (g_isQuitting) {
            DestroyWindow(hwnd);
        } else {
            ShowWindow(hwnd, SW_HIDE);
        }
        return 0;

    case WM_PAINT:
        PaintMainWindow(hwnd);
        return 0;

    case WM_DESTROY:
        RemoveTrayIcon();
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
}

bool RegisterMainWindowClass(HINSTANCE instance) {
    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_HREDRAW | CS_VREDRAW;
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = instance;
    windowClass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_TRAY_APP));
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = CreateSolidBrush(RGB(18, 16, 24));
    windowClass.lpszClassName = kWindowClassName;
    windowClass.hIconSm = LoadIconW(instance, MAKEINTRESOURCEW(IDI_TRAY_APP));

    return RegisterClassExW(&windowClass) != 0;
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int commandShow) {
    const std::wstring mutexName = BuildUserMutexName();
    HANDLE singleInstanceMutex = CreateMutexW(nullptr, TRUE, mutexName.c_str());

    if (!singleInstanceMutex) {
        const std::wstring error = L"Не удалось создать mutex: " + GetLastErrorText(GetLastError());
        MessageBoxW(nullptr, error.c_str(), kWindowTitle, MB_ICONERROR);
        return 1;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(singleInstanceMutex);
        return 0;
    }

    g_taskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");

    if (!RegisterMainWindowClass(instance)) {
        MessageBoxW(nullptr, L"Не удалось зарегистрировать класс окна.", kWindowTitle, MB_ICONERROR);
        CloseHandle(singleInstanceMutex);
        return 1;
    }

    g_mainWindow = CreateWindowExW(
        0,
        kWindowClassName,
        kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        720,
        420,
        nullptr,
        nullptr,
        instance,
        nullptr);

    if (!g_mainWindow) {
        MessageBoxW(nullptr, L"Не удалось создать главное окно.", kWindowTitle, MB_ICONERROR);
        CloseHandle(singleInstanceMutex);
        return 1;
    }

    if (!HasHiddenModeFlag()) {
        ShowWindow(g_mainWindow, commandShow);
        UpdateWindow(g_mainWindow);
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    ReleaseMutex(singleInstanceMutex);
    CloseHandle(singleInstanceMutex);
    return static_cast<int>(message.wParam);
}
