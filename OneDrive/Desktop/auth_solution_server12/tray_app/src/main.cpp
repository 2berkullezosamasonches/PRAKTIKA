#include <windows.h>
#include <rpc.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commdlg.h>
#include <strsafe.h>
#include <tlhelp32.h>

#include <cstdlib>
#include <cwchar>
#include <iterator>
#include <string>
#include <vector>

#include "resource.h"
#include "TrayKeeperControl.h"

namespace {

constexpr wchar_t kWindowClassName[] = L"TrayAppWindowClass";
constexpr wchar_t kWindowTitle[] = L"Tray Keeper";
constexpr wchar_t kServiceName[] = L"TrayKeeperService";
constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"TrayKeeperControlAlpc";
constexpr UINT kTrayCallbackMessage = WM_APP + 1;
constexpr UINT kTrayIconId = 1;
constexpr UINT_PTR kLicensePollTimer = 42;
constexpr UINT_PTR kScheduleStatusPollTimer = 43;
constexpr UINT kScheduleStatusPollMs = 5000;

constexpr long TK_OK = 0;
constexpr long TK_ERROR_AUTH = 1002;
constexpr long TK_ERROR_NO_LICENSE = 1003;

constexpr int IDC_LOGIN_USER = 1001;
constexpr int IDC_LOGIN_PASSWORD = 1002;
constexpr int IDC_LOGIN_BUTTON = 1003;
constexpr int IDC_LOGOUT_BUTTON = 1004;
constexpr int IDC_ACTIVATION_CODE = 1005;
constexpr int IDC_ACTIVATE_BUTTON = 1006;
constexpr int IDC_AV_STATUS_BUTTON = 1007;
constexpr int IDC_SCAN_FILE_BUTTON = 1008;
constexpr int IDC_SCAN_DIR_BUTTON = 1009;
constexpr int IDC_SCAN_DRIVES_BUTTON = 1010;
constexpr int IDC_MONITOR_DIR_BUTTON = 1011;
constexpr int IDC_MONITOR_STOP_BUTTON = 1012;
constexpr int IDC_MONITOR_STATUS_BUTTON = 1013;
constexpr int IDC_SCHEDULE_INTERVAL_EDIT = 1014;
constexpr int IDC_SCHEDULE_DIR_BUTTON = 1015;
constexpr int IDC_SCHEDULE_STOP_BUTTON = 1016;
constexpr int IDC_SCHEDULE_STATUS_BUTTON = 1017;

HWND g_mainWindow = nullptr;
HWND g_loginEdit = nullptr;
HWND g_passwordEdit = nullptr;
HWND g_loginButton = nullptr;
HWND g_logoutButton = nullptr;
HWND g_activationEdit = nullptr;
HWND g_activateButton = nullptr;
HWND g_antivirusButton = nullptr;
HWND g_scanFileButton = nullptr;
HWND g_scanDirButton = nullptr;
HWND g_scanDrivesButton = nullptr;
HWND g_monitorDirButton = nullptr;
HWND g_monitorStopButton = nullptr;
HWND g_monitorStatusButton = nullptr;
HWND g_scheduleIntervalEdit = nullptr;
HWND g_scheduleDirButton = nullptr;
HWND g_scheduleStopButton = nullptr;
HWND g_scheduleStatusButton = nullptr;
HMENU g_mainMenu = nullptr;
UINT g_taskbarCreatedMessage = 0;
NOTIFYICONDATAW g_trayIconData{};
bool g_trayIconAdded = false;
bool g_isQuitting = false;
bool g_isAuthenticated = false;
bool g_hasLicense = false;
std::wstring g_username;
std::wstring g_licenseExpires;
std::wstring g_statusText = L"Подключение к службе...";
std::wstring g_avDbRelease = L"-";
long g_avDbRecords = 0;
std::wstring g_lastScanSummary;
bool g_scheduleAutoStatusEnabled = false;

bool EqualsIgnoreCase(const std::wstring& left, const std::wstring& right) {
    return _wcsicmp(left.c_str(), right.c_str()) == 0;
}

std::wstring GetLastErrorText(DWORD errorCode) {
    if (errorCode == 0) return L"Unknown error";
    wchar_t* buffer = nullptr;
    const DWORD size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring message = size && buffer ? buffer : L"Unknown error";
    if (buffer) LocalFree(buffer);
    return message;
}

std::wstring BuildUserMutexName() {
    wchar_t userName[256]{};
    DWORD userNameLength = static_cast<DWORD>(std::size(userName));
    if (!GetUserNameW(userName, &userNameLength)) StringCchCopyW(userName, std::size(userName), L"UnknownUser");
    return std::wstring(L"Local\\TrayKeeper.SingleInstance.") + userName;
}

bool HasHiddenModeFlag() {
    for (int i = 1; i < __argc; ++i) {
        if (_wcsicmp(__wargv[i], L"--hidden") == 0 || _wcsicmp(__wargv[i], L"/hidden") == 0 || _wcsicmp(__wargv[i], L"--background") == 0 || _wcsicmp(__wargv[i], L"/background") == 0) return true;
    }
    return false;
}

bool QueryServiceState(SC_HANDLE service, DWORD& state) {
    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) return false;
    state = status.dwCurrentState;
    return true;
}

bool WaitForServiceState(SC_HANDLE service, DWORD expectedState, DWORD timeoutMs) {
    const DWORD startedAt = GetTickCount();
    while (GetTickCount() - startedAt < timeoutMs) {
        DWORD state = 0;
        if (!QueryServiceState(service, state)) return false;
        if (state == expectedState) return true;
        Sleep(300);
    }
    return false;
}

bool StartServiceIfStoppedAndExit() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return true;
    SC_HANDLE service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS);
    if (!service) { CloseServiceHandle(manager); return true; }

    DWORD state = 0;
    if (!QueryServiceState(service, state)) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return true;
    }

    bool shouldExit = false;
    if (state == SERVICE_STOPPED) {
        CloseServiceHandle(service);
        service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
        if (service && (StartServiceW(service, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)) WaitForServiceState(service, SERVICE_RUNNING, 30000);
        shouldExit = true;
    }

    if (service) CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return shouldExit;
}

DWORD GetParentProcessId(DWORD processId) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    DWORD parentProcessId = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == processId) { parentProcessId = entry.th32ParentProcessID; break; }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return parentProcessId;
}

bool IsParentServiceProcess() {
    const DWORD parentProcessId = GetParentProcessId(GetCurrentProcessId());
    if (parentProcessId == 0) return false;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return false;
    SC_HANDLE service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS);
    if (!service) { CloseServiceHandle(manager); return false; }
    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    const BOOL queried = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded);
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return queried && status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != 0 && parentProcessId == status.dwProcessId;
}

bool BindRpc() {
    if (TrayKeeperControlBinding) return true;
    RPC_WSTR stringBinding = nullptr;
    RPC_STATUS status = RpcStringBindingComposeW(nullptr, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)), nullptr, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)), nullptr, &stringBinding);
    if (status != RPC_S_OK) return false;
    status = RpcBindingFromStringBindingW(stringBinding, &TrayKeeperControlBinding);
    RpcStringFreeW(&stringBinding);
    return status == RPC_S_OK;
}

void FreeRpcString(wchar_t*& value) {
    if (value) {
        midl_user_free(value);
        value = nullptr;
    }
}

void ResetUiState() {
    g_isAuthenticated = false;
    g_hasLicense = false;
    g_username.clear();
    g_licenseExpires.clear();
    g_avDbRelease = L"-";
    g_avDbRecords = 0;
    g_scheduleAutoStatusEnabled = false;
}

bool RpcRefreshUser() {
    if (!BindRpc()) {
        g_statusText = L"Служба недоступна. Проверьте, что TrayKeeperService запущена.";
        ResetUiState();
        return false;
    }

    TK_AUTH_INFO info{};
    long status = TK_ERROR_AUTH;
    status = TrayKeeperGetCurrentUser(&info);

    if (status == TK_OK && info.authenticated) {
        g_isAuthenticated = true;
        g_username = info.username ? info.username : L"";
        g_statusText = L"Пользователь аутентифицирован";
    } else {
        ResetUiState();
        g_statusText = L"Войдите в учётную запись, чтобы включить защиту.";
    }
    FreeRpcString(info.username);
    return g_isAuthenticated;
}

bool RpcRefreshLicense() {
    if (!g_isAuthenticated || !BindRpc()) return false;

    TK_LICENSE_INFO info{};
    long status = TK_ERROR_NO_LICENSE;
    status = TrayKeeperGetLicenseInfo(&info);

    g_hasLicense = status == TK_OK && info.active != 0;
    g_licenseExpires = info.expiresAt ? info.expiresAt : L"";
    if (g_hasLicense) {
        g_statusText = L"Лицензия активна. Функции антивируса разблокированы.";
    } else {
        g_statusText = info.message && *info.message ? info.message : L"Введите код активации, чтобы разблокировать защиту.";
    }
    FreeRpcString(info.expiresAt);
    FreeRpcString(info.message);
    return g_hasLicense;
}


bool RpcRefreshAvDatabase() {
    if (!g_hasLicense || !BindRpc()) return false;
    TK_AV_DATABASE_INFO info{};
    const long status = TrayKeeperGetAvDatabaseInfo(&info);
    if (status == TK_OK && info.loaded) {
        g_avDbRelease = info.releaseDate ? info.releaseDate : L"-";
        g_avDbRecords = info.recordCount;
    } else {
        g_avDbRelease = L"-";
        g_avDbRecords = 0;
    }
    FreeRpcString(info.releaseDate);
    FreeRpcString(info.message);
    return status == TK_OK;
}

void RefreshStateAndUi(HWND hwnd) {
    if (RpcRefreshUser()) {
        if (RpcRefreshLicense()) RpcRefreshAvDatabase();
    }
    InvalidateRect(hwnd, nullptr, TRUE);
}

void ShowMainWindow(HWND hwnd) {
    ShowWindow(hwnd, SW_SHOWNORMAL);
    SetForegroundWindow(hwnd);
    RefreshStateAndUi(hwnd);
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

void StopServiceFromUi(HWND hwnd) {
    UNREFERENCED_PARAMETER(hwnd);
    if (!BindRpc()) return;
    TrayKeeperStopService();
}

void ShowTrayContextMenu(HWND hwnd) {
    HMENU menu = CreatePopupMenu();
    if (!menu) return;
    AppendMenuW(menu, MF_STRING, IDM_TRAY_OPEN, L"Открыть");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"Выход");
    POINT cursorPosition{};
    GetCursorPos(&cursorPosition);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN, cursorPosition.x, cursorPosition.y, 0, hwnd, nullptr);
    DestroyMenu(menu);
}

HMENU CreateMainWindowMenu() {
    HMENU mainMenu = CreateMenu();
    HMENU fileMenu = CreatePopupMenu();
    AppendMenuW(fileMenu, MF_STRING, IDM_FILE_EXIT, L"Выход");
    AppendMenuW(mainMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"Файл");
    return mainMenu;
}

void SetControlFont(HWND control, int points, int weight = FW_NORMAL) {
    HFONT font = CreateFontW(-MulDiv(points, GetDeviceCaps(GetDC(control), LOGPIXELSY), 72), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

HWND CreateChild(HWND parent, const wchar_t* cls, const wchar_t* text, DWORD style, DWORD exStyle, int id) {
    HWND hwnd = CreateWindowExW(exStyle, cls, text, WS_CHILD | WS_TABSTOP | style, 0, 0, 0, 0, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    if (hwnd) SetControlFont(hwnd, 10);
    return hwnd;
}

void CreateControls(HWND hwnd) {
    g_loginEdit = CreateChild(hwnd, L"EDIT", L"", ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, IDC_LOGIN_USER);
    g_passwordEdit = CreateChild(hwnd, L"EDIT", L"", ES_AUTOHSCROLL | ES_PASSWORD, WS_EX_CLIENTEDGE, IDC_LOGIN_PASSWORD);
    g_loginButton = CreateChild(hwnd, L"BUTTON", L"Войти", BS_PUSHBUTTON, 0, IDC_LOGIN_BUTTON);
    g_logoutButton = CreateChild(hwnd, L"BUTTON", L"Выйти из аккаунта", BS_PUSHBUTTON, 0, IDC_LOGOUT_BUTTON);
    g_activationEdit = CreateChild(hwnd, L"EDIT", L"", ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, IDC_ACTIVATION_CODE);
    g_activateButton = CreateChild(hwnd, L"BUTTON", L"Активировать продукт", BS_PUSHBUTTON, 0, IDC_ACTIVATE_BUTTON);
    g_antivirusButton = CreateChild(hwnd, L"BUTTON", L"Антивирус включён", BS_PUSHBUTTON, 0, IDC_AV_STATUS_BUTTON);
    g_scanFileButton = CreateChild(hwnd, L"BUTTON", L"Сканировать файл", BS_PUSHBUTTON, 0, IDC_SCAN_FILE_BUTTON);
    g_scanDirButton = CreateChild(hwnd, L"BUTTON", L"Сканировать папку", BS_PUSHBUTTON, 0, IDC_SCAN_DIR_BUTTON);
    g_scanDrivesButton = CreateChild(hwnd, L"BUTTON", L"Сканировать диски", BS_PUSHBUTTON, 0, IDC_SCAN_DRIVES_BUTTON);
    g_monitorDirButton = CreateChild(hwnd, L"BUTTON", L"Мониторинг папки", BS_PUSHBUTTON, 0, IDC_MONITOR_DIR_BUTTON);
    g_monitorStopButton = CreateChild(hwnd, L"BUTTON", L"Стоп мониторинг", BS_PUSHBUTTON, 0, IDC_MONITOR_STOP_BUTTON);
    g_monitorStatusButton = CreateChild(hwnd, L"BUTTON", L"Статус мониторинга", BS_PUSHBUTTON, 0, IDC_MONITOR_STATUS_BUTTON);
    g_scheduleIntervalEdit = CreateChild(hwnd, L"EDIT", L"30", ES_AUTOHSCROLL | ES_NUMBER, WS_EX_CLIENTEDGE, IDC_SCHEDULE_INTERVAL_EDIT);
    g_scheduleDirButton = CreateChild(hwnd, L"BUTTON", L"Расписание папки", BS_PUSHBUTTON, 0, IDC_SCHEDULE_DIR_BUTTON);
    g_scheduleStopButton = CreateChild(hwnd, L"BUTTON", L"Стоп расписание", BS_PUSHBUTTON, 0, IDC_SCHEDULE_STOP_BUTTON);
    g_scheduleStatusButton = CreateChild(hwnd, L"BUTTON", L"Статус расписания", BS_PUSHBUTTON, 0, IDC_SCHEDULE_STATUS_BUTTON);
}

void LayoutControls(HWND hwnd) {
    RECT rc{};
    GetClientRect(hwnd, &rc);
    const int w = rc.right - rc.left;
    const int panelLeft = 64;
    const int top = 190;
    const int controlW = max(260, w - 128);

    MoveWindow(g_loginEdit, panelLeft, top, controlW, 30, TRUE);
    MoveWindow(g_passwordEdit, panelLeft, top + 42, controlW, 30, TRUE);
    MoveWindow(g_loginButton, panelLeft, top + 86, 160, 34, TRUE);

    // Authenticated screen: keep logout away from the antivirus controls.
    MoveWindow(g_logoutButton, panelLeft + 560, top + 158, 190, 34, TRUE);

    MoveWindow(g_activationEdit, panelLeft, top + 48, controlW, 30, TRUE);
    MoveWindow(g_activateButton, panelLeft, top + 92, 220, 34, TRUE);

    // Antivirus actions are placed in separate rows below the database info.
    MoveWindow(g_antivirusButton, panelLeft, top + 150, 180, 34, TRUE);
    MoveWindow(g_scanFileButton, panelLeft + 190, top + 150, 170, 34, TRUE);
    MoveWindow(g_scanDirButton, panelLeft + 370, top + 150, 170, 34, TRUE);
    MoveWindow(g_scanDrivesButton, panelLeft, top + 194, 180, 34, TRUE);
    MoveWindow(g_monitorDirButton, panelLeft + 190, top + 194, 190, 34, TRUE);
    MoveWindow(g_monitorStopButton, panelLeft + 390, top + 194, 160, 34, TRUE);
    MoveWindow(g_monitorStatusButton, panelLeft, top + 238, 220, 34, TRUE);

    MoveWindow(g_scheduleIntervalEdit, panelLeft, top + 282, 90, 30, TRUE);
    MoveWindow(g_scheduleDirButton, panelLeft + 100, top + 282, 190, 34, TRUE);
    MoveWindow(g_scheduleStopButton, panelLeft + 300, top + 282, 170, 34, TRUE);
    MoveWindow(g_scheduleStatusButton, panelLeft + 480, top + 282, 190, 34, TRUE);
}

void UpdateControlVisibility() {
    ShowWindow(g_loginEdit, !g_isAuthenticated ? SW_SHOW : SW_HIDE);
    ShowWindow(g_passwordEdit, !g_isAuthenticated ? SW_SHOW : SW_HIDE);
    ShowWindow(g_loginButton, !g_isAuthenticated ? SW_SHOW : SW_HIDE);

    ShowWindow(g_logoutButton, g_isAuthenticated ? SW_SHOW : SW_HIDE);
    ShowWindow(g_activationEdit, g_isAuthenticated && !g_hasLicense ? SW_SHOW : SW_HIDE);
    ShowWindow(g_activateButton, g_isAuthenticated && !g_hasLicense ? SW_SHOW : SW_HIDE);
    ShowWindow(g_antivirusButton, g_isAuthenticated && g_hasLicense ? SW_SHOW : SW_HIDE);
    ShowWindow(g_scanFileButton, g_isAuthenticated && g_hasLicense ? SW_SHOW : SW_HIDE);
    ShowWindow(g_scanDirButton, g_isAuthenticated && g_hasLicense ? SW_SHOW : SW_HIDE);
    ShowWindow(g_scanDrivesButton, g_isAuthenticated && g_hasLicense ? SW_SHOW : SW_HIDE);
    ShowWindow(g_monitorDirButton, g_isAuthenticated && g_hasLicense ? SW_SHOW : SW_HIDE);
    ShowWindow(g_monitorStopButton, g_isAuthenticated && g_hasLicense ? SW_SHOW : SW_HIDE);
    ShowWindow(g_monitorStatusButton, g_isAuthenticated && g_hasLicense ? SW_SHOW : SW_HIDE);
    ShowWindow(g_scheduleIntervalEdit, g_isAuthenticated && g_hasLicense ? SW_SHOW : SW_HIDE);
    ShowWindow(g_scheduleDirButton, g_isAuthenticated && g_hasLicense ? SW_SHOW : SW_HIDE);
    ShowWindow(g_scheduleStopButton, g_isAuthenticated && g_hasLicense ? SW_SHOW : SW_HIDE);
    ShowWindow(g_scheduleStatusButton, g_isAuthenticated && g_hasLicense ? SW_SHOW : SW_HIDE);
    EnableWindow(g_antivirusButton, g_hasLicense ? TRUE : FALSE);
    EnableWindow(g_scanFileButton, g_hasLicense ? TRUE : FALSE);
    EnableWindow(g_scanDirButton, g_hasLicense ? TRUE : FALSE);
    EnableWindow(g_scanDrivesButton, g_hasLicense ? TRUE : FALSE);
    EnableWindow(g_monitorDirButton, g_hasLicense ? TRUE : FALSE);
    EnableWindow(g_monitorStopButton, g_hasLicense ? TRUE : FALSE);
    EnableWindow(g_monitorStatusButton, g_hasLicense ? TRUE : FALSE);
}

void DrawTextLine(HDC hdc, const std::wstring& text, RECT rect, int points, int weight, COLORREF color, UINT format) {
    HFONT font = CreateFontW(-MulDiv(points, GetDeviceCaps(hdc, LOGPIXELSY), 72), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");
    HFONT oldFont = static_cast<HFONT>(SelectObject(hdc, font));
    SetTextColor(hdc, color);
    SetBkMode(hdc, TRANSPARENT);
    DrawTextW(hdc, text.c_str(), -1, &rect, format);
    SelectObject(hdc, oldFont);
    DeleteObject(font);
}

void PaintMainWindow(HWND hwnd) {
    UpdateControlVisibility();
    PAINTSTRUCT ps{};
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT clientRect{};
    GetClientRect(hwnd, &clientRect);

    HBRUSH backgroundBrush = CreateSolidBrush(RGB(15, 17, 26));
    FillRect(hdc, &clientRect, backgroundBrush);
    DeleteObject(backgroundBrush);

    RECT panelRect = clientRect;
    InflateRect(&panelRect, -38, -34);
    HBRUSH panelBrush = CreateSolidBrush(RGB(27, 31, 46));
    HPEN borderPen = CreatePen(PS_SOLID, 2, g_hasLicense ? RGB(51, 179, 124) : RGB(210, 92, 92));
    HGDIOBJ oldBrush = SelectObject(hdc, panelBrush);
    HGDIOBJ oldPen = SelectObject(hdc, borderPen);
    RoundRect(hdc, panelRect.left, panelRect.top, panelRect.right, panelRect.bottom, 28, 28);
    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(panelBrush);
    DeleteObject(borderPen);

    RECT titleRect = panelRect;
    titleRect.left += 26;
    titleRect.right -= 26;
    titleRect.top += 26;
    titleRect.bottom = titleRect.top + 40;
    DrawTextLine(hdc, L"Tray Keeper Antivirus", titleRect, 24, FW_BOLD, RGB(238, 242, 255), DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    RECT statusRect = titleRect;
    statusRect.top += 48;
    statusRect.bottom = statusRect.top + 56;
    DrawTextLine(hdc, g_statusText, statusRect, 12, FW_NORMAL, RGB(191, 201, 222), DT_LEFT | DT_WORDBREAK);

    RECT infoRect = statusRect;
    infoRect.top += 62;
    infoRect.bottom = infoRect.top + 34;
    std::wstring info;
    if (!g_isAuthenticated) info = L"Статус: пользователь не аутентифицирован. Защита заблокирована.";
    else if (!g_hasLicense) info = L"Пользователь: " + g_username + L". Лицензия не найдена. Защита заблокирована.";
    else info = L"Пользователь: " + g_username + L". Лицензия до: " + g_licenseExpires;
    DrawTextLine(hdc, info, infoRect, 13, FW_SEMIBOLD, g_hasLicense ? RGB(123, 225, 178) : RGB(255, 184, 115), DT_LEFT | DT_WORDBREAK);

    RECT labelRect = infoRect;
    labelRect.top += 46;
    labelRect.bottom = labelRect.top + 28;
    if (!g_isAuthenticated) DrawTextLine(hdc, L"Логин и пароль", labelRect, 11, FW_NORMAL, RGB(163, 174, 199), DT_LEFT | DT_SINGLELINE);
    else if (!g_hasLicense) DrawTextLine(hdc, L"Код активации", labelRect, 11, FW_NORMAL, RGB(163, 174, 199), DT_LEFT | DT_SINGLELINE);
    else {
        DrawTextLine(hdc, L"Базы от: " + g_avDbRelease + L". Записей: " + std::to_wstring(g_avDbRecords), labelRect, 11, FW_NORMAL, RGB(163, 174, 199), DT_LEFT | DT_SINGLELINE);
        RECT scanRect = labelRect;
        // Keep the last scan/monitoring text safely below all action buttons.
        scanRect.top += 320;
        scanRect.bottom = scanRect.top + 95;
        DrawTextLine(hdc, g_lastScanSummary.empty() ? L"Выберите файл, папку, диски, мониторинг или расписание. Статус расписания обновляется автоматически каждые 5 секунд." : g_lastScanSummary, scanRect, 10, FW_NORMAL, RGB(191, 201, 222), DT_LEFT | DT_WORDBREAK);
    }

    EndPaint(hwnd, &ps);
}

std::wstring ReadControlText(HWND control) {
    const int length = GetWindowTextLengthW(control);
    std::vector<wchar_t> buffer(static_cast<size_t>(length) + 1);
    GetWindowTextW(control, buffer.data(), static_cast<int>(buffer.size()));
    return std::wstring(buffer.data());
}

void DoLogin(HWND hwnd) {
    if (!BindRpc()) {
        MessageBoxW(hwnd, L"Не удалось подключиться к службе RPC.", kWindowTitle, MB_ICONERROR);
        return;
    }
    const std::wstring username = ReadControlText(g_loginEdit);
    const std::wstring password = ReadControlText(g_passwordEdit);
    TK_AUTH_INFO info{};
    long status = TK_ERROR_AUTH;
    status = TrayKeeperLogin(const_cast<wchar_t*>(username.c_str()), const_cast<wchar_t*>(password.c_str()), &info);

    if (status != TK_OK || !info.authenticated) {
        g_statusText = L"Ошибка входа: проверьте логин и пароль.";
        MessageBoxW(hwnd, g_statusText.c_str(), kWindowTitle, MB_ICONERROR);
        ResetUiState();
    } else {
        g_isAuthenticated = true;
        g_username = info.username ? info.username : username;
        g_statusText = L"Вход выполнен. Проверяю лицензию.";
        SetWindowTextW(g_passwordEdit, L"");
        RpcRefreshLicense();
    }
    FreeRpcString(info.username);
    InvalidateRect(hwnd, nullptr, TRUE);
}

void DoLogout(HWND hwnd) {
    if (BindRpc()) {
        TrayKeeperLogout();
    }
    ResetUiState();
    KillTimer(hwnd, kScheduleStatusPollTimer);
    g_statusText = L"Вы вышли из аккаунта. JWT-токены и лицензионный тикет удалены из памяти службы.";
    InvalidateRect(hwnd, nullptr, TRUE);
}

void DoActivate(HWND hwnd) {
    if (!BindRpc()) return;
    const std::wstring code = ReadControlText(g_activationEdit);
    TK_LICENSE_INFO info{};
    long status = TK_ERROR_NO_LICENSE;
    status = TrayKeeperActivateProduct(const_cast<wchar_t*>(code.c_str()), &info);

    if (status == TK_OK && info.active) {
        g_hasLicense = true;
        g_licenseExpires = info.expiresAt ? info.expiresAt : L"";
        g_statusText = L"Продукт активирован. Защита разблокирована.";
        RpcRefreshAvDatabase();
        SetWindowTextW(g_activationEdit, L"");
    } else {
        g_hasLicense = false;
        g_statusText = info.message && *info.message ? info.message : L"Ошибка активации: код не принят сервером.";
        MessageBoxW(hwnd, g_statusText.c_str(), kWindowTitle, MB_ICONERROR);
    }
    FreeRpcString(info.expiresAt);
    FreeRpcString(info.message);
    InvalidateRect(hwnd, nullptr, TRUE);
}


void ShowScanResult(HWND hwnd, long status, const TK_SCAN_RESULT& result) {
    g_lastScanSummary = result.details ? result.details : L"";
    if (status == TK_OK) {
        g_statusText = result.infectedObjects > 0 ? L"Сканирование завершено: найдены угрозы." : L"Сканирование завершено: угрозы не найдены.";
        MessageBoxW(hwnd, g_lastScanSummary.c_str(), kWindowTitle, result.infectedObjects > 0 ? MB_ICONWARNING : MB_ICONINFORMATION);
    } else {
        if (g_lastScanSummary.empty()) g_lastScanSummary = L"Ошибка сканирования.";
        g_statusText = g_lastScanSummary;
        MessageBoxW(hwnd, g_lastScanSummary.c_str(), kWindowTitle, MB_ICONERROR);
    }
    InvalidateRect(hwnd, nullptr, TRUE);
}


void UpdateScheduledScanStatusSilently(HWND hwnd) {
    if (!g_scheduleAutoStatusEnabled || !g_isAuthenticated || !g_hasLicense || !BindRpc()) return;

    TK_SCAN_RESULT result{};
    const long status = TrayKeeperGetScheduledScanStatus(&result);
    if (status == TK_OK) {
        g_lastScanSummary = result.details ? result.details : L"";
        g_statusText = result.infectedObjects > 0
            ? L"Автообновление расписания: найдены угрозы."
            : L"Автообновление расписания: угрозы не найдены.";
        InvalidateRect(hwnd, nullptr, TRUE);
    }
    FreeRpcString(result.details);
}

void DoScanFile(HWND hwnd) {
    if (!BindRpc()) return;
    wchar_t fileName[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Выберите файл для сканирования";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;

    TK_SCAN_RESULT result{};
    const long status = TrayKeeperScanFile(fileName, &result);
    ShowScanResult(hwnd, status, result);
    FreeRpcString(result.details);
}

void DoScanDirectory(HWND hwnd) {
    if (!BindRpc()) return;
    BROWSEINFOW browse{};
    browse.hwndOwner = hwnd;
    browse.lpszTitle = L"Выберите папку для сканирования";
    browse.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&browse);
    if (!pidl) return;
    wchar_t folder[MAX_PATH]{};
    const BOOL ok = SHGetPathFromIDListW(pidl, folder);
    CoTaskMemFree(pidl);
    if (!ok) return;

    TK_SCAN_RESULT result{};
    const long status = TrayKeeperScanDirectory(folder, &result);
    ShowScanResult(hwnd, status, result);
    FreeRpcString(result.details);
}

void DoScanFixedDrives(HWND hwnd) {
    if (!BindRpc()) return;
    const int answer = MessageBoxW(hwnd,
        L"Будет запущено сканирование всех несъёмных дисков. Это может занять длительное время. Продолжить?",
        kWindowTitle,
        MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
    if (answer != IDYES) return;

    TK_SCAN_RESULT result{};
    const long status = TrayKeeperScanFixedDrives(&result);
    ShowScanResult(hwnd, status, result);
    FreeRpcString(result.details);
}

void DoStartDirectoryMonitor(HWND hwnd) {
    if (!BindRpc()) return;
    BROWSEINFOW browse{};
    browse.hwndOwner = hwnd;
    browse.lpszTitle = L"Выберите папку для мониторинга";
    browse.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&browse);
    if (!pidl) return;
    wchar_t folder[MAX_PATH]{};
    const BOOL ok = SHGetPathFromIDListW(pidl, folder);
    CoTaskMemFree(pidl);
    if (!ok) return;

    TK_SCAN_RESULT result{};
    const long status = TrayKeeperStartDirectoryMonitor(folder, &result);
    ShowScanResult(hwnd, status, result);
    FreeRpcString(result.details);
}

void DoStopDirectoryMonitor(HWND hwnd) {
    if (!BindRpc()) return;
    TK_SCAN_RESULT result{};
    const long status = TrayKeeperStopDirectoryMonitor(&result);
    ShowScanResult(hwnd, status, result);
    FreeRpcString(result.details);
}

void DoGetDirectoryMonitorStatus(HWND hwnd) {
    if (!BindRpc()) return;
    TK_SCAN_RESULT result{};
    const long status = TrayKeeperGetDirectoryMonitorStatus(&result);
    ShowScanResult(hwnd, status, result);
    FreeRpcString(result.details);
}


long ReadScheduleIntervalSeconds() {
    const std::wstring text = ReadControlText(g_scheduleIntervalEdit);
    long value = _wtol(text.c_str());
    if (value < 10) value = 10;
    if (value > 86400) value = 86400;
    return value;
}

void DoStartScheduledDirectoryScan(HWND hwnd) {
    if (!BindRpc()) return;
    BROWSEINFOW browse{};
    browse.hwndOwner = hwnd;
    browse.lpszTitle = L"Выберите папку для сканирования по расписанию";
    browse.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&browse);
    if (!pidl) return;
    wchar_t folder[MAX_PATH]{};
    const BOOL ok = SHGetPathFromIDListW(pidl, folder);
    CoTaskMemFree(pidl);
    if (!ok) return;

    const long intervalSeconds = ReadScheduleIntervalSeconds();
    TK_SCAN_RESULT result{};
    const long status = TrayKeeperStartScheduledDirectoryScan(folder, intervalSeconds, &result);
    ShowScanResult(hwnd, status, result);
    if (status == TK_OK) {
        g_scheduleAutoStatusEnabled = true;
        SetTimer(hwnd, kScheduleStatusPollTimer, kScheduleStatusPollMs, nullptr);
    }
    FreeRpcString(result.details);
}

void DoStopScheduledScan(HWND hwnd) {
    if (!BindRpc()) return;
    TK_SCAN_RESULT result{};
    const long status = TrayKeeperStopScheduledScan(&result);
    ShowScanResult(hwnd, status, result);
    g_scheduleAutoStatusEnabled = false;
    KillTimer(hwnd, kScheduleStatusPollTimer);
    FreeRpcString(result.details);
}

void DoGetScheduledScanStatus(HWND hwnd) {
    if (!BindRpc()) return;
    TK_SCAN_RESULT result{};
    const long status = TrayKeeperGetScheduledScanStatus(&result);
    ShowScanResult(hwnd, status, result);
    FreeRpcString(result.details);
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
        CreateControls(hwnd);
        AddTrayIcon(hwnd);
        SetTimer(hwnd, kLicensePollTimer, 30000, nullptr);
        RefreshStateAndUi(hwnd);
        return 0;

    case WM_SIZE:
        LayoutControls(hwnd);
        return 0;

    case WM_TIMER:
        if (wParam == kLicensePollTimer) RefreshStateAndUi(hwnd);
        else if (wParam == kScheduleStatusPollTimer) UpdateScheduledScanStatusSilently(hwnd);
        return 0;

    case kTrayCallbackMessage:
        if (LOWORD(lParam) == WM_LBUTTONUP) ShowMainWindow(hwnd);
        else if (LOWORD(lParam) == WM_RBUTTONUP || LOWORD(lParam) == WM_CONTEXTMENU) ShowTrayContextMenu(hwnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDM_FILE_EXIT:
        case IDM_TRAY_EXIT:
            StopServiceFromUi(hwnd);
            QuitApplication(hwnd);
            return 0;
        case IDM_TRAY_OPEN:
            ShowMainWindow(hwnd);
            return 0;
        case IDC_LOGIN_BUTTON:
            DoLogin(hwnd);
            return 0;
        case IDC_LOGOUT_BUTTON:
            DoLogout(hwnd);
            return 0;
        case IDC_ACTIVATE_BUTTON:
            DoActivate(hwnd);
            return 0;
        case IDC_SCAN_FILE_BUTTON:
            DoScanFile(hwnd);
            return 0;
        case IDC_SCAN_DIR_BUTTON:
            DoScanDirectory(hwnd);
            return 0;
        case IDC_SCAN_DRIVES_BUTTON:
            DoScanFixedDrives(hwnd);
            return 0;
        case IDC_MONITOR_DIR_BUTTON:
            DoStartDirectoryMonitor(hwnd);
            return 0;
        case IDC_MONITOR_STOP_BUTTON:
            DoStopDirectoryMonitor(hwnd);
            return 0;
        case IDC_MONITOR_STATUS_BUTTON:
            DoGetDirectoryMonitorStatus(hwnd);
            return 0;
        case IDC_SCHEDULE_DIR_BUTTON:
            DoStartScheduledDirectoryScan(hwnd);
            return 0;
        case IDC_SCHEDULE_STOP_BUTTON:
            DoStopScheduledScan(hwnd);
            return 0;
        case IDC_SCHEDULE_STATUS_BUTTON:
            DoGetScheduledScanStatus(hwnd);
            return 0;
        default:
            return DefWindowProcW(hwnd, message, wParam, lParam);
        }

    case WM_CLOSE:
        if (g_isQuitting) DestroyWindow(hwnd); else ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_PAINT:
        PaintMainWindow(hwnd);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, kLicensePollTimer);
        KillTimer(hwnd, kScheduleStatusPollTimer);
        RemoveTrayIcon();
        if (TrayKeeperControlBinding) RpcBindingFree(&TrayKeeperControlBinding);
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
    windowClass.hbrBackground = CreateSolidBrush(RGB(15, 17, 26));
    windowClass.lpszClassName = kWindowClassName;
    windowClass.hIconSm = LoadIconW(instance, MAKEINTRESOURCEW(IDI_TRAY_APP));
    return RegisterClassExW(&windowClass) != 0;
}

} // namespace

extern "C" { handle_t TrayKeeperControlBinding = nullptr; }
extern "C" void* __RPC_USER midl_user_allocate(size_t size) { return std::malloc(size); }
extern "C" void __RPC_USER midl_user_free(void* pointer) { std::free(pointer); }

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int commandShow) {
    if (StartServiceIfStoppedAndExit()) return 0;
    if (!IsParentServiceProcess()) return 0;

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

    g_mainWindow = CreateWindowExW(0, kWindowClassName, kWindowTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 860, 660, nullptr, nullptr, instance, nullptr);
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
