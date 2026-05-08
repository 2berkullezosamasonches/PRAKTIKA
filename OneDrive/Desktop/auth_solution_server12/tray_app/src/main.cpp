#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <rpc.h>

#include <cstdlib>
#include <string>

#include "resource.h"
#include "TrayKeeperControl.h"

namespace {

constexpr wchar_t kWindowClassName[] = L"TrayKeeperWindowClass";
constexpr wchar_t kWindowTitle[] = L"Tray Keeper";
constexpr wchar_t kServiceName[] = L"TrayKeeperService";
constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"TrayKeeperControlAlpc";
constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayCallbackMessage = WM_APP + 1;
constexpr UINT_PTR kLicenseRefreshTimer = 1001;

constexpr int IDM_LOGOUT = 40004;
constexpr int IDC_LOGIN_EDIT = 50001;
constexpr int IDC_PASSWORD_EDIT = 50002;
constexpr int IDC_LOGIN_BUTTON = 50003;
constexpr int IDC_ACTIVATION_EDIT = 50004;
constexpr int IDC_ACTIVATE_BUTTON = 50005;
constexpr int IDC_LOGOUT_BUTTON = 50006;

HWND g_mainWindow = nullptr;
HMENU g_mainMenu = nullptr;
NOTIFYICONDATAW g_trayIconData{};
UINT g_taskbarCreatedMessage = 0;
bool g_trayIconAdded = false;
bool g_isQuitting = false;

HWND g_titleLabel = nullptr;
HWND g_statusLabel = nullptr;
HWND g_userLabel = nullptr;
HWND g_licenseLabel = nullptr;
HWND g_antivirusLabel = nullptr;
HWND g_loginEdit = nullptr;
HWND g_passwordEdit = nullptr;
HWND g_loginButton = nullptr;
HWND g_activationEdit = nullptr;
HWND g_activateButton = nullptr;
HWND g_logoutButton = nullptr;

struct UiState {
    bool authenticated = false;
    bool hasLicense = false;
    bool antivirusAllowed = false;
    std::wstring username;
    std::wstring licenseEndingDate;
    std::wstring status;
};

UiState g_ui;

} // namespace

extern "C" {
handle_t TrayKeeperControlBinding = nullptr;
}

extern "C" void* __RPC_USER midl_user_allocate(size_t size) {
    return std::malloc(size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer) {
    std::free(pointer);
}

namespace {

std::wstring GetLastErrorText(DWORD errorCode) {
    wchar_t* buffer = nullptr;
    const DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    std::wstring message = size && buffer ? buffer : L"Неизвестная ошибка";
    if (buffer) LocalFree(buffer);
    return message;
}

std::wstring GetControlText(HWND control) {
    const int length = GetWindowTextLengthW(control);
    std::wstring text(static_cast<size_t>(length), L'\0');
    if (length > 0) {
        GetWindowTextW(control, text.data(), length + 1);
    }
    return text;
}

void SetText(HWND hwnd, const std::wstring& text) {
    SetWindowTextW(hwnd, text.c_str());
}

bool HasHiddenModeFlag() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return false;

    bool hidden = false;
    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--hidden") == 0) {
            hidden = true;
            break;
        }
    }
    LocalFree(argv);
    return hidden;
}

std::wstring BuildUserMutexName() {
    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
    return L"Local\\TrayKeeperSingleInstance_" + std::to_wstring(sessionId);
}

bool QueryServiceStatusExSafe(SERVICE_STATUS_PROCESS& status) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return false;

    SC_HANDLE service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
    if (!service) {
        CloseServiceHandle(manager);
        return false;
    }

    DWORD bytesNeeded = 0;
    const BOOL ok = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded);

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return ok != FALSE;
}

bool StartServiceIfStoppedAndExit() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return false;

    SC_HANDLE service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
    if (!service) {
        CloseServiceHandle(manager);
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return false;
    }

    if (status.dwCurrentState == SERVICE_STOPPED) {
        StartServiceW(service, 0, nullptr);
        for (int i = 0; i < 60; ++i) {
            Sleep(500);
            if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) break;
            if (status.dwCurrentState == SERVICE_RUNNING) break;
        }
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return true;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return false;
}

DWORD GetParentProcessId() {
    DWORD parentProcessId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    const DWORD currentProcessId = GetCurrentProcessId();

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == currentProcessId) {
                parentProcessId = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return parentProcessId;
}

bool IsServiceRunning() {
    SERVICE_STATUS_PROCESS status{};
    return QueryServiceStatusExSafe(status) && status.dwCurrentState == SERVICE_RUNNING;
}

bool IsParentServiceProcess() {
    SERVICE_STATUS_PROCESS status{};
    if (!QueryServiceStatusExSafe(status)) return false;

    const DWORD parentProcessId = GetParentProcessId();
    return status.dwProcessId != 0 && parentProcessId == status.dwProcessId;
}

bool IsAllowedServiceLaunchInstance() {
    // The service launches GUI as TrayKeeper.exe --hidden in the user session.
    // On some Windows versions the direct parent PID is not always the service PID after
    // CreateProcessAsUserW/session transition, so we additionally allow hidden mode
    // only while the service is already running. Plain manual launch remains blocked.
    return IsParentServiceProcess() || (HasHiddenModeFlag() && IsServiceRunning());
}

bool BindRpc() {
    RPC_WSTR stringBinding = nullptr;
    RPC_STATUS status = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr,
        &stringBinding);

    if (status != RPC_S_OK) return false;
    status = RpcBindingFromStringBindingW(stringBinding, &TrayKeeperControlBinding);
    RpcStringFreeW(&stringBinding);
    return status == RPC_S_OK;
}

void UnbindRpc() {
    if (TrayKeeperControlBinding) {
        RpcBindingFree(&TrayKeeperControlBinding);
        TrayKeeperControlBinding = nullptr;
    }
}

std::wstring TakeRpcString(wchar_t* value) {
    std::wstring result = value ? value : L"";
    if (value) midl_user_free(value);
    return result;
}

bool RequestServiceStopViaRpc() {
    if (!BindRpc()) return false;
    bool stopped = false;
    TrayKeeperStopService();
    stopped = true;
    UnbindRpc();
    return stopped;
}

bool RpcGetCurrentUser(long& authenticated, std::wstring& username, std::wstring& error) {
    if (!BindRpc()) {
        error = L"Не удалось подключиться к RPC-серверу службы";
        return false;
    }

    long result = ERROR_GEN_FAILURE;
    wchar_t* rpcUsername = nullptr;
    wchar_t* rpcError = nullptr;
    result = TrayKeeperGetCurrentUser(&authenticated, &rpcUsername, &rpcError);

    username = TakeRpcString(rpcUsername);
    error = TakeRpcString(rpcError);
    UnbindRpc();
    return result == ERROR_SUCCESS;
}

bool RpcLogin(const std::wstring& username, const std::wstring& password, std::wstring& error) {
    if (!BindRpc()) {
        error = L"Не удалось подключиться к RPC-серверу службы";
        return false;
    }

    long result = ERROR_GEN_FAILURE;
    wchar_t* rpcError = nullptr;
    std::wstring mutableUsername = username;
    std::wstring mutablePassword = password;
    result = TrayKeeperLogin(mutableUsername.data(), mutablePassword.data(), &rpcError);

    error = TakeRpcString(rpcError);
    UnbindRpc();
    return result == ERROR_SUCCESS;
}

bool RpcLogout(std::wstring& error) {
    if (!BindRpc()) {
        error = L"Не удалось подключиться к RPC-серверу службы";
        return false;
    }

    long result = ERROR_GEN_FAILURE;
    wchar_t* rpcError = nullptr;
    result = TrayKeeperLogout(&rpcError);

    error = TakeRpcString(rpcError);
    UnbindRpc();
    return result == ERROR_SUCCESS;
}

bool RpcGetLicense(long& hasLicense, long& antivirusAllowed, std::wstring& endingDate, std::wstring& error) {
    if (!BindRpc()) {
        error = L"Не удалось подключиться к RPC-серверу службы";
        return false;
    }

    long result = ERROR_GEN_FAILURE;
    wchar_t* rpcEndingDate = nullptr;
    wchar_t* rpcError = nullptr;
    result = TrayKeeperGetLicenseInfo(&hasLicense, &antivirusAllowed, &rpcEndingDate, &rpcError);

    endingDate = TakeRpcString(rpcEndingDate);
    error = TakeRpcString(rpcError);
    UnbindRpc();
    return result == ERROR_SUCCESS;
}

bool RpcActivate(const std::wstring& code, std::wstring& error) {
    if (!BindRpc()) {
        error = L"Не удалось подключиться к RPC-серверу службы";
        return false;
    }

    long result = ERROR_GEN_FAILURE;
    wchar_t* rpcError = nullptr;
    std::wstring mutableCode = code;
    result = TrayKeeperActivateProduct(mutableCode.data(), &rpcError);

    error = TakeRpcString(rpcError);
    UnbindRpc();
    return result == ERROR_SUCCESS;
}

void HideAllAuthControls() {
    HWND controls[] = { g_userLabel, g_licenseLabel, g_antivirusLabel, g_loginEdit, g_passwordEdit,
        g_loginButton, g_activationEdit, g_activateButton, g_logoutButton };
    for (HWND control : controls) {
        if (control) ShowWindow(control, SW_HIDE);
    }
}

void LayoutUi(HWND hwnd) {
    RECT rc{};
    GetClientRect(hwnd, &rc);
    const int width = rc.right - rc.left;
    const int left = 70;
    const int fieldLeft = 250;
    const int fieldWidth = max(240, width - fieldLeft - 80);

    MoveWindow(g_titleLabel, left, 30, width - 140, 32, TRUE);
    MoveWindow(g_statusLabel, left, 72, width - 140, 48, TRUE);
    MoveWindow(g_userLabel, left, 128, width - 140, 28, TRUE);
    MoveWindow(g_licenseLabel, left, 166, width - 140, 28, TRUE);
    MoveWindow(g_antivirusLabel, left, 204, width - 140, 28, TRUE);

    MoveWindow(g_loginEdit, fieldLeft, 150, fieldWidth, 28, TRUE);
    MoveWindow(g_passwordEdit, fieldLeft, 190, fieldWidth, 28, TRUE);
    MoveWindow(g_loginButton, fieldLeft, 236, 170, 34, TRUE);

    MoveWindow(g_activationEdit, fieldLeft, 190, fieldWidth, 28, TRUE);
    MoveWindow(g_activateButton, fieldLeft, 236, 190, 34, TRUE);
    MoveWindow(g_logoutButton, left, 300, 170, 34, TRUE);
}

void RenderUi() {
    HideAllAuthControls();
    SetText(g_titleLabel, L"Tray Keeper Security");
    SetText(g_statusLabel, g_ui.status);

    if (!g_ui.authenticated) {
        SetText(g_userLabel, L"Логин:");
        SetText(g_licenseLabel, L"Пароль:");
        ShowWindow(g_userLabel, SW_SHOW);
        ShowWindow(g_licenseLabel, SW_SHOW);
        ShowWindow(g_loginEdit, SW_SHOW);
        ShowWindow(g_passwordEdit, SW_SHOW);
        ShowWindow(g_loginButton, SW_SHOW);
        SetText(g_antivirusLabel, L"Антивирусная функциональность заблокирована: выполните вход.");
        ShowWindow(g_antivirusLabel, SW_SHOW);
        return;
    }

    SetText(g_userLabel, L"Пользователь: " + g_ui.username);
    ShowWindow(g_userLabel, SW_SHOW);
    ShowWindow(g_logoutButton, SW_SHOW);

    if (!g_ui.hasLicense) {
        SetText(g_licenseLabel, L"Код активации:");
        SetText(g_antivirusLabel, L"Антивирусная функциональность заблокирована: нет активной лицензии.");
        ShowWindow(g_licenseLabel, SW_SHOW);
        ShowWindow(g_antivirusLabel, SW_SHOW);
        ShowWindow(g_activationEdit, SW_SHOW);
        ShowWindow(g_activateButton, SW_SHOW);
        return;
    }

    SetText(g_licenseLabel, L"Лицензия активна до: " + g_ui.licenseEndingDate);
    SetText(g_antivirusLabel, g_ui.antivirusAllowed ? L"Антивирусная функциональность разблокирована." : L"Антивирусная функциональность заблокирована.");
    ShowWindow(g_licenseLabel, SW_SHOW);
    ShowWindow(g_antivirusLabel, SW_SHOW);
}

void RefreshAuthAndLicenseState() {
    long authenticated = 0;
    std::wstring username;
    std::wstring error;

    if (!RpcGetCurrentUser(authenticated, username, error)) {
        g_ui.authenticated = false;
        g_ui.hasLicense = false;
        g_ui.antivirusAllowed = false;
        g_ui.username.clear();
        g_ui.licenseEndingDate.clear();
        g_ui.status = error.empty() ? L"Не удалось получить состояние пользователя." : error;
        RenderUi();
        return;
    }

    g_ui.authenticated = authenticated != 0;
    g_ui.username = username;

    if (!g_ui.authenticated) {
        g_ui.hasLicense = false;
        g_ui.antivirusAllowed = false;
        g_ui.licenseEndingDate.clear();
        g_ui.status = L"Пользователь не аутентифицирован. Введите логин и пароль.";
        RenderUi();
        return;
    }

    long hasLicense = 0;
    long antivirusAllowed = 0;
    std::wstring endingDate;
    std::wstring licenseError;
    const bool licenseOk = RpcGetLicense(hasLicense, antivirusAllowed, endingDate, licenseError);

    g_ui.hasLicense = licenseOk && hasLicense != 0;
    g_ui.antivirusAllowed = licenseOk && antivirusAllowed != 0;
    g_ui.licenseEndingDate = endingDate;
    g_ui.status = g_ui.hasLicense ? L"Вход выполнен. Лицензия активна." : L"Вход выполнен. Требуется активация продукта.";
    if (!g_ui.hasLicense && !licenseError.empty()) {
        g_ui.status += L" " + licenseError;
    }
    RenderUi();
}

void DoLogin(HWND hwnd) {
    const std::wstring username = GetControlText(g_loginEdit);
    const std::wstring password = GetControlText(g_passwordEdit);
    if (username.empty() || password.empty()) {
        MessageBoxW(hwnd, L"Введите логин и пароль.", kWindowTitle, MB_ICONWARNING);
        return;
    }

    std::wstring error;
    if (!RpcLogin(username, password, error)) {
        g_ui.authenticated = false;
        g_ui.hasLicense = false;
        g_ui.antivirusAllowed = false;
        g_ui.status = error.empty() ? L"Ошибка аутентификации." : error;
        RenderUi();
        MessageBoxW(hwnd, g_ui.status.c_str(), kWindowTitle, MB_ICONERROR);
        return;
    }

    SetWindowTextW(g_passwordEdit, L"");
    RefreshAuthAndLicenseState();
}

void DoLogout(HWND hwnd) {
    std::wstring error;
    if (!RpcLogout(error)) {
        MessageBoxW(hwnd, error.empty() ? L"Не удалось выйти из аккаунта." : error.c_str(), kWindowTitle, MB_ICONERROR);
    }
    RefreshAuthAndLicenseState();
}

void DoActivate(HWND hwnd) {
    const std::wstring code = GetControlText(g_activationEdit);
    if (code.empty()) {
        MessageBoxW(hwnd, L"Введите код активации.", kWindowTitle, MB_ICONWARNING);
        return;
    }

    std::wstring error;
    if (!RpcActivate(code, error)) {
        g_ui.hasLicense = false;
        g_ui.antivirusAllowed = false;
        g_ui.status = error.empty() ? L"Ошибка активации." : error;
        RenderUi();
        MessageBoxW(hwnd, g_ui.status.c_str(), kWindowTitle, MB_ICONERROR);
        return;
    }

    SetWindowTextW(g_activationEdit, L"");
    RefreshAuthAndLicenseState();
}

void ShowMainWindow(HWND hwnd) {
    RefreshAuthAndLicenseState();
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

void StopServiceFromUi(HWND hwnd) {
    if (!RequestServiceStopViaRpc()) {
        MessageBoxW(hwnd, L"Не удалось отправить команду остановки службе.", kWindowTitle, MB_ICONERROR);
    }
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
    AppendMenuW(fileMenu, MF_STRING, IDM_LOGOUT, L"Выйти из аккаунта");
    AppendMenuW(mainMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"Файл");
    return mainMenu;
}

HWND CreateLabel(HWND parent, const wchar_t* text) {
    return CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE, 0, 0, 100, 24, parent, nullptr, GetModuleHandleW(nullptr), nullptr);
}

HWND CreateEdit(HWND parent, int id, bool password = false) {
    DWORD style = WS_CHILD | WS_BORDER | ES_AUTOHSCROLL;
    if (password) style |= ES_PASSWORD;
    return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", style, 0, 0, 100, 24, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
}

HWND CreateButton(HWND parent, int id, const wchar_t* text) {
    return CreateWindowExW(0, L"BUTTON", text, WS_CHILD | BS_PUSHBUTTON, 0, 0, 100, 28, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
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

        g_titleLabel = CreateLabel(hwnd, L"Tray Keeper Security");
        g_statusLabel = CreateLabel(hwnd, L"");
        g_userLabel = CreateLabel(hwnd, L"");
        g_licenseLabel = CreateLabel(hwnd, L"");
        g_antivirusLabel = CreateLabel(hwnd, L"");
        g_loginEdit = CreateEdit(hwnd, IDC_LOGIN_EDIT);
        g_passwordEdit = CreateEdit(hwnd, IDC_PASSWORD_EDIT, true);
        g_loginButton = CreateButton(hwnd, IDC_LOGIN_BUTTON, L"Войти");
        g_activationEdit = CreateEdit(hwnd, IDC_ACTIVATION_EDIT);
        g_activateButton = CreateButton(hwnd, IDC_ACTIVATE_BUTTON, L"Активировать");
        g_logoutButton = CreateButton(hwnd, IDC_LOGOUT_BUTTON, L"Выйти из аккаунта");

        SendMessageW(g_titleLabel, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
        LayoutUi(hwnd);
        RefreshAuthAndLicenseState();
        SetTimer(hwnd, kLicenseRefreshTimer, 15000, nullptr);
        return 0;

    case WM_SIZE:
        LayoutUi(hwnd);
        return 0;

    case kTrayCallbackMessage:
        if (LOWORD(lParam) == WM_LBUTTONUP) {
            ShowMainWindow(hwnd);
        } else if (LOWORD(lParam) == WM_RBUTTONUP || LOWORD(lParam) == WM_CONTEXTMENU) {
            ShowTrayContextMenu(hwnd);
        }
        return 0;

    case WM_TIMER:
        if (wParam == kLicenseRefreshTimer) {
            RefreshAuthAndLicenseState();
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDM_FILE_EXIT:
        case IDM_TRAY_EXIT:
            StopServiceFromUi(hwnd);
            return 0;
        case IDM_TRAY_OPEN:
            ShowMainWindow(hwnd);
            return 0;
        case IDM_LOGOUT:
        case IDC_LOGOUT_BUTTON:
            DoLogout(hwnd);
            return 0;
        case IDC_LOGIN_BUTTON:
            DoLogin(hwnd);
            return 0;
        case IDC_ACTIVATE_BUTTON:
            DoActivate(hwnd);
            return 0;
        default:
            return DefWindowProcW(hwnd, message, wParam, lParam);
        }

    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, kLicenseRefreshTimer);
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
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = kWindowClassName;
    windowClass.hIconSm = LoadIconW(instance, MAKEINTRESOURCEW(IDI_TRAY_APP));
    return RegisterClassExW(&windowClass) != 0;
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int commandShow) {
    if (StartServiceIfStoppedAndExit()) {
        return 0;
    }

    if (!IsAllowedServiceLaunchInstance()) {
        return 0;
    }

    const std::wstring mutexName = BuildUserMutexName();
    HANDLE singleInstanceMutex = CreateMutexW(nullptr, TRUE, mutexName.c_str());
    if (!singleInstanceMutex) {
        MessageBoxW(nullptr, (L"Не удалось создать mutex: " + GetLastErrorText(GetLastError())).c_str(), kWindowTitle, MB_ICONERROR);
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
        760,
        430,
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
