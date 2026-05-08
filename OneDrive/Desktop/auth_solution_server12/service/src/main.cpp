#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <rpc.h>
#include <userenv.h>
#include <wtsapi32.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <wincrypt.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "TrayKeeperControl.h"

namespace {

constexpr wchar_t kServiceName[] = L"TrayKeeperService";
constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"TrayKeeperControlAlpc";
constexpr wchar_t kServerHost[] = L"localhost";
constexpr INTERNET_PORT kServerPort = 8443;
constexpr DWORD kProductId = 1;
constexpr DWORD kMinRefreshDelaySeconds = 30;

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stopEvent = nullptr;
std::mutex g_processesMutex;
std::mutex g_stateMutex;
std::thread g_backgroundThread;
std::atomic_bool g_backgroundRunning{ false };

struct TrayProcess {
    DWORD sessionId = 0;
    PROCESS_INFORMATION processInfo{};
};

struct AuthState {
    bool authenticated = false;
    std::wstring username;
    std::wstring accessToken;
    std::wstring refreshToken;
    long long accessExpUnix = 0;
    long long refreshExpUnix = 0;
};

struct LicenseState {
    bool hasLicense = false;
    bool antivirusAllowed = false;
    std::wstring endingDate;
    std::wstring ticketJson;
    std::wstring signature;
    std::chrono::system_clock::time_point refreshAt{};
};

std::vector<TrayProcess> g_trayProcesses;
AuthState g_auth;
LicenseState g_license;

std::filesystem::path GetServiceDirectory() {
    wchar_t modulePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    return std::filesystem::path(modulePath).parent_path();
}

void WriteLog(const std::wstring& message) {
    const std::filesystem::path logPath = GetServiceDirectory() / L"TrayKeeperService.log";
    std::wofstream log(logPath, std::ios::app);
    if (log) {
        SYSTEMTIME time{};
        GetLocalTime(&time);
        log << L"[" << time.wYear << L"-" << time.wMonth << L"-" << time.wDay
            << L" " << time.wHour << L":" << time.wMinute << L":" << time.wSecond
            << L"] " << message << L"\n";
    }
}

void LogLastError(const std::wstring& operation) {
    WriteLog(operation + L" failed. GetLastError=" + std::to_wstring(GetLastError()));
}

void SetServiceStatusState(DWORD state, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = win32ExitCode;
    g_status.dwWaitHint = waitHint;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_SESSIONCHANGE : 0;

    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
        ++g_status.dwCheckPoint;
    } else {
        g_status.dwCheckPoint = 0;
    }

    if (g_statusHandle) {
        SetServiceStatus(g_statusHandle, &g_status);
    }
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) return L"";
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) return "";
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring EscapeJson(const std::wstring& value) {
    std::wstring result;
    result.reserve(value.size() + 8);
    for (wchar_t ch : value) {
        switch (ch) {
        case L'\\': result += L"\\\\"; break;
        case L'\"': result += L"\\\""; break;
        case L'\n': result += L"\\n"; break;
        case L'\r': result += L"\\r"; break;
        case L'\t': result += L"\\t"; break;
        default: result += ch; break;
        }
    }
    return result;
}

std::wstring JsonString(const std::wstring& json, const std::wstring& key) {
    const std::wstring needle = L"\"" + key + L"\"";
    size_t pos = json.find(needle);
    if (pos == std::wstring::npos) return L"";
    pos = json.find(L':', pos);
    if (pos == std::wstring::npos) return L"";
    pos = json.find(L'\"', pos);
    if (pos == std::wstring::npos) return L"";
    ++pos;
    std::wstring result;
    bool escape = false;
    for (; pos < json.size(); ++pos) {
        wchar_t ch = json[pos];
        if (escape) {
            switch (ch) {
            case L'n': result.push_back(L'\n'); break;
            case L'r': result.push_back(L'\r'); break;
            case L't': result.push_back(L'\t'); break;
            default: result.push_back(ch); break;
            }
            escape = false;
        } else if (ch == L'\\') {
            escape = true;
        } else if (ch == L'\"') {
            break;
        } else {
            result.push_back(ch);
        }
    }
    return result;
}

long long JsonInt64(const std::wstring& json, const std::wstring& key) {
    const std::wstring needle = L"\"" + key + L"\"";
    size_t pos = json.find(needle);
    if (pos == std::wstring::npos) return 0;
    pos = json.find(L':', pos);
    if (pos == std::wstring::npos) return 0;
    ++pos;
    while (pos < json.size() && iswspace(json[pos])) ++pos;
    size_t end = pos;
    while (end < json.size() && (iswdigit(json[end]) || json[end] == L'-')) ++end;
    if (end == pos) return 0;
    try { return std::stoll(json.substr(pos, end - pos)); } catch (...) { return 0; }
}

std::wstring JsonObject(const std::wstring& json, const std::wstring& key) {
    const std::wstring needle = L"\"" + key + L"\"";
    size_t pos = json.find(needle);
    if (pos == std::wstring::npos) return L"";
    pos = json.find(L'{', pos);
    if (pos == std::wstring::npos) return L"";
    int depth = 0;
    bool inString = false;
    bool escape = false;
    for (size_t i = pos; i < json.size(); ++i) {
        wchar_t ch = json[i];
        if (escape) { escape = false; continue; }
        if (ch == L'\\') { escape = true; continue; }
        if (ch == L'\"') { inString = !inString; continue; }
        if (!inString) {
            if (ch == L'{') ++depth;
            if (ch == L'}') {
                --depth;
                if (depth == 0) return json.substr(pos, i - pos + 1);
            }
        }
    }
    return L"";
}

std::vector<unsigned char> Base64UrlDecode(std::string input) {
    for (char& c : input) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (input.size() % 4) input.push_back('=');

    DWORD outputSize = 0;
    if (!CryptStringToBinaryA(input.c_str(), static_cast<DWORD>(input.size()), CRYPT_STRING_BASE64, nullptr, &outputSize, nullptr, nullptr)) {
        return {};
    }
    std::vector<unsigned char> output(outputSize);
    if (!CryptStringToBinaryA(input.c_str(), static_cast<DWORD>(input.size()), CRYPT_STRING_BASE64, output.data(), &outputSize, nullptr, nullptr)) {
        return {};
    }
    output.resize(outputSize);
    return output;
}

long long GetJwtExpUnix(const std::wstring& token) {
    const std::string utf8 = WideToUtf8(token);
    const size_t firstDot = utf8.find('.');
    if (firstDot == std::string::npos) return 0;
    const size_t secondDot = utf8.find('.', firstDot + 1);
    if (secondDot == std::string::npos) return 0;
    const std::string payload64 = utf8.substr(firstDot + 1, secondDot - firstDot - 1);
    const auto payload = Base64UrlDecode(payload64);
    if (payload.empty()) return 0;
    const std::wstring json = Utf8ToWide(std::string(reinterpret_cast<const char*>(payload.data()), payload.size()));
    return JsonInt64(json, L"exp");
}

std::wstring AllocRpcString(const std::wstring& value) {
    return value;
}

void SetRpcString(wchar_t** output, const std::wstring& value) {
    if (!output) return;
    const size_t bytes = (value.size() + 1) * sizeof(wchar_t);
    auto* buffer = static_cast<wchar_t*>(midl_user_allocate(bytes));
    if (!buffer) {
        *output = nullptr;
        return;
    }
    memcpy(buffer, value.c_str(), bytes);
    *output = buffer;
}

struct HttpResponse {
    DWORD statusCode = 0;
    std::wstring body;
    std::wstring error;
};

HttpResponse HttpsPost(const std::wstring& path, const std::wstring& body, const std::wstring& bearerToken = L"") {
    HttpResponse result;
    HINTERNET session = WinHttpOpen(L"TrayKeeperService/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { result.error = L"WinHttpOpen failed"; return result; }

    HINTERNET connection = WinHttpConnect(session, kServerHost, kServerPort, 0);
    if (!connection) {
        result.error = L"WinHttpConnect failed";
        WinHttpCloseHandle(session);
        return result;
    }

    HINTERNET request = WinHttpOpenRequest(connection, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!request) {
        result.error = L"WinHttpOpenRequest failed";
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return result;
    }

    DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    if (!bearerToken.empty()) {
        headers += L"Authorization: Bearer " + bearerToken + L"\r\n";
    }

    const std::string requestBody = WideToUtf8(body);
    BOOL sent = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        const_cast<char*>(requestBody.data()),
        static_cast<DWORD>(requestBody.size()),
        static_cast<DWORD>(requestBody.size()),
        0);

    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        result.error = L"HTTPS request failed. Error=" + std::to_wstring(GetLastError());
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return result;
    }

    DWORD statusSize = sizeof(result.statusCode);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
        &result.statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);

    std::string responseUtf8;
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available) || available == 0) break;
        std::string buffer(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request, buffer.data(), available, &read) || read == 0) break;
        buffer.resize(read);
        responseUtf8 += buffer;
    }
    result.body = Utf8ToWide(responseUtf8);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return result;
}

std::wstring GetDeviceMac() {
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW) {
        return L"00-00-00-00-00-00";
    }
    std::vector<unsigned char> buffer(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, adapters, &size) != NO_ERROR) {
        return L"00-00-00-00-00-00";
    }
    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->PhysicalAddressLength == 6 && adapter->IfType != IF_TYPE_SOFTWARE_LOOPBACK) {
            std::wstringstream ss;
            for (ULONG i = 0; i < adapter->PhysicalAddressLength; ++i) {
                if (i) ss << L"-";
                wchar_t part[4]{};
                swprintf_s(part, L"%02X", adapter->PhysicalAddress[i]);
                ss << part;
            }
            return ss.str();
        }
    }
    return L"00-00-00-00-00-00";
}

std::wstring GetDeviceName() {
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = static_cast<DWORD>(std::size(name));
    if (GetComputerNameW(name, &size)) return name;
    return L"Windows device";
}

void ClearLicenseLocked() {
    g_license = LicenseState{};
}

void ClearAuthAndLicenseLocked() {
    g_auth = AuthState{};
    ClearLicenseLocked();
}

bool StoreLicenseFromResponseLocked(const std::wstring& responseJson, std::wstring& error) {
    const std::wstring ticketJson = JsonObject(responseJson, L"ticket");
    if (ticketJson.empty()) {
        error = L"Ответ сервера не содержит лицензионный тикет";
        return false;
    }

    g_license.hasLicense = true;
    g_license.antivirusAllowed = true;
    g_license.ticketJson = ticketJson;
    g_license.signature = JsonString(responseJson, L"signature");
    g_license.endingDate = JsonString(ticketJson, L"endingDate");

    const long long lifetime = JsonInt64(ticketJson, L"ticketLifetimeSeconds");
    const long long delay = std::max<long long>(kMinRefreshDelaySeconds, lifetime > 90 ? lifetime - 60 : lifetime > 0 ? lifetime / 2 : 300);
    g_license.refreshAt = std::chrono::system_clock::now() + std::chrono::seconds(delay);
    return true;
}

bool LoginInternal(const std::wstring& username, const std::wstring& password, std::wstring& error) {
    const std::wstring body = L"{\"username\":\"" + EscapeJson(username) + L"\",\"password\":\"" + EscapeJson(password) + L"\"}";
    const HttpResponse response = HttpsPost(L"/api/auth/login", body);
    if (response.statusCode < 200 || response.statusCode >= 300) {
        error = response.body.empty() ? response.error : response.body;
        return false;
    }

    const std::wstring accessToken = JsonString(response.body, L"accessToken");
    const std::wstring refreshToken = JsonString(response.body, L"refreshToken");
    if (accessToken.empty() || refreshToken.empty()) {
        error = L"Сервер не вернул JWT-токены";
        return false;
    }

    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_auth.authenticated = true;
    g_auth.username = username;
    g_auth.accessToken = accessToken;
    g_auth.refreshToken = refreshToken;
    g_auth.accessExpUnix = GetJwtExpUnix(accessToken);
    g_auth.refreshExpUnix = GetJwtExpUnix(refreshToken);
    ClearLicenseLocked();
    return true;
}

bool RefreshTokensInternal(std::wstring& error) {
    std::wstring refreshToken;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (!g_auth.authenticated || g_auth.refreshToken.empty()) return false;
        refreshToken = g_auth.refreshToken;
    }

    const std::wstring body = L"{\"refreshToken\":\"" + EscapeJson(refreshToken) + L"\"}";
    const HttpResponse response = HttpsPost(L"/api/auth/refresh", body);
    if (response.statusCode < 200 || response.statusCode >= 300) {
        error = response.body.empty() ? response.error : response.body;
        std::lock_guard<std::mutex> lock(g_stateMutex);
        ClearAuthAndLicenseLocked();
        return false;
    }

    const std::wstring accessToken = JsonString(response.body, L"accessToken");
    const std::wstring newRefreshToken = JsonString(response.body, L"refreshToken");
    if (accessToken.empty() || newRefreshToken.empty()) {
        error = L"Сервер не вернул обновлённые JWT-токены";
        return false;
    }

    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_auth.accessToken = accessToken;
    g_auth.refreshToken = newRefreshToken;
    g_auth.accessExpUnix = GetJwtExpUnix(accessToken);
    g_auth.refreshExpUnix = GetJwtExpUnix(newRefreshToken);
    return true;
}

bool CheckLicenseInternal(std::wstring& error) {
    std::wstring accessToken;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (!g_auth.authenticated) {
            error = L"Пользователь не аутентифицирован";
            return false;
        }
        accessToken = g_auth.accessToken;
    }

    const std::wstring body = L"{\"deviceMac\":\"" + EscapeJson(GetDeviceMac()) + L"\",\"productId\":" + std::to_wstring(kProductId) + L"}";
    const HttpResponse response = HttpsPost(L"/api/licenses/check", body, accessToken);
    if (response.statusCode < 200 || response.statusCode >= 300) {
        error = response.body.empty() ? response.error : response.body;
        std::lock_guard<std::mutex> lock(g_stateMutex);
        ClearLicenseLocked();
        return false;
    }

    std::lock_guard<std::mutex> lock(g_stateMutex);
    return StoreLicenseFromResponseLocked(response.body, error);
}

bool ActivateInternal(const std::wstring& code, std::wstring& error) {
    std::wstring accessToken;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (!g_auth.authenticated) {
            error = L"Пользователь не аутентифицирован";
            return false;
        }
        accessToken = g_auth.accessToken;
    }

    const std::wstring body = L"{\"code\":\"" + EscapeJson(code) + L"\",\"deviceMac\":\"" + EscapeJson(GetDeviceMac()) +
        L"\",\"deviceName\":\"" + EscapeJson(GetDeviceName()) + L"\"}";
    const HttpResponse response = HttpsPost(L"/api/licenses/activate", body, accessToken);
    if (response.statusCode < 200 || response.statusCode >= 300) {
        error = response.body.empty() ? response.error : response.body;
        std::lock_guard<std::mutex> lock(g_stateMutex);
        ClearLicenseLocked();
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (StoreLicenseFromResponseLocked(response.body, error)) {
            return true;
        }
    }

    // На случай сервера, который после активации не возвращает тикет.
    return CheckLicenseInternal(error);
}

long long NowUnix() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void BackgroundRefreshLoop() {
    g_backgroundRunning = true;
    while (g_stopEvent && WaitForSingleObject(g_stopEvent, 10000) == WAIT_TIMEOUT) {
        bool shouldRefreshToken = false;
        bool shouldRefreshLicense = false;
        {
            std::lock_guard<std::mutex> lock(g_stateMutex);
            if (g_auth.authenticated) {
                const long long now = NowUnix();
                shouldRefreshToken = g_auth.accessExpUnix == 0 || now >= g_auth.accessExpUnix - 60;
                shouldRefreshLicense = g_license.hasLicense && std::chrono::system_clock::now() >= g_license.refreshAt;
            }
        }
        std::wstring error;
        if (shouldRefreshToken) {
            RefreshTokensInternal(error);
        }
        if (shouldRefreshLicense) {
            CheckLicenseInternal(error);
        }
    }
    g_backgroundRunning = false;
}

std::filesystem::path GetTrayAppPath() {
    return GetServiceDirectory() / L"TrayKeeper.exe";
}

void RemoveExitedProcessesLocked() {
    g_trayProcesses.erase(
        std::remove_if(
            g_trayProcesses.begin(),
            g_trayProcesses.end(),
            [](TrayProcess& process) {
                const DWORD wait = WaitForSingleObject(process.processInfo.hProcess, 0);
                if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED) {
                    CloseHandle(process.processInfo.hThread);
                    CloseHandle(process.processInfo.hProcess);
                    return true;
                }
                return false;
            }),
        g_trayProcesses.end());
}

bool IsSessionAlreadyStartedLocked(DWORD sessionId) {
    RemoveExitedProcessesLocked();
    return std::any_of(g_trayProcesses.begin(), g_trayProcesses.end(), [sessionId](const TrayProcess& process) {
        return process.sessionId == sessionId;
    });
}

bool LaunchTrayForSession(DWORD sessionId) {
    if (sessionId == 0) {
        WriteLog(L"Skipping session 0");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_processesMutex);
        if (IsSessionAlreadyStartedLocked(sessionId)) return true;
    }

    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &userToken)) {
        LogLastError(L"WTSQueryUserToken");
        return false;
    }

    HANDLE primaryToken = nullptr;
    const BOOL duplicated = DuplicateTokenEx(userToken,
        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
        nullptr, SecurityImpersonation, TokenPrimary, &primaryToken);
    CloseHandle(userToken);
    if (!duplicated) {
        LogLastError(L"DuplicateTokenEx");
        return false;
    }

    void* environment = nullptr;
    if (!CreateEnvironmentBlock(&environment, primaryToken, FALSE)) {
        LogLastError(L"CreateEnvironmentBlock");
    }

    const std::filesystem::path appPath = GetTrayAppPath();
    const std::wstring commandLine = L"\"" + appPath.wstring() + L"\" --hidden";
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PROCESS_INFORMATION processInfo{};
    BOOL created = CreateProcessAsUserW(primaryToken, appPath.c_str(), mutableCommandLine.data(), nullptr, nullptr, FALSE,
        CREATE_UNICODE_ENVIRONMENT, environment, appPath.parent_path().c_str(), &startupInfo, &processInfo);

    if (!created) {
        LogLastError(L"CreateProcessAsUserW");
        created = CreateProcessWithTokenW(primaryToken, LOGON_WITH_PROFILE, appPath.c_str(), mutableCommandLine.data(),
            CREATE_UNICODE_ENVIRONMENT, environment, appPath.parent_path().c_str(), &startupInfo, &processInfo);
        if (!created) LogLastError(L"CreateProcessWithTokenW");
    }

    if (environment) DestroyEnvironmentBlock(environment);
    CloseHandle(primaryToken);
    if (!created) return false;

    std::lock_guard<std::mutex> lock(g_processesMutex);
    g_trayProcesses.push_back({ sessionId, processInfo });
    WriteLog(L"Started TrayKeeper.exe pid " + std::to_wstring(processInfo.dwProcessId) + L" for session " + std::to_wstring(sessionId));
    return true;
}

void LaunchTrayForAllLoggedOnSessions() {
    WTS_SESSION_INFOW* sessions = nullptr;
    DWORD sessionCount = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &sessionCount)) {
        LogLastError(L"WTSEnumerateSessionsW");
        return;
    }
    for (DWORD i = 0; i < sessionCount; ++i) {
        if (sessions[i].SessionId != 0 && (sessions[i].State == WTSActive || sessions[i].State == WTSConnected)) {
            LaunchTrayForSession(sessions[i].SessionId);
        }
    }
    WTSFreeMemory(sessions);
}

void TerminateTrayProcesses() {
    std::lock_guard<std::mutex> lock(g_processesMutex);
    for (TrayProcess& process : g_trayProcesses) {
        TerminateProcess(process.processInfo.hProcess, 0);
        WaitForSingleObject(process.processInfo.hProcess, 3000);
        CloseHandle(process.processInfo.hThread);
        CloseHandle(process.processInfo.hProcess);
    }
    g_trayProcesses.clear();
}

RPC_STATUS StartRpcServer() {
    RPC_STATUS status = RpcServerUseProtseqEpW(reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)), nullptr);
    if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) return status;

    status = RpcServerRegisterIf2(TrayKeeperControl_v1_0_s_ifspec, nullptr, nullptr, RPC_IF_ALLOW_LOCAL_ONLY,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT, static_cast<unsigned int>(-1), nullptr);
    if (status != RPC_S_OK) return status;

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    if (status == RPC_S_ALREADY_LISTENING) status = RPC_S_OK;
    return status;
}

void StopRpcServer() {
    RpcMgmtStopServerListening(nullptr);
    RpcServerUnregisterIf(nullptr, nullptr, FALSE);
}

DWORD WINAPI ServiceControlHandler(DWORD control, DWORD eventType, LPVOID, LPVOID) {
    switch (control) {
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    case SERVICE_CONTROL_SESSIONCHANGE:
        if (eventType == WTS_SESSION_LOGON || eventType == WTS_CONSOLE_CONNECT ||
            eventType == WTS_REMOTE_CONNECT || eventType == WTS_SESSION_UNLOCK) {
            LaunchTrayForAllLoggedOnSessions();
        }
        return NO_ERROR;
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        return ERROR_CALL_NOT_IMPLEMENTED;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceControlHandler, nullptr);
    if (!g_statusHandle) return;

    SetServiceStatusState(SERVICE_START_PENDING, NO_ERROR, 3000);
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        SetServiceStatusState(SERVICE_STOPPED, GetLastError());
        return;
    }

    const RPC_STATUS rpcStatus = StartRpcServer();
    if (rpcStatus != RPC_S_OK) {
        SetServiceStatusState(SERVICE_STOPPED, rpcStatus);
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        return;
    }

    g_backgroundThread = std::thread(BackgroundRefreshLoop);
    LaunchTrayForAllLoggedOnSessions();
    SetServiceStatusState(SERVICE_RUNNING);

    WaitForSingleObject(g_stopEvent, INFINITE);

    SetServiceStatusState(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    StopRpcServer();
    if (g_backgroundThread.joinable()) g_backgroundThread.join();
    TerminateTrayProcesses();

    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        ClearAuthAndLicenseLocked();
    }

    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    SetServiceStatusState(SERVICE_STOPPED);
}

} // namespace

extern "C" void* __RPC_USER midl_user_allocate(size_t size) {
    return std::malloc(size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer) {
    std::free(pointer);
}

extern "C" void TrayKeeperStopService() {
    if (g_stopEvent) SetEvent(g_stopEvent);
}

extern "C" long TrayKeeperGetCurrentUser(long* authenticated, wchar_t** username, wchar_t** errorMessage) {
    if (!authenticated || !username || !errorMessage) return ERROR_INVALID_PARAMETER;
    std::lock_guard<std::mutex> lock(g_stateMutex);
    *authenticated = g_auth.authenticated ? 1 : 0;
    SetRpcString(username, g_auth.authenticated ? g_auth.username : L"");
    SetRpcString(errorMessage, L"");
    return ERROR_SUCCESS;
}

extern "C" long TrayKeeperLogin(wchar_t* username, wchar_t* password, wchar_t** errorMessage) {
    if (!username || !password || !errorMessage) return ERROR_INVALID_PARAMETER;
    std::wstring error;
    const bool ok = LoginInternal(username, password, error);
    if (ok) {
        std::wstring ignored;
        CheckLicenseInternal(ignored);
    }
    SetRpcString(errorMessage, ok ? L"" : error);
    return ok ? ERROR_SUCCESS : ERROR_LOGON_FAILURE;
}

extern "C" long TrayKeeperLogout(wchar_t** errorMessage) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    ClearAuthAndLicenseLocked();
    SetRpcString(errorMessage, L"");
    return ERROR_SUCCESS;
}

extern "C" long TrayKeeperGetLicenseInfo(long* hasLicense, long* antivirusAllowed, wchar_t** endingDate, wchar_t** errorMessage) {
    if (!hasLicense || !antivirusAllowed || !endingDate || !errorMessage) return ERROR_INVALID_PARAMETER;

    bool shouldCheck = false;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        shouldCheck = g_auth.authenticated && !g_license.hasLicense;
    }
    std::wstring checkError;
    if (shouldCheck) CheckLicenseInternal(checkError);

    std::lock_guard<std::mutex> lock(g_stateMutex);
    *hasLicense = g_license.hasLicense ? 1 : 0;
    *antivirusAllowed = g_license.antivirusAllowed ? 1 : 0;
    SetRpcString(endingDate, g_license.hasLicense ? g_license.endingDate : L"");
    SetRpcString(errorMessage, g_license.hasLicense ? L"" : (checkError.empty() ? L"Лицензия отсутствует" : checkError));
    return g_license.hasLicense ? ERROR_SUCCESS : ERROR_LICENSE_QUOTA_EXCEEDED;
}

extern "C" long TrayKeeperActivateProduct(wchar_t* activationCode, wchar_t** errorMessage) {
    if (!activationCode || !errorMessage) return ERROR_INVALID_PARAMETER;
    std::wstring error;
    const bool ok = ActivateInternal(activationCode, error);
    SetRpcString(errorMessage, ok ? L"" : error);
    return ok ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

extern "C" long TrayKeeperCheckAntivirusAccess(wchar_t** errorMessage) {
    if (!errorMessage) return ERROR_INVALID_PARAMETER;
    std::lock_guard<std::mutex> lock(g_stateMutex);
    if (!g_license.hasLicense || !g_license.antivirusAllowed) {
        SetRpcString(errorMessage, L"Антивирусная функциональность заблокирована: нет активной лицензии");
        return ERROR_LICENSE_QUOTA_EXCEEDED;
    }
    SetRpcString(errorMessage, L"");
    return ERROR_SUCCESS;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        return static_cast<int>(GetLastError());
    }
    return 0;
}
