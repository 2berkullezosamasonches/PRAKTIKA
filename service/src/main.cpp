#include <windows.h>
#include <rpc.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

#include "TrayKeeperControl.h"

namespace {

constexpr wchar_t kServiceName[] = L"TrayKeeperService";
constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"TrayKeeperControlAlpc";

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stopEvent = nullptr;
std::mutex g_processesMutex;

struct TrayProcess {
    DWORD sessionId = 0;
    PROCESS_INFORMATION processInfo{};
};

std::vector<TrayProcess> g_trayProcesses;

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

std::filesystem::path GetTrayAppPath() {
    wchar_t modulePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, modulePath, MAX_PATH);

    std::filesystem::path path(modulePath);
    path = path.parent_path() / L"TrayKeeper.exe";
    return path;
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

    return std::any_of(
        g_trayProcesses.begin(),
        g_trayProcesses.end(),
        [sessionId](const TrayProcess& process) {
            return process.sessionId == sessionId;
        });
}

bool LaunchTrayForSession(DWORD sessionId) {
    if (sessionId == 0) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_processesMutex);
        if (IsSessionAlreadyStartedLocked(sessionId)) {
            return true;
        }
    }

    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &userToken)) {
        return false;
    }

    HANDLE primaryToken = nullptr;
    const BOOL duplicated = DuplicateTokenEx(
        userToken,
        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
        nullptr,
        SecurityImpersonation,
        TokenPrimary,
        &primaryToken);
    CloseHandle(userToken);

    if (!duplicated) {
        return false;
    }

    void* environment = nullptr;
    CreateEnvironmentBlock(&environment, primaryToken, FALSE);

    const std::filesystem::path appPath = GetTrayAppPath();
    const std::wstring commandLine = L"\"" + appPath.wstring() + L"\" --hidden";
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PROCESS_INFORMATION processInfo{};
    const BOOL created = CreateProcessAsUserW(
        primaryToken,
        appPath.c_str(),
        mutableCommandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        environment,
        appPath.parent_path().c_str(),
        &startupInfo,
        &processInfo);

    if (environment) {
        DestroyEnvironmentBlock(environment);
    }
    CloseHandle(primaryToken);

    if (!created) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_processesMutex);
    g_trayProcesses.push_back({ sessionId, processInfo });
    return true;
}

void LaunchTrayForAllLoggedOnSessions() {
    WTS_SESSION_INFOW* sessions = nullptr;
    DWORD sessionCount = 0;

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &sessionCount)) {
        return;
    }

    for (DWORD i = 0; i < sessionCount; ++i) {
        if (sessions[i].SessionId != 0 &&
            (sessions[i].State == WTSActive || sessions[i].State == WTSConnected)) {
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
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr);

    if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
        return status;
    }

    status = RpcServerRegisterIf2(
        TrayKeeperControl_v1_0_s_ifspec,
        nullptr,
        nullptr,
        RPC_IF_ALLOW_LOCAL_ONLY,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        static_cast<unsigned int>(-1),
        nullptr);

    if (status != RPC_S_OK) {
        return status;
    }

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    if (status == RPC_S_ALREADY_LISTENING) {
        status = RPC_S_OK;
    }

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
        if (eventType == WTS_SESSION_LOGON ||
            eventType == WTS_CONSOLE_CONNECT ||
            eventType == WTS_REMOTE_CONNECT ||
            eventType == WTS_SESSION_UNLOCK) {
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
    if (!g_statusHandle) {
        return;
    }

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

    LaunchTrayForAllLoggedOnSessions();
    SetServiceStatusState(SERVICE_RUNNING);

    WaitForSingleObject(g_stopEvent, INFINITE);

    SetServiceStatusState(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    StopRpcServer();
    TerminateTrayProcesses();

    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;

    SetServiceStatusState(SERVICE_STOPPED);
}

} // namespace

extern "C" void TrayKeeperStopService() {
    RpcMgmtStopServerListening(nullptr);

    if (g_stopEvent) {
        SetEvent(g_stopEvent);
    }
}

extern "C" void* __RPC_USER midl_user_allocate(size_t size) {
    return std::malloc(size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer) {
    std::free(pointer);
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
