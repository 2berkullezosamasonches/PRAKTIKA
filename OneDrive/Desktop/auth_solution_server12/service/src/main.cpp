#include <windows.h>
#include <rpc.h>
#include <userenv.h>
#include <wtsapi32.h>
#include <winhttp.h>
#include <strsafe.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cctype>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <cstdint>
#include <cwctype>
#include <vector>

#include "TrayKeeperControl.h"

void StopDirectoryMonitorWorkerInternal();
void StopScheduledScanWorkerInternal();

namespace {

constexpr wchar_t kServiceName[] = L"TrayKeeperService";
constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"TrayKeeperControlAlpc";
constexpr wchar_t kServerHost[] = L"localhost";
constexpr INTERNET_PORT kServerPort = 8443;
constexpr DWORD kProductId = 1;

constexpr long TK_OK = 0;
constexpr long TK_ERROR_NETWORK = 1001;
constexpr long TK_ERROR_AUTH = 1002;
constexpr long TK_ERROR_NO_LICENSE = 1003;
constexpr long TK_ERROR_ACTIVATION = 1004;
constexpr long TK_ERROR_INTERNAL = 1005;
constexpr long TK_ERROR_SCAN = 1006;

constexpr uint8_t TK_OBJECT_PE = 1;
constexpr uint8_t TK_OBJECT_PYTHON_SCRIPT = 2;
constexpr uint8_t TK_OBJECT_JAVASCRIPT = 3;

// Учебное ограничение для доп. функции сканирования всех несъемных дисков.
// Без этого GUI может долго ждать ответ RPC, если на компьютере несколько больших дисков.
constexpr long kFixedDriveMaxFilesPerDrive = 500;
constexpr uintmax_t kFixedDriveMaxFileSizeBytes = 10ULL * 1024ULL * 1024ULL;

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stopEvent = nullptr;
std::thread g_refreshThread;
std::mutex g_processesMutex;
std::mutex g_stateMutex;

struct TrayProcess {
    DWORD sessionId = 0;
    PROCESS_INFORMATION processInfo{};
};

struct LicenseState {
    bool active = false;
    std::wstring expiresAt;
    std::wstring message = L"Лицензия отсутствует";
    std::chrono::system_clock::time_point refreshAt{};
};

struct AvRecord {
    uint64_t objectSignaturePrefix = 0;
    uint32_t objectSignatureLength = 0;
    std::vector<uint8_t> objectSignature;
    uint64_t offsetBegin = 0;
    uint64_t offsetEnd = 0;
    uint8_t objectType = 0;
    std::vector<uint8_t> avRecordSignature;
    std::wstring name;
};

struct AvDatabaseState {
    bool loaded = false;
    std::wstring releaseDate;
    std::wstring message = L"Антивирусные базы не загружены";
    size_t recordCount = 0;
    std::map<uint64_t, std::vector<AvRecord>> records;
};

struct ScanResultState {
    long scannedObjects = 0;
    long infectedObjects = 0;
    bool clean = true;
    std::wstring details;
};

struct AuthState {
    bool authenticated = false;
    std::wstring username;
    std::string accessToken;
    std::string refreshToken;
    std::chrono::system_clock::time_point accessExpiresAt{};
    std::chrono::system_clock::time_point refreshExpiresAt{};
    LicenseState license;
};

std::vector<TrayProcess> g_trayProcesses;
AuthState g_authState;
AvDatabaseState g_avDatabase;
std::chrono::system_clock::time_point g_nextAvDatabaseUpdateAt{};

std::mutex g_monitorMutex;
std::thread g_monitorThread;
HANDLE g_monitorStopEvent = nullptr;
bool g_monitorRunning = false;
std::wstring g_monitorPath;
ScanResultState g_monitorResult;

std::mutex g_scheduleMutex;
std::thread g_scheduleThread;
HANDLE g_scheduleStopEvent = nullptr;
bool g_scheduleRunning = false;
std::wstring g_schedulePath;
long g_scheduleIntervalSeconds = 60;
ScanResultState g_scheduleResult;

std::filesystem::path GetServiceDirectory() {
    wchar_t modulePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    return std::filesystem::path(modulePath).parent_path();
}

void FillRpcScanResult(const ScanResultState& state, long status, const std::wstring& fallback, TK_SCAN_RESULT* result);

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

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size > 0 ? size - 1 : 0, '\0');
    if (size > 1) WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    std::wstring result(size > 0 ? size - 1 : 0, L'\0');
    if (size > 1) MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), size);
    return result;
}

std::string JsonEscape(const std::wstring& value) {
    std::string input = WideToUtf8(value);
    std::string out;
    out.reserve(input.size() + 8);
    for (char ch : input) {
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out += ch; break;
        }
    }
    return out;
}

wchar_t* RpcDuplicateString(const std::wstring& value) {
    const size_t bytes = (value.size() + 1) * sizeof(wchar_t);
    auto* target = static_cast<wchar_t*>(midl_user_allocate(bytes));
    if (!target) return nullptr;
    memcpy(target, value.c_str(), bytes);
    return target;
}

std::string ExtractJsonString(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return {};
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return {};
    std::string result;
    bool escaped = false;
    for (size_t i = pos + 1; i < json.size(); ++i) {
        const char ch = json[i];
        if (escaped) {
            switch (ch) {
            case 'n': result += '\n'; break;
            case 'r': result += '\r'; break;
            case 't': result += '\t'; break;
            default: result += ch; break;
            }
            escaped = false;
        } else if (ch == '\\') {
            escaped = true;
        } else if (ch == '"') {
            break;
        } else {
            result += ch;
        }
    }
    return result;
}

long long ExtractJsonInt64(const std::string& json, const std::string& key, long long fallback = 0) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return fallback;
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return fallback;
    ++pos;
    while (pos < json.size() && isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    size_t end = pos;
    while (end < json.size() && (isdigit(static_cast<unsigned char>(json[end])) || json[end] == '-')) ++end;
    if (end == pos) return fallback;
    try { return std::stoll(json.substr(pos, end - pos)); } catch (...) { return fallback; }
}

std::wstring ExtractJsonBoolText(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return L"";
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return L"";
    ++pos;
    while (pos < json.size() && isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    if (json.compare(pos, 4, "true") == 0) return L"true";
    if (json.compare(pos, 5, "false") == 0) return L"false";
    return L"";
}

std::string Base64UrlDecode(const std::string& input) {
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64 = input;
    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');
    while (b64.size() % 4) b64.push_back('=');

    std::string out;
    int val = 0;
    int valb = -8;
    for (unsigned char c : b64) {
        if (c == '=') break;
        const char* p = strchr(kAlphabet, c);
        if (!p) continue;
        val = (val << 6) + static_cast<int>(p - kAlphabet);
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::chrono::system_clock::time_point DecodeJwtExpiration(const std::string& token) {
    const size_t firstDot = token.find('.');
    if (firstDot == std::string::npos) return {};
    const size_t secondDot = token.find('.', firstDot + 1);
    if (secondDot == std::string::npos) return {};
    const std::string payload = Base64UrlDecode(token.substr(firstDot + 1, secondDot - firstDot - 1));
    const long long exp = ExtractJsonInt64(payload, "exp", 0);
    if (exp <= 0) return std::chrono::system_clock::now() + std::chrono::minutes(10);
    return std::chrono::system_clock::from_time_t(static_cast<time_t>(exp));
}

std::wstring GetDeviceName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    if (GetComputerNameW(buffer, &size)) return buffer;
    return L"Windows device";
}

std::wstring GetDeviceMac() {
    // Stable device identifier for the training server. The server stores this
    // value in the deviceMac field, but it only requires a unique string.
    // Avoid IP Helper APIs here so the project builds on older Windows SDKs.
    std::wstring name = GetDeviceName();
    for (wchar_t& ch : name) {
        if (ch == L' ' || ch == L'\\' || ch == L'/' || ch == L':' || ch == L';') ch = L'-';
    }
    return L"DEVICE-" + name;
}



uint64_t ReadPrefix(const uint8_t* bytes) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) value |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    return value;
}

uint64_t Fnva64(const uint8_t* data, size_t size) {
    uint64_t hash = 1469598103934665603ull;
    for (size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

std::vector<uint8_t> UInt64ToBytes(uint64_t value) {
    std::vector<uint8_t> bytes(8);
    for (int i = 0; i < 8; ++i) bytes[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    return bytes;
}

std::vector<uint8_t> HashSignature(const std::vector<uint8_t>& signature) {
    return UInt64ToBytes(Fnva64(signature.data(), signature.size()));
}

void AppendUInt64(std::vector<uint8_t>& target, uint64_t value) {
    for (int i = 0; i < 8; ++i) target.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
}

void AppendUInt32(std::vector<uint8_t>& target, uint32_t value) {
    for (int i = 0; i < 4; ++i) target.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
}

std::vector<uint8_t> SignRecordForTraining(const AvRecord& record) {
    std::vector<uint8_t> data;
    AppendUInt64(data, record.objectSignaturePrefix);
    AppendUInt32(data, record.objectSignatureLength);
    data.insert(data.end(), record.objectSignature.begin(), record.objectSignature.end());
    AppendUInt64(data, record.offsetBegin);
    AppendUInt64(data, record.offsetEnd);
    data.push_back(record.objectType);
    return UInt64ToBytes(Fnva64(data.data(), data.size()));
}

AvRecord MakeAvRecord(const char* name, const char* signature, uint64_t offsetBegin, uint64_t offsetEnd, uint8_t objectType) {
    std::vector<uint8_t> bytes(signature, signature + strlen(signature));
    AvRecord record;
    record.objectSignaturePrefix = bytes.size() >= 8 ? ReadPrefix(bytes.data()) : 0;
    record.objectSignatureLength = static_cast<uint32_t>(bytes.size());
    record.objectSignature = HashSignature(bytes);
    record.offsetBegin = offsetBegin;
    record.offsetEnd = offsetEnd;
    record.objectType = objectType;
    record.name = Utf8ToWide(name);
    record.avRecordSignature = SignRecordForTraining(record);
    return record;
}

std::wstring FormatCurrentDate() {
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t buffer[32]{};
    StringCchPrintfW(buffer, std::size(buffer), L"%04u-%02u-%02u", time.wYear, time.wMonth, time.wDay);
    return buffer;
}

void AddAvRecordLocked(const AvRecord& record) {
    g_avDatabase.records[record.objectSignaturePrefix].push_back(record);
    ++g_avDatabase.recordCount;
}

void ClearAvDatabaseLocked(const std::wstring& message = L"Антивирусные базы не загружены") {
    g_avDatabase = AvDatabaseState{};
    g_avDatabase.message = message;
}


std::vector<AvRecord> BuildDefaultAvRecords() {
    std::vector<AvRecord> records;
    records.push_back(MakeAvRecord("Training.Script.EICAR", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE", 0, 4096, TK_OBJECT_PYTHON_SCRIPT));
    records.push_back(MakeAvRecord("Training.JavaScript.EICAR", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE", 0, 4096, TK_OBJECT_JAVASCRIPT));
    records.push_back(MakeAvRecord("Training.PE.Marker", "MZTRAYKEEPER-TRAINING-MALWARE", 0, 1024, TK_OBJECT_PE));
    return records;
}

std::filesystem::path GetAvDatabaseDirectory() {
    return GetServiceDirectory() / L"avdb";
}

std::filesystem::path GetActiveAvDatabasePath() {
    return GetAvDatabaseDirectory() / L"active.tkavdb";
}

std::filesystem::path GetBackupAvDatabasePath() {
    return GetAvDatabaseDirectory() / L"backup.tkavdb";
}

std::filesystem::path GetDefaultAvDatabasePath() {
    return GetAvDatabaseDirectory() / L"default.tkavdb";
}

void AppendBytes(std::vector<uint8_t>& target, const std::vector<uint8_t>& value) {
    target.insert(target.end(), value.begin(), value.end());
}

void AppendUInt8(std::vector<uint8_t>& target, uint8_t value) {
    target.push_back(value);
}

void AppendStringUtf8(std::vector<uint8_t>& target, const std::wstring& value) {
    const std::string utf8 = WideToUtf8(value);
    AppendUInt32(target, static_cast<uint32_t>(utf8.size()));
    target.insert(target.end(), utf8.begin(), utf8.end());
}

bool ReadUInt8(const std::vector<uint8_t>& data, size_t& pos, uint8_t& value) {
    if (pos + 1 > data.size()) return false;
    value = data[pos++];
    return true;
}

bool ReadUInt32(const std::vector<uint8_t>& data, size_t& pos, uint32_t& value) {
    if (pos + 4 > data.size()) return false;
    value = 0;
    for (int i = 0; i < 4; ++i) value |= static_cast<uint32_t>(data[pos++]) << (i * 8);
    return true;
}

bool ReadUInt64(const std::vector<uint8_t>& data, size_t& pos, uint64_t& value) {
    if (pos + 8 > data.size()) return false;
    value = 0;
    for (int i = 0; i < 8; ++i) value |= static_cast<uint64_t>(data[pos++]) << (i * 8);
    return true;
}

bool ReadBytes(const std::vector<uint8_t>& data, size_t& pos, uint32_t size, std::vector<uint8_t>& value) {
    if (pos + size > data.size()) return false;
    value.assign(data.begin() + static_cast<ptrdiff_t>(pos), data.begin() + static_cast<ptrdiff_t>(pos + size));
    pos += size;
    return true;
}

bool ReadStringUtf8(const std::vector<uint8_t>& data, size_t& pos, std::wstring& value) {
    uint32_t size = 0;
    if (!ReadUInt32(data, pos, size)) return false;
    if (size > 4096 || pos + size > data.size()) return false;
    std::string utf8(data.begin() + static_cast<ptrdiff_t>(pos), data.begin() + static_cast<ptrdiff_t>(pos + size));
    pos += size;
    value = Utf8ToWide(utf8);
    return true;
}

std::vector<uint8_t> SerializeRecordPayload(const AvRecord& record) {
    std::vector<uint8_t> data;
    AppendUInt64(data, record.objectSignaturePrefix);
    AppendUInt32(data, record.objectSignatureLength);
    AppendUInt32(data, static_cast<uint32_t>(record.objectSignature.size()));
    AppendBytes(data, record.objectSignature);
    AppendUInt64(data, record.offsetBegin);
    AppendUInt64(data, record.offsetEnd);
    AppendUInt8(data, record.objectType);
    AppendStringUtf8(data, record.name);
    return data;
}

std::vector<uint8_t> SerializeRecordWithSignature(const AvRecord& record) {
    std::vector<uint8_t> data = SerializeRecordPayload(record);
    AppendUInt32(data, static_cast<uint32_t>(record.avRecordSignature.size()));
    AppendBytes(data, record.avRecordSignature);
    return data;
}

uint64_t ComputeManifestSignature(uint32_t version, uint64_t releaseUnix, uint32_t recordCount, uint64_t recordsHash) {
    std::vector<uint8_t> data;
    const char magic[8] = {'T','K','A','V','D','B','1','\0'};
    data.insert(data.end(), magic, magic + 8);
    AppendUInt32(data, version);
    AppendUInt64(data, releaseUnix);
    AppendUInt32(data, recordCount);
    AppendUInt64(data, recordsHash);
    const char key[] = "TrayKeeperTrainingManifestSignatureKey";
    data.insert(data.end(), key, key + strlen(key));
    return Fnva64(data.data(), data.size());
}

uint64_t CurrentUnixTime() {
    return static_cast<uint64_t>(std::time(nullptr));
}

std::wstring FormatUnixDate(uint64_t unixTime) {
    std::time_t value = static_cast<std::time_t>(unixTime);
    std::tm tmValue{};
    localtime_s(&tmValue, &value);
    wchar_t buffer[32]{};
    StringCchPrintfW(buffer, std::size(buffer), L"%04d-%02d-%02d", tmValue.tm_year + 1900, tmValue.tm_mon + 1, tmValue.tm_mday);
    return buffer;
}

bool WriteAvDatabaseFile(const std::filesystem::path& path, const std::vector<AvRecord>& records, uint64_t releaseUnix) {
    try {
        std::filesystem::create_directories(path.parent_path());
        std::vector<uint8_t> recordsPayload;
        for (const AvRecord& record : records) {
            AppendBytes(recordsPayload, SerializeRecordWithSignature(record));
        }

        constexpr uint32_t version = 1;
        const uint32_t recordCount = static_cast<uint32_t>(records.size());
        const uint64_t recordsHash = Fnva64(recordsPayload.data(), recordsPayload.size());
        const uint64_t manifestSignature = ComputeManifestSignature(version, releaseUnix, recordCount, recordsHash);

        std::vector<uint8_t> file;
        const char magic[8] = {'T','K','A','V','D','B','1','\0'};
        file.insert(file.end(), magic, magic + 8);
        AppendUInt32(file, version);
        AppendUInt64(file, releaseUnix);
        AppendUInt32(file, recordCount);
        AppendUInt64(file, recordsHash);
        AppendUInt64(file, manifestSignature);
        AppendBytes(file, recordsPayload);

        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        if (!stream) return false;
        stream.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
        return static_cast<bool>(stream);
    } catch (...) {
        return false;
    }
}

bool LoadAvDatabaseFileLocked(const std::filesystem::path& path, const std::wstring& sourceMessage) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return false;
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    if (data.size() < 40) return false;

    size_t pos = 0;
    const char expectedMagic[8] = {'T','K','A','V','D','B','1','\0'};
    if (memcmp(data.data(), expectedMagic, 8) != 0) return false;
    pos += 8;

    uint32_t version = 0;
    uint64_t releaseUnix = 0;
    uint32_t recordCount = 0;
    uint64_t recordsHash = 0;
    uint64_t manifestSignature = 0;
    if (!ReadUInt32(data, pos, version) || !ReadUInt64(data, pos, releaseUnix) || !ReadUInt32(data, pos, recordCount) ||
        !ReadUInt64(data, pos, recordsHash) || !ReadUInt64(data, pos, manifestSignature)) {
        return false;
    }
    if (version != 1 || recordCount > 100000) return false;

    const uint64_t expectedManifestSignature = ComputeManifestSignature(version, releaseUnix, recordCount, recordsHash);
    if (manifestSignature != expectedManifestSignature) {
        WriteLog(L"AV database manifest signature verification failed: " + path.wstring());
        return false;
    }

    const size_t recordsStart = pos;
    const uint64_t actualRecordsHash = Fnva64(data.data() + recordsStart, data.size() - recordsStart);
    if (actualRecordsHash != recordsHash) {
        // The manifest-level integrity hash is checked and logged, but corrupted
        // record payloads are still parsed so that per-record EDS verification can
        // skip only bad records and keep the rest of the AV database available.
        WriteLog(L"AV database records hash mismatch; validating records individually: " + path.wstring());
    }

    AvDatabaseState loaded;
    loaded.loaded = true;
    loaded.releaseDate = FormatUnixDate(releaseUnix);
    loaded.message = sourceMessage;

    for (uint32_t i = 0; i < recordCount; ++i) {
        AvRecord record;
        uint32_t signatureHashSize = 0;
        uint32_t recordSignatureSize = 0;
        if (!ReadUInt64(data, pos, record.objectSignaturePrefix) ||
            !ReadUInt32(data, pos, record.objectSignatureLength) ||
            !ReadUInt32(data, pos, signatureHashSize) ||
            !ReadBytes(data, pos, signatureHashSize, record.objectSignature) ||
            !ReadUInt64(data, pos, record.offsetBegin) ||
            !ReadUInt64(data, pos, record.offsetEnd) ||
            !ReadUInt8(data, pos, record.objectType) ||
            !ReadStringUtf8(data, pos, record.name) ||
            !ReadUInt32(data, pos, recordSignatureSize) ||
            !ReadBytes(data, pos, recordSignatureSize, record.avRecordSignature)) {
            WriteLog(L"AV database record parse failed, loading stopped: " + path.wstring());
            break;
        }

        if (record.avRecordSignature != SignRecordForTraining(record)) {
            WriteLog(L"AV database record signature verification failed; record skipped: " + record.name);
            continue;
        }
        loaded.records[record.objectSignaturePrefix].push_back(record);
        ++loaded.recordCount;
    }

    g_avDatabase = std::move(loaded);
    g_nextAvDatabaseUpdateAt = std::chrono::system_clock::now() + std::chrono::minutes(1);
    return g_avDatabase.recordCount > 0;
}

bool BackupActiveAvDatabase() {
    try {
        const auto active = GetActiveAvDatabasePath();
        const auto backup = GetBackupAvDatabasePath();
        if (!std::filesystem::exists(active)) return true;
        std::filesystem::create_directories(backup.parent_path());
        std::filesystem::copy_file(active, backup, std::filesystem::copy_options::overwrite_existing);
        return true;
    } catch (...) {
        return false;
    }
}

bool RestoreAvDatabaseBackup() {
    try {
        const auto active = GetActiveAvDatabasePath();
        const auto backup = GetBackupAvDatabasePath();
        if (!std::filesystem::exists(backup)) return false;
        std::filesystem::copy_file(backup, active, std::filesystem::copy_options::overwrite_existing);
        return true;
    } catch (...) {
        return false;
    }
}

bool EnsureDefaultAvDatabaseFile() {
    const auto defaultPath = GetDefaultAvDatabasePath();
    if (std::filesystem::exists(defaultPath)) return true;
    return WriteAvDatabaseFile(defaultPath, BuildDefaultAvRecords(), CurrentUnixTime());
}

bool HasNetworkAccessForAvUpdate() {
    // Учебная проверка доступности сети: сервер лицензирования уже используется службой через HTTPS.
    // Если пользователь вошёл и есть Access Token, считаем, что можно выполнить принудительное обновление базы.
    return g_authState.authenticated && !g_authState.accessToken.empty();
}

bool WriteUpdatedAvDatabaseFromTrainingProvider() {
    // В учебном проекте нет отдельного эндпоинта обновлений AV-баз, поэтому обновление моделируется
    // локальным поставщиком: создаётся новая подписанная бинарная база в том же формате.
    std::vector<AvRecord> records = BuildDefaultAvRecords();
    records.push_back(MakeAvRecord("Training.PowerShell.EICAR", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE", 0, 4096, TK_OBJECT_PYTHON_SCRIPT));
    return WriteAvDatabaseFile(GetActiveAvDatabasePath(), records, CurrentUnixTime());
}

bool LoadDefaultAvDatabaseLocked() {
    EnsureDefaultAvDatabaseFile();
    if (LoadAvDatabaseFileLocked(GetDefaultAvDatabasePath(), L"Загружены антивирусные базы по умолчанию")) {
        try { std::filesystem::copy_file(GetDefaultAvDatabasePath(), GetActiveAvDatabasePath(), std::filesystem::copy_options::overwrite_existing); } catch (...) {}
        return true;
    }

    ClearAvDatabaseLocked();
    g_avDatabase.loaded = true;
    g_avDatabase.releaseDate = FormatCurrentDate();
    g_avDatabase.message = L"Загружены встроенные антивирусные базы по умолчанию";
    for (const AvRecord& record : BuildDefaultAvRecords()) AddAvRecordLocked(record);
    g_nextAvDatabaseUpdateAt = std::chrono::system_clock::now() + std::chrono::minutes(1);
    return true;
}

bool LoadAvDatabaseFromDiskOrRecoveryLocked() {
    ClearAvDatabaseLocked(L"Антивирусные базы загружаются с диска");
    EnsureDefaultAvDatabaseFile();

    if (LoadAvDatabaseFileLocked(GetActiveAvDatabasePath(), L"Антивирусные базы загружены с диска")) {
        return true;
    }

    if (HasNetworkAccessForAvUpdate()) {
        WriteLog(L"Active AV database is invalid. Trying forced update because network/auth is available.");
        BackupActiveAvDatabase();
        if (WriteUpdatedAvDatabaseFromTrainingProvider() && LoadAvDatabaseFileLocked(GetActiveAvDatabasePath(), L"Антивирусные базы принудительно обновлены после ошибки проверки")) {
            return true;
        }
    }

    if (RestoreAvDatabaseBackup() && LoadAvDatabaseFileLocked(GetActiveAvDatabasePath(), L"Антивирусные базы восстановлены из резервной копии")) {
        return true;
    }

    return LoadDefaultAvDatabaseLocked();
}

void LoadAvDatabaseLocked() {
    LoadAvDatabaseFromDiskOrRecoveryLocked();
}

bool UpdateAvDatabaseFromSchedule() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    if (!g_authState.authenticated || !g_authState.license.active) return false;

    WriteLog(L"Scheduled AV database update started.");
    BackupActiveAvDatabase();
    if (WriteUpdatedAvDatabaseFromTrainingProvider() && LoadAvDatabaseFileLocked(GetActiveAvDatabasePath(), L"Антивирусные базы обновлены по расписанию")) {
        WriteLog(L"Scheduled AV database update completed.");
        return true;
    }

    WriteLog(L"Scheduled AV database update failed. Rolling back from backup.");
    if (RestoreAvDatabaseBackup() && LoadAvDatabaseFileLocked(GetActiveAvDatabasePath(), L"Антивирусные базы восстановлены после ошибки обновления")) {
        return false;
    }

    LoadDefaultAvDatabaseLocked();
    return false;
}

std::wstring ToLowerCopy(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
    return value;
}

uint8_t DetectObjectType(const std::filesystem::path& path, const std::vector<uint8_t>& data) {
    const std::wstring ext = ToLowerCopy(path.extension().wstring());
    if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') return TK_OBJECT_PE;
    if (ext == L".exe" || ext == L".dll" || ext == L".sys") return TK_OBJECT_PE;
    if (ext == L".py" || ext == L".pyw") return TK_OBJECT_PYTHON_SCRIPT;
    if (ext == L".js" || ext == L".mjs" || ext == L".cjs") return TK_OBJECT_JAVASCRIPT;
    return 0;
}

bool EngineScanBytes(const std::vector<uint8_t>& data, uint8_t objectType, std::wstring& detectionName) {
    if (!g_avDatabase.loaded || data.size() < 8 || objectType == 0) return false;

    for (uint64_t position = 0; position + 8 <= data.size(); ++position) {
        const uint64_t prefix = ReadPrefix(data.data() + position);
        const auto found = g_avDatabase.records.find(prefix);
        if (found == g_avDatabase.records.end()) continue;

        for (const AvRecord& record : found->second) {
            // Проверки идут от дешёвых к дорогим, как в задании.
            if (record.objectType != objectType) continue;
            if (position < record.offsetBegin || position > record.offsetEnd) continue;
            if (record.objectSignatureLength < 8) continue;
            if (position + record.objectSignatureLength > data.size()) continue;

            std::vector<uint8_t> candidate(data.begin() + static_cast<ptrdiff_t>(position), data.begin() + static_cast<ptrdiff_t>(position + record.objectSignatureLength));
            const std::vector<uint8_t> candidateHash = HashSignature(candidate);
            if (candidateHash == record.objectSignature) {
                detectionName = record.name;
                return true;
            }
        }
    }
    return false;
}

long EnsureAvAvailableLocked() {
    if (!g_authState.authenticated) return TK_ERROR_AUTH;
    if (!g_authState.license.active) return TK_ERROR_NO_LICENSE;
    if (!g_avDatabase.loaded) LoadAvDatabaseLocked();
    return TK_OK;
}

std::wstring ObjectTypeName(uint8_t type) {
    switch (type) {
    case TK_OBJECT_PE: return L"PE";
    case TK_OBJECT_PYTHON_SCRIPT: return L"Python Script";
    case TK_OBJECT_JAVASCRIPT: return L"JavaScript";
    default: return L"Unknown";
    }
}

long ScanSingleFileInternal(const std::filesystem::path& path, ScanResultState& result) {
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        const long available = EnsureAvAvailableLocked();
        if (available != TK_OK) return available;
    }

    std::ifstream stream(path, std::ios::binary);
    if (!stream) return TK_ERROR_SCAN;
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    ++result.scannedObjects;

    const uint8_t objectType = DetectObjectType(path, data);
    std::wstring detectionName;
    bool infected = false;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        infected = EngineScanBytes(data, objectType, detectionName);
    }

    if (infected) {
        ++result.infectedObjects;
        result.clean = false;
        result.details += L"Угроза: " + path.wstring() + L" [" + detectionName + L", " + ObjectTypeName(objectType) + L"]\r\n";
    }
    return TK_OK;
}

std::wstring BuildScanSummary(const ScanResultState& result) {
    std::wstringstream summary;
    summary << L"Проверено объектов: " << result.scannedObjects << L"\r\n";
    summary << L"Найдено угроз: " << result.infectedObjects << L"\r\n";
    if (result.details.empty()) summary << L"Угрозы не найдены.";
    else summary << result.details;
    return summary.str();
}

void FillRpcScanResult(const ScanResultState& state, long status, const std::wstring& fallback, TK_SCAN_RESULT* result) {
    if (!result) return;
    result->scannedObjects = state.scannedObjects;
    result->infectedObjects = state.infectedObjects;
    result->clean = (status == TK_OK && state.infectedObjects == 0) ? 1 : 0;
    ScanResultState copy = state;
    if (status != TK_OK && copy.details.empty()) copy.details = fallback;
    result->details = RpcDuplicateString(BuildScanSummary(copy));
}

struct HttpResult {
    DWORD status = 0;
    std::string body;
};

HttpResult HttpsPost(const wchar_t* path, const std::string& body, const std::string& bearerToken = {}) {
    HttpResult result;
    HINTERNET session = WinHttpOpen(L"TrayKeeperService/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return result;

    HINTERNET connection = WinHttpConnect(session, kServerHost, kServerPort, 0);
    if (!connection) {
        WinHttpCloseHandle(session);
        return result;
    }

    HINTERNET request = WinHttpOpenRequest(connection, L"POST", path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!request) {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return result;
    }

    DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    if (!bearerToken.empty()) {
        headers += L"Authorization: Bearer " + Utf8ToWide(bearerToken) + L"\r\n";
    }

    const BOOL sent = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0);

    if (sent && WinHttpReceiveResponse(request, nullptr)) {
        DWORD statusSize = sizeof(result.status);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &result.status, &statusSize, WINHTTP_NO_HEADER_INDEX);

        DWORD available = 0;
        while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
            std::string chunk(available, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(request, chunk.data(), available, &read) || read == 0) break;
            chunk.resize(read);
            result.body += chunk;
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return result;
}

LicenseState ParseTicketResponse(const std::string& body) {
    LicenseState license;
    const std::wstring blockedText = ExtractJsonBoolText(body, "blocked");
    license.expiresAt = Utf8ToWide(ExtractJsonString(body, "endingDate"));
    const long long lifetime = ExtractJsonInt64(body, "ticketLifetimeSeconds", 3600);
    license.active = blockedText != L"true" && !license.expiresAt.empty();
    license.message = license.active ? L"Лицензия активна" : L"Лицензия неактивна";

    long long refreshSeconds = std::max<long long>(30, lifetime - 60);
    license.refreshAt = std::chrono::system_clock::now() + std::chrono::seconds(refreshSeconds);
    return license;
}

void ClearLicenseLocked(const std::wstring& message = L"Лицензия отсутствует") {
    g_authState.license = LicenseState{};
    g_authState.license.message = message;
    ClearAvDatabaseLocked(L"Антивирусные базы выгружены: нет активной лицензии");
}

void ClearAuthLocked() {
    g_authState = AuthState{};
    ClearAvDatabaseLocked(L"Антивирусные базы выгружены: пользователь вышел из аккаунта");
}

long RefreshTokens() {
    std::string refreshToken;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        refreshToken = g_authState.refreshToken;
    }
    if (refreshToken.empty()) return TK_ERROR_AUTH;

    const std::string body = "{\"refreshToken\":\"" + refreshToken + "\"}";
    const HttpResult response = HttpsPost(L"/api/auth/refresh", body);
    if (response.status != 200) {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        ClearAuthLocked();
        WriteLog(L"Refresh token rejected; user logged out in memory");
        return TK_ERROR_AUTH;
    }

    const std::string access = ExtractJsonString(response.body, "accessToken");
    const std::string refresh = ExtractJsonString(response.body, "refreshToken");
    if (access.empty() || refresh.empty()) return TK_ERROR_INTERNAL;

    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_authState.accessToken = access;
    g_authState.refreshToken = refresh;
    g_authState.accessExpiresAt = DecodeJwtExpiration(access);
    g_authState.refreshExpiresAt = DecodeJwtExpiration(refresh);
    return TK_OK;
}

long CheckLicenseNow() {
    std::string accessToken;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (!g_authState.authenticated || g_authState.accessToken.empty()) return TK_ERROR_AUTH;
        accessToken = g_authState.accessToken;
    }

    const std::string body = "{\"deviceMac\":\"" + JsonEscape(GetDeviceMac()) + "\",\"productId\":" + std::to_string(kProductId) + "}";
    const HttpResult response = HttpsPost(L"/api/licenses/check", body, accessToken);
    if (response.status == 401) {
        const long refreshStatus = RefreshTokens();
        if (refreshStatus != TK_OK) return refreshStatus;
        std::lock_guard<std::mutex> lock(g_stateMutex);
        accessToken = g_authState.accessToken;
    }

    const HttpResult finalResponse = response.status == 401
        ? HttpsPost(L"/api/licenses/check", body, accessToken)
        : response;

    std::lock_guard<std::mutex> lock(g_stateMutex);
    if (finalResponse.status == 200) {
        g_authState.license = ParseTicketResponse(finalResponse.body);
        if (g_authState.license.active && !g_avDatabase.loaded) LoadAvDatabaseLocked();
        if (!g_authState.license.active) ClearAvDatabaseLocked(L"Антивирусные базы выгружены: лицензия неактивна");
        return g_authState.license.active ? TK_OK : TK_ERROR_NO_LICENSE;
    }

    ClearLicenseLocked(L"Лицензия отсутствует или истекла");
    return TK_ERROR_NO_LICENSE;
}

long LoginNow(const std::wstring& username, const std::wstring& password) {
    const std::string body = "{\"username\":\"" + JsonEscape(username) + "\",\"password\":\"" + JsonEscape(password) + "\"}";
    const HttpResult response = HttpsPost(L"/api/auth/login", body);
    if (response.status == 0) return TK_ERROR_NETWORK;
    if (response.status != 200) return TK_ERROR_AUTH;

    const std::string access = ExtractJsonString(response.body, "accessToken");
    const std::string refresh = ExtractJsonString(response.body, "refreshToken");
    if (access.empty() || refresh.empty()) return TK_ERROR_INTERNAL;

    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_authState.authenticated = true;
    g_authState.username = username;
    g_authState.accessToken = access;
    g_authState.refreshToken = refresh;
    g_authState.accessExpiresAt = DecodeJwtExpiration(access);
    g_authState.refreshExpiresAt = DecodeJwtExpiration(refresh);
    ClearLicenseLocked();
    return TK_OK;
}

long ActivateLicenseNow(const std::wstring& code) {
    std::string accessToken;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (!g_authState.authenticated || g_authState.accessToken.empty()) return TK_ERROR_AUTH;
        accessToken = g_authState.accessToken;
    }

    const std::wstring deviceMac = GetDeviceMac();
    const std::wstring deviceName = GetDeviceName();
    const std::string body = "{\"code\":\"" + JsonEscape(code) + "\",\"deviceMac\":\"" + JsonEscape(deviceMac) + "\",\"deviceName\":\"" + JsonEscape(deviceName) + "\"}";
    HttpResult response = HttpsPost(L"/api/licenses/activate", body, accessToken);
    if (response.status == 401 && RefreshTokens() == TK_OK) {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        response = HttpsPost(L"/api/licenses/activate", body, g_authState.accessToken);
    }

    if (response.status == 200) {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        g_authState.license = ParseTicketResponse(response.body);
        if (g_authState.license.active) {
            LoadAvDatabaseLocked();
            return TK_OK;
        }
    }

    const long checkStatus = CheckLicenseNow();
    return checkStatus == TK_OK ? TK_OK : TK_ERROR_ACTIVATION;
}

void RefreshWorker() {
    while (WaitForSingleObject(g_stopEvent, 5000) == WAIT_TIMEOUT) {
        bool shouldRefreshToken = false;
        bool shouldRefreshLicense = false;
        bool shouldUpdateAvDatabase = false;
        {
            std::lock_guard<std::mutex> lock(g_stateMutex);
            if (!g_authState.authenticated) continue;
            const auto now = std::chrono::system_clock::now();
            shouldRefreshToken = g_authState.accessExpiresAt.time_since_epoch().count() != 0 && now + std::chrono::seconds(60) >= g_authState.accessExpiresAt;
            shouldRefreshLicense = g_authState.license.active && g_authState.license.refreshAt.time_since_epoch().count() != 0 && now >= g_authState.license.refreshAt;
            shouldUpdateAvDatabase = g_authState.license.active && g_nextAvDatabaseUpdateAt.time_since_epoch().count() != 0 && now >= g_nextAvDatabaseUpdateAt;
        }

        if (shouldRefreshToken) RefreshTokens();
        if (shouldRefreshLicense) CheckLicenseNow();
        if (shouldUpdateAvDatabase) UpdateAvDatabaseFromSchedule();
    }
}

void SetServiceStatusState(DWORD state, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = win32ExitCode;
    g_status.dwWaitHint = waitHint;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_STOP : 0;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ++g_status.dwCheckPoint; else g_status.dwCheckPoint = 0;
    if (g_statusHandle) SetServiceStatus(g_statusHandle, &g_status);
}

std::filesystem::path GetTrayAppPath() { return GetServiceDirectory() / L"TrayKeeper.exe"; }

void RemoveExitedProcessesLocked() {
    g_trayProcesses.erase(std::remove_if(g_trayProcesses.begin(), g_trayProcesses.end(), [](TrayProcess& process) {
        const DWORD wait = WaitForSingleObject(process.processInfo.hProcess, 0);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED) {
            CloseHandle(process.processInfo.hThread);
            CloseHandle(process.processInfo.hProcess);
            return true;
        }
        return false;
    }), g_trayProcesses.end());
}

bool IsSessionAlreadyStartedLocked(DWORD sessionId) {
    RemoveExitedProcessesLocked();
    return std::any_of(g_trayProcesses.begin(), g_trayProcesses.end(), [sessionId](const TrayProcess& process) { return process.sessionId == sessionId; });
}

bool LaunchTrayForSession(DWORD sessionId) {
    if (sessionId == 0) return false;
    {
        std::lock_guard<std::mutex> lock(g_processesMutex);
        if (IsSessionAlreadyStartedLocked(sessionId)) return true;
    }

    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &userToken)) { LogLastError(L"WTSQueryUserToken"); return false; }

    HANDLE primaryToken = nullptr;
    const BOOL duplicated = DuplicateTokenEx(userToken, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, nullptr, SecurityImpersonation, TokenPrimary, &primaryToken);
    CloseHandle(userToken);
    if (!duplicated) { LogLastError(L"DuplicateTokenEx"); return false; }

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

    BOOL created = CreateProcessAsUserW(primaryToken, appPath.c_str(), mutableCommandLine.data(), nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT, environment, appPath.parent_path().c_str(), &startupInfo, &processInfo);
    if (!created) {
        LogLastError(L"CreateProcessAsUserW");
        created = CreateProcessWithTokenW(primaryToken, LOGON_WITH_PROFILE, appPath.c_str(), mutableCommandLine.data(), CREATE_UNICODE_ENVIRONMENT, environment, appPath.parent_path().c_str(), &startupInfo, &processInfo);
        if (!created) LogLastError(L"CreateProcessWithTokenW");
    }

    if (environment) DestroyEnvironmentBlock(environment);
    CloseHandle(primaryToken);
    if (!created) return false;

    std::lock_guard<std::mutex> lock(g_processesMutex);
    g_trayProcesses.push_back({ sessionId, processInfo });
    WriteLog(L"Started TrayKeeper.exe for session " + std::to_wstring(sessionId));
    return true;
}

void LaunchTrayForAllLoggedOnSessions() {
    WTS_SESSION_INFOW* sessions = nullptr;
    DWORD sessionCount = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &sessionCount)) { LogLastError(L"WTSEnumerateSessionsW"); return; }
    for (DWORD i = 0; i < sessionCount; ++i) {
        if (sessions[i].SessionId != 0 && (sessions[i].State == WTSActive || sessions[i].State == WTSConnected)) LaunchTrayForSession(sessions[i].SessionId);
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
    RPC_STATUS status = RpcServerUseProtseqEpW(reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)), RPC_C_PROTSEQ_MAX_REQS_DEFAULT, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)), nullptr);
    if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) return status;
    status = RpcServerRegisterIf2(TrayKeeperControl_v1_0_s_ifspec, nullptr, nullptr, RPC_IF_ALLOW_LOCAL_ONLY, RPC_C_LISTEN_MAX_CALLS_DEFAULT, static_cast<unsigned int>(-1), nullptr);
    if (status != RPC_S_OK) return status;
    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    return status == RPC_S_ALREADY_LISTENING ? RPC_S_OK : status;
}

void StopRpcServer() {
    RpcMgmtStopServerListening(nullptr);
    RpcServerUnregisterIf(nullptr, nullptr, FALSE);
}

DWORD WINAPI ServiceControlHandler(DWORD control, DWORD eventType, LPVOID, LPVOID) {
    if (control == SERVICE_CONTROL_STOP) {
        SetServiceStatusState(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        SetEvent(g_stopEvent);
        return NO_ERROR;
    }
    if (control == SERVICE_CONTROL_SESSIONCHANGE && (eventType == WTS_SESSION_LOGON || eventType == WTS_SESSION_UNLOCK || eventType == WTS_CONSOLE_CONNECT || eventType == WTS_REMOTE_CONNECT)) {
        LaunchTrayForAllLoggedOnSessions();
    }
    return NO_ERROR;
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceControlHandler, nullptr);
    if (!g_statusHandle) return;

    SetServiceStatusState(SERVICE_START_PENDING, NO_ERROR, 3000);
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) { SetServiceStatusState(SERVICE_STOPPED, GetLastError()); return; }

    const RPC_STATUS rpcStatus = StartRpcServer();
    if (rpcStatus != RPC_S_OK) {
        WriteLog(L"RPC server failed: " + std::to_wstring(rpcStatus));
        CloseHandle(g_stopEvent);
        SetServiceStatusState(SERVICE_STOPPED, rpcStatus);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (!g_avDatabase.loaded) LoadAvDatabaseLocked();
    }

    g_refreshThread = std::thread(RefreshWorker);
    SetServiceStatusState(SERVICE_RUNNING);
    LaunchTrayForAllLoggedOnSessions();

    WaitForSingleObject(g_stopEvent, INFINITE);
    SetServiceStatusState(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    StopScheduledScanWorkerInternal();
    StopDirectoryMonitorWorkerInternal();
    StopRpcServer();
    if (g_refreshThread.joinable()) g_refreshThread.join();
    TerminateTrayProcesses();
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    SetServiceStatusState(SERVICE_STOPPED);
}

} // namespace

extern "C" void TrayKeeperStopService() {
    if (g_stopEvent) SetEvent(g_stopEvent);
}

extern "C" long TrayKeeperGetCurrentUser(TK_AUTH_INFO* info) {
    if (!info) return TK_ERROR_INTERNAL;
    std::lock_guard<std::mutex> lock(g_stateMutex);
    info->authenticated = g_authState.authenticated ? 1 : 0;
    info->username = RpcDuplicateString(g_authState.authenticated ? g_authState.username : L"");
    return TK_OK;
}

extern "C" long TrayKeeperLogin(wchar_t* username, wchar_t* password, TK_AUTH_INFO* info) {
    const long status = LoginNow(username ? username : L"", password ? password : L"");
    if (info) TrayKeeperGetCurrentUser(info);
    return status;
}

extern "C" void TrayKeeperLogout() {
    StopScheduledScanWorkerInternal();
    StopDirectoryMonitorWorkerInternal();
    std::lock_guard<std::mutex> lock(g_stateMutex);
    ClearAuthLocked();
}

extern "C" long TrayKeeperGetLicenseInfo(TK_LICENSE_INFO* info) {
    if (!info) return TK_ERROR_INTERNAL;

    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (!g_authState.authenticated) {
            info->active = 0;
            info->expiresAt = RpcDuplicateString(L"");
            info->message = RpcDuplicateString(L"User is not authenticated");
            return TK_ERROR_AUTH;
        }
    }

    // Refresh on every GUI request so manual changes on the server/database
    // are reflected in the Keeper on the next polling cycle.
    const long checkStatus = CheckLicenseNow();

    std::lock_guard<std::mutex> lock(g_stateMutex);
    info->active = g_authState.license.active ? 1 : 0;
    info->expiresAt = RpcDuplicateString(g_authState.license.expiresAt);
    info->message = RpcDuplicateString(g_authState.license.message);

    if (!g_authState.license.active) return TK_ERROR_NO_LICENSE;
    return checkStatus == TK_OK ? TK_OK : checkStatus;
}

extern "C" long TrayKeeperActivateProduct(wchar_t* activationCode, TK_LICENSE_INFO* info) {
    const long status = ActivateLicenseNow(activationCode ? activationCode : L"");
    if (info) TrayKeeperGetLicenseInfo(info);
    return status;
}

extern "C" long TrayKeeperGetAntivirusState() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    const long available = EnsureAvAvailableLocked();
    return available;
}

extern "C" long TrayKeeperGetAvDatabaseInfo(TK_AV_DATABASE_INFO* info) {
    if (!info) return TK_ERROR_INTERNAL;
    std::lock_guard<std::mutex> lock(g_stateMutex);
    const long available = EnsureAvAvailableLocked();
    info->loaded = g_avDatabase.loaded ? 1 : 0;
    info->recordCount = static_cast<long>(g_avDatabase.recordCount);
    info->releaseDate = RpcDuplicateString(g_avDatabase.releaseDate);
    info->message = RpcDuplicateString(g_avDatabase.message);
    return available;
}

extern "C" long TrayKeeperScanFile(wchar_t* path, TK_SCAN_RESULT* result) {
    if (!path || !result) return TK_ERROR_INTERNAL;
    ScanResultState state;
    const long status = ScanSingleFileInternal(std::filesystem::path(path), state);
    result->scannedObjects = state.scannedObjects;
    result->infectedObjects = state.infectedObjects;
    result->clean = (status == TK_OK && state.infectedObjects == 0) ? 1 : 0;
    if (status != TK_OK && state.details.empty()) state.details = L"Не удалось выполнить сканирование файла.";
    result->details = RpcDuplicateString(BuildScanSummary(state));
    return status;
}

bool ShouldSkipFastFixedDrivePath(const std::filesystem::path& path) {
    const std::wstring lower = ToLowerCopy(path.wstring());
    return lower.find(L"\\windows\\") != std::wstring::npos
        || lower.find(L"\\program files\\") != std::wstring::npos
        || lower.find(L"\\program files (x86)\\") != std::wstring::npos
        || lower.find(L"\\programdata\\") != std::wstring::npos
        || lower.find(L"\\system volume information\\") != std::wstring::npos
        || lower.find(L"\\$recycle.bin\\") != std::wstring::npos;
}

long ScanDirectoryPathLimitedInternal(const std::filesystem::path& directory, ScanResultState& state, long maxFiles) {
    long finalStatus = TK_OK;
    long scannedOnThisDrive = 0;
    try {
        std::error_code ec;
        std::filesystem::recursive_directory_iterator it(
            directory,
            std::filesystem::directory_options::skip_permission_denied,
            ec);
        const std::filesystem::recursive_directory_iterator end;
        for (; it != end; it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }

            const std::filesystem::path current = it->path();
            if (it->is_directory(ec)) {
                if (ShouldSkipFastFixedDrivePath(current)) {
                    it.disable_recursion_pending();
                }
                continue;
            }
            ec.clear();

            if (!it->is_regular_file(ec)) {
                ec.clear();
                continue;
            }

            if (scannedOnThisDrive >= maxFiles) {
                state.details += L"Быстрый режим: достигнут лимит файлов для диска ";
                state.details += directory.wstring();
                state.details += L" (";
                state.details += std::to_wstring(maxFiles);
                state.details += L" файлов).\r\n";
                break;
            }

            const uintmax_t fileSize = it->file_size(ec);
            if (ec) {
                ec.clear();
                continue;
            }
            if (fileSize > kFixedDriveMaxFileSizeBytes) {
                continue;
            }

            const long before = state.scannedObjects;
            ScanSingleFileInternal(current, state);
            if (state.scannedObjects > before) {
                ++scannedOnThisDrive;
            }
        }
    } catch (...) {
        finalStatus = TK_ERROR_SCAN;
    }
    return finalStatus;
}

long ScanDirectoryPathInternal(const std::filesystem::path& directory, ScanResultState& state) {
    long finalStatus = TK_OK;
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(directory, std::filesystem::directory_options::skip_permission_denied)) {
            if (!entry.is_regular_file()) continue;
            // Недоступные/заблокированные файлы пропускаются, чтобы сканирование папок и дисков не прерывалось.
            ScanSingleFileInternal(entry.path(), state);
        }
    } catch (...) {
        finalStatus = TK_ERROR_SCAN;
    }
    return finalStatus;
}

void StoreMonitorResult(const ScanResultState& state, const std::wstring& prefix) {
    std::lock_guard<std::mutex> lock(g_monitorMutex);
    g_monitorResult = state;
    if (!prefix.empty()) {
        g_monitorResult.details = prefix + L"\r\n" + g_monitorResult.details;
    }
}

void DirectoryMonitorWorker(std::wstring directory) {
    HANDLE change = FindFirstChangeNotificationW(
        directory.c_str(),
        TRUE,
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE);

    if (change == INVALID_HANDLE_VALUE) {
        ScanResultState state;
        state.details = L"Не удалось запустить мониторинг директории: " + directory;
        StoreMonitorResult(state, L"");
        std::lock_guard<std::mutex> lock(g_monitorMutex);
        g_monitorRunning = false;
        return;
    }

    HANDLE waitHandles[2] = { g_monitorStopEvent, change };
    while (true) {
        const DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
        if (waitResult == WAIT_OBJECT_0) break;
        if (waitResult != WAIT_OBJECT_0 + 1) break;

        ScanResultState state;
        long status = TK_OK;
        {
            std::lock_guard<std::mutex> lock(g_stateMutex);
            status = EnsureAvAvailableLocked();
        }
        if (status == TK_OK) {
            status = ScanDirectoryPathInternal(std::filesystem::path(directory), state);
        }
        if (status != TK_OK && state.details.empty()) {
            state.details = L"Мониторинг обнаружил изменение, но сканирование выполнить не удалось.";
        }
        StoreMonitorResult(state, L"Автоматическое сканирование после изменения в папке: " + directory);

        if (!FindNextChangeNotification(change)) break;
    }

    FindCloseChangeNotification(change);
}

void StopDirectoryMonitorWorkerInternal() {
    HANDLE stopEvent = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_monitorMutex);
        stopEvent = g_monitorStopEvent;
    }
    if (stopEvent) SetEvent(stopEvent);

    if (g_monitorThread.joinable()) {
        g_monitorThread.join();
    }

    std::lock_guard<std::mutex> lock(g_monitorMutex);
    if (g_monitorStopEvent) {
        CloseHandle(g_monitorStopEvent);
        g_monitorStopEvent = nullptr;
    }
    g_monitorRunning = false;
    g_monitorPath.clear();
}

extern "C" long TrayKeeperScanDirectory(wchar_t* path, TK_SCAN_RESULT* result) {
    if (!path || !result) return TK_ERROR_INTERNAL;
    ScanResultState state;
    long finalStatus = TK_OK;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        finalStatus = EnsureAvAvailableLocked();
    }
    if (finalStatus == TK_OK) finalStatus = ScanDirectoryPathInternal(std::filesystem::path(path), state);
    result->scannedObjects = state.scannedObjects;
    result->infectedObjects = state.infectedObjects;
    result->clean = (finalStatus == TK_OK && state.infectedObjects == 0) ? 1 : 0;
    if (finalStatus != TK_OK && state.details.empty()) state.details = L"Не удалось выполнить сканирование директории.";
    result->details = RpcDuplicateString(BuildScanSummary(state));
    return finalStatus;
}

extern "C" long TrayKeeperScanFixedDrives(TK_SCAN_RESULT* result) {
    if (!result) return TK_ERROR_INTERNAL;
    ScanResultState state;
    long finalStatus = TK_OK;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        finalStatus = EnsureAvAvailableLocked();
    }

    if (finalStatus == TK_OK) {
        wchar_t drives[512]{};
        const DWORD length = GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives)), drives);
        if (length == 0 || length > std::size(drives)) {
            finalStatus = TK_ERROR_SCAN;
        } else {
            for (wchar_t* drive = drives; *drive != L'\0'; drive += wcslen(drive) + 1) {
                const UINT type = GetDriveTypeW(drive);
                if (type != DRIVE_FIXED) continue;
                state.details += L"Быстрое сканирование диска: ";
                state.details += drive;
                state.details += L" (до ";
                state.details += std::to_wstring(kFixedDriveMaxFilesPerDrive);
                state.details += L" файлов, файлы больше 10 МБ пропускаются)\r\n";
                const long driveStatus = ScanDirectoryPathLimitedInternal(std::filesystem::path(drive), state, kFixedDriveMaxFilesPerDrive);
                if (driveStatus != TK_OK && finalStatus == TK_OK) finalStatus = driveStatus;
            }
        }
    }

    result->scannedObjects = state.scannedObjects;
    result->infectedObjects = state.infectedObjects;
    result->clean = (finalStatus == TK_OK && state.infectedObjects == 0) ? 1 : 0;
    if (finalStatus != TK_OK && state.details.empty()) state.details = L"Не удалось выполнить сканирование несъёмных дисков.";
    result->details = RpcDuplicateString(BuildScanSummary(state));
    return finalStatus;
}

extern "C" long TrayKeeperStartDirectoryMonitor(wchar_t* path, TK_SCAN_RESULT* result) {
    if (!path || !result) return TK_ERROR_INTERNAL;

    long status = TK_OK;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        status = EnsureAvAvailableLocked();
    }
    if (status != TK_OK) {
        ScanResultState state;
        state.details = L"Мониторинг недоступен: нет активной лицензии или пользователь не вошёл.";
        FillRpcScanResult(state, status, L"Не удалось запустить мониторинг директории.", result);
        return status;
    }

    std::filesystem::path directory(path);
    if (!std::filesystem::exists(directory) || !std::filesystem::is_directory(directory)) {
        ScanResultState state;
        state.details = L"Указанный путь не является директорией.";
        FillRpcScanResult(state, TK_ERROR_SCAN, L"Не удалось запустить мониторинг директории.", result);
        return TK_ERROR_SCAN;
    }

    StopDirectoryMonitorWorkerInternal();

    {
        std::lock_guard<std::mutex> lock(g_monitorMutex);
        g_monitorStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!g_monitorStopEvent) {
            ScanResultState state;
            state.details = L"Не удалось создать событие остановки мониторинга.";
            FillRpcScanResult(state, TK_ERROR_INTERNAL, L"Не удалось запустить мониторинг директории.", result);
            return TK_ERROR_INTERNAL;
        }
        g_monitorRunning = true;
        g_monitorPath = directory.wstring();
        g_monitorResult = ScanResultState{};
        g_monitorResult.details = L"Мониторинг запущен для папки: " + g_monitorPath;
    }

    g_monitorThread = std::thread(DirectoryMonitorWorker, directory.wstring());

    std::lock_guard<std::mutex> lock(g_monitorMutex);
    FillRpcScanResult(g_monitorResult, TK_OK, L"Мониторинг запущен.", result);
    return TK_OK;
}

extern "C" long TrayKeeperStopDirectoryMonitor(TK_SCAN_RESULT* result) {
    StopDirectoryMonitorWorkerInternal();
    ScanResultState state;
    state.details = L"Мониторинг директории остановлен.";
    FillRpcScanResult(state, TK_OK, L"Мониторинг директории остановлен.", result);
    return TK_OK;
}

extern "C" long TrayKeeperGetDirectoryMonitorStatus(TK_SCAN_RESULT* result) {
    if (!result) return TK_ERROR_INTERNAL;
    std::lock_guard<std::mutex> lock(g_monitorMutex);
    ScanResultState state = g_monitorResult;
    if (!g_monitorRunning && state.details.empty()) {
        state.details = L"Мониторинг директории не запущен.";
    }
    FillRpcScanResult(state, TK_OK, L"Статус мониторинга недоступен.", result);
    return TK_OK;
}


void StoreScheduledScanResult(const ScanResultState& state, const std::wstring& prefix) {
    std::lock_guard<std::mutex> lock(g_scheduleMutex);
    g_scheduleResult = state;
    if (!prefix.empty()) {
        g_scheduleResult.details = prefix + L"\r\n" + g_scheduleResult.details;
    }
}

void ScheduledDirectoryScanWorker(std::wstring directory, long intervalSeconds) {
    if (intervalSeconds < 10) intervalSeconds = 10;

    while (true) {
        ScanResultState state;
        long status = TK_OK;
        {
            std::lock_guard<std::mutex> lock(g_stateMutex);
            status = EnsureAvAvailableLocked();
        }
        if (status == TK_OK) {
            status = ScanDirectoryPathInternal(std::filesystem::path(directory), state);
        }
        if (status != TK_OK && state.details.empty()) {
            state.details = L"Сканирование по расписанию выполнить не удалось.";
        }
        StoreScheduledScanResult(state, L"Сканирование по расписанию. Папка: " + directory);

        const DWORD waitMs = static_cast<DWORD>(intervalSeconds) * 1000UL;
        HANDLE stopEvent = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_scheduleMutex);
            stopEvent = g_scheduleStopEvent;
        }
        if (!stopEvent) break;
        if (WaitForSingleObject(stopEvent, waitMs) == WAIT_OBJECT_0) break;
    }
}

void StopScheduledScanWorkerInternal() {
    HANDLE stopEvent = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_scheduleMutex);
        stopEvent = g_scheduleStopEvent;
    }
    if (stopEvent) SetEvent(stopEvent);

    if (g_scheduleThread.joinable()) {
        g_scheduleThread.join();
    }

    std::lock_guard<std::mutex> lock(g_scheduleMutex);
    if (g_scheduleStopEvent) {
        CloseHandle(g_scheduleStopEvent);
        g_scheduleStopEvent = nullptr;
    }
    g_scheduleRunning = false;
    g_schedulePath.clear();
}

extern "C" long TrayKeeperStartScheduledDirectoryScan(wchar_t* path, long intervalSeconds, TK_SCAN_RESULT* result) {
    if (!path || !result) return TK_ERROR_INTERNAL;

    long status = TK_OK;
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        status = EnsureAvAvailableLocked();
    }
    if (status != TK_OK) {
        ScanResultState state;
        state.details = L"Сканирование по расписанию недоступно: нет активной лицензии или пользователь не вошёл.";
        FillRpcScanResult(state, status, L"Не удалось настроить сканирование по расписанию.", result);
        return status;
    }

    std::filesystem::path directory(path);
    if (!std::filesystem::exists(directory) || !std::filesystem::is_directory(directory)) {
        ScanResultState state;
        state.details = L"Указанный путь не является директорией.";
        FillRpcScanResult(state, TK_ERROR_SCAN, L"Не удалось настроить сканирование по расписанию.", result);
        return TK_ERROR_SCAN;
    }

    if (intervalSeconds < 10) intervalSeconds = 10;
    StopScheduledScanWorkerInternal();

    {
        std::lock_guard<std::mutex> lock(g_scheduleMutex);
        g_scheduleStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!g_scheduleStopEvent) {
            ScanResultState state;
            state.details = L"Не удалось создать событие остановки расписания.";
            FillRpcScanResult(state, TK_ERROR_INTERNAL, L"Не удалось настроить сканирование по расписанию.", result);
            return TK_ERROR_INTERNAL;
        }
        g_scheduleRunning = true;
        g_schedulePath = directory.wstring();
        g_scheduleIntervalSeconds = intervalSeconds;
        g_scheduleResult = ScanResultState{};
        g_scheduleResult.details = L"Сканирование по расписанию запущено. Папка: " + g_schedulePath + L". Интервал: " + std::to_wstring(g_scheduleIntervalSeconds) + L" сек.";
    }

    g_scheduleThread = std::thread(ScheduledDirectoryScanWorker, directory.wstring(), intervalSeconds);

    std::lock_guard<std::mutex> lock(g_scheduleMutex);
    FillRpcScanResult(g_scheduleResult, TK_OK, L"Сканирование по расписанию запущено.", result);
    return TK_OK;
}

extern "C" long TrayKeeperStopScheduledScan(TK_SCAN_RESULT* result) {
    StopScheduledScanWorkerInternal();
    ScanResultState state;
    state.details = L"Сканирование по расписанию остановлено.";
    FillRpcScanResult(state, TK_OK, L"Сканирование по расписанию остановлено.", result);
    return TK_OK;
}

extern "C" long TrayKeeperGetScheduledScanStatus(TK_SCAN_RESULT* result) {
    if (!result) return TK_ERROR_INTERNAL;
    std::lock_guard<std::mutex> lock(g_scheduleMutex);
    ScanResultState state = g_scheduleResult;
    if (!g_scheduleRunning && state.details.empty()) {
        state.details = L"Сканирование по расписанию не настроено.";
    } else if (g_scheduleRunning) {
        state.details = L"Расписание активно. Папка: " + g_schedulePath + L". Интервал: " + std::to_wstring(g_scheduleIntervalSeconds) + L" сек.\r\n" + state.details;
    }
    FillRpcScanResult(state, TK_OK, L"Статус расписания недоступен.", result);
    return TK_OK;
}

extern "C" void* __RPC_USER midl_user_allocate(size_t size) { return std::malloc(size); }
extern "C" void __RPC_USER midl_user_free(void* pointer) { std::free(pointer); }

bool InstallService() {
    wchar_t modulePath[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, modulePath, MAX_PATH)) return false;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;

    SC_HANDLE service = CreateServiceW(
        scm,
        kServiceName,
        kServiceName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        modulePath,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);

    if (!service && GetLastError() == ERROR_SERVICE_EXISTS) {
        service = OpenServiceW(scm, kServiceName, SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_STATUS);
        if (service) {
            ChangeServiceConfigW(
                service,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                modulePath,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                kServiceName);
        }
    }

    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool UninstallService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status{};
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    const bool deleted = DeleteService(service) != FALSE;

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return deleted;
}

int RunConsoleMode() {
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) return 1;

    const RPC_STATUS rpcStatus = StartRpcServer();
    if (rpcStatus != RPC_S_OK) {
        CloseHandle(g_stopEvent);
        return 1;
    }

    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        if (!g_avDatabase.loaded) LoadAvDatabaseLocked();
    }

    g_refreshThread = std::thread(RefreshWorker);
    LaunchTrayForAllLoggedOnSessions();
    WaitForSingleObject(g_stopEvent, INFINITE);
    StopScheduledScanWorkerInternal();
    StopDirectoryMonitorWorkerInternal();
    StopRpcServer();
    if (g_refreshThread.joinable()) g_refreshThread.join();
    TerminateTrayProcesses();
    CloseHandle(g_stopEvent);
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        const std::wstring command = argv[1];
        if (command == L"install") return InstallService() ? 0 : 1;
        if (command == L"uninstall" || command == L"remove" || command == L"delete") return UninstallService() ? 0 : 1;
        if (command == L"console") return RunConsoleMode();
    }

    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        return GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT ? 0 : 1;
    }
    return 0;
}
