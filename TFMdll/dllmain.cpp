#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_

#include <windows.h>
#include <winsock2.h>
#include <fstream>
#include <vector>
#include <string>
#include "include/MinHook.h" 
#include <shlobj.h> 
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <map>

#pragma comment(linker, "/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=C:\\Windows\\System32\\version.GetFileVersionInfoByHandle")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW")
#pragma comment(linker, "/export:GetSystemDLLInfo=C:\\Windows\\System32\\version.GetSystemDLLInfo")
#pragma comment(linker, "/export:VerFindFileA=C:\\Windows\\System32\\version.VerFindFileA")
#pragma comment(linker, "/export:VerFindFileW=C:\\Windows\\System32\\version.VerFindFileW")
#pragma comment(linker, "/export:VerInstallFileA=C:\\Windows\\System32\\version.VerInstallFileA")
#pragma comment(linker, "/export:VerInstallFileW=C:\\Windows\\System32\\version.VerInstallFileW")
#pragma comment(linker, "/export:VerLanguageNameA=C:\\Windows\\System32\\version.VerLanguageNameA")
#pragma comment(linker, "/export:VerLanguageNameW=C:\\Windows\\System32\\version.VerLanguageNameW")
#pragma comment(linker, "/export:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=C:\\Windows\\System32\\version.VerQueryValueW")

#pragma comment(lib,"ws2_32.lib")

typedef int (WINAPI* recv_t)(SOCKET, char*, int, int);
recv_t oRecv;

std::map<SOCKET, std::vector<unsigned char>> socket_buffers;
namespace fs = std::filesystem;
std::string global_log_path = "";

void InitLogPath() {
    char desktop_path[MAX_PATH];
    if (SHGetSpecialFolderPathA(NULL, desktop_path, CSIDL_DESKTOPDIRECTORY, FALSE)) {
        fs::path dir = fs::path(desktop_path) / "Tfm_chats";
        if (!fs::exists(dir)) fs::create_directories(dir);

        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        struct tm buf_time;
        localtime_s(&buf_time, &in_time_t);

        std::stringstream ss;
        ss << std::put_time(&buf_time, "%d.%m.%Y_%H-%M");
        global_log_path = (dir / (ss.str() + "_chat_log.log")).string();
    }
}

int ReadVarInt(const unsigned char* data, int& offset, int max) {
    int numRead = 0, result = 0;
    unsigned char read;
    do {
        if (offset >= max) return -1;
        read = data[offset++];
        result |= (read & 0x7F) << (7 * numRead);
        numRead++;
        if (numRead > 5) return -1;
    } while (read & 0x80);
    return result;
}

int WINAPI hkRecv(SOCKET s, char* buf, int len, int flags) {
    int ret = oRecv(s, buf, len, flags);
    if (ret <= 0) return ret;

    if (global_log_path.empty()) InitLogPath();

    std::vector<unsigned char>& tcp_buf = socket_buffers[s];
    tcp_buf.insert(tcp_buf.end(), buf, buf + ret);

    int offset = 0;
    while (true) {
        int temp_offset = offset;
        int packet_len = ReadVarInt(tcp_buf.data(), temp_offset, (int)tcp_buf.size());
        if (packet_len <= 0 || (int)tcp_buf.size() - temp_offset < packet_len) break;

        unsigned char* payload = tcp_buf.data() + temp_offset;
        int category = payload[0];
        bool is_valid = false;
        int start_index = 1;

        if (category == 6 && packet_len > 3) is_valid = true;
        else if (category == 60 && packet_len > 10) {
            for (int i = 1; i < 6 && i < packet_len; i++) {
                if (payload[i] == 'B' || payload[i] == 'A') {
                    is_valid = true;
                    start_index = i + 1;
                    break;
                }
            }
        }

        if (is_valid) {
            std::ofstream f(global_log_path, std::ios::app | std::ios::binary);
            if (f.is_open()) {
                f.seekp(0, std::ios::end);
                if (f.tellp() == 0) {
                    unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
                    f.write((char*)bom, 3);
                }

                auto now = std::chrono::system_clock::now();
                auto in_time_t = std::chrono::system_clock::to_time_t(now);
                struct tm buf_time;
                localtime_s(&buf_time, &in_time_t);

                std::stringstream ss;
                ss << std::put_time(&buf_time, "[%H:%M:%S] ");
                std::string prefix = (category == 60 ? "[WHISPER] " : "[CHAT] ");
                f.write(ss.str().c_str(), ss.str().size());
                f.write(prefix.c_str(), prefix.size());

                std::string content = "";
                for (int i = start_index; i < packet_len; i++) {
                    unsigned char c = payload[i];
                    if (c >= 32 || c >= 128) content += (char)c;
                    else if (c == 0x01) content += " ";
                }

                if (category == 6) {
                    size_t h = content.find('#');
                    if (h != std::string::npos && h + 4 < content.size()) {
                        content.insert(h + 5, ": ");
                        size_t m = h + 7;
                        if (m < content.size() && (content[m] == '=' || content[m] == '&' || content[m] == '<')) content.erase(m, 1);
                    }
                }
                else if (category == 60) {
                    size_t h1 = content.find('#');
                    if (h1 != std::string::npos && h1 + 4 < content.size()) {
                        size_t h2 = content.find('#', h1 + 5);
                        if (h2 != std::string::npos && h2 + 4 < content.size()) {
                            content.insert(h2 + 5, ": ");
                            content.insert(h1 + 5, " -> ");
                            size_t m = h2 + 11;
                            if (m < content.size() && (content[m] == '=' || content[m] == '&' || content[m] == '<')) content.erase(m, 1);
                        }
                    }
                }
                f.write(content.c_str(), content.size());
                f.write("\r\n", 2);
                f.close();
            }
        }
        offset = temp_offset + packet_len;
    }
    if (offset > 0) tcp_buf.erase(tcp_buf.begin(), tcp_buf.begin() + offset);
    return ret;
}

DWORD WINAPI Init(LPVOID) {
    MH_Initialize();
    MH_CreateHookApi(L"ws2_32", "recv", &hkRecv, reinterpret_cast<LPVOID*>(&oRecv));
    MH_EnableHook(MH_ALL_HOOKS);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(0, 0, Init, 0, 0, 0);
    }
    return TRUE;
}