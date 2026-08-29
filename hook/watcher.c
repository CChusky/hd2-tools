// watcher.c - HD2 auto-inject watcher daemon
// Stays resident, watches for helldivers2.exe, auto-injects
// hd2_raycast_hook.dll when the game starts, then waits for the
// process to exit and keeps watching.
//
// Build: cl /O2 /W0 watcher.c /link /OUT:watcher.exe
// Usage: watcher.exe [process_name] [dll_path] [-once]
//
// -once: inject once and exit (manual mode)
// default: resident watch loop

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

/* v3.1: require elevation - SeDebugPrivilege only works in an elevated
 * process; the Themida-protected game denies OpenProcess (err 5) otherwise.
 * Elevation manifest is set via the linker flag /MANIFESTUAC:level=
 * 'requireAdministrator' in the build script (not a #pragma - MSVC ignores
 * /MANIFESTUAC in pragma linker comments). */

static FILE *g_log = NULL;
static void log_msg(const char *fmt, ...); /* forward decl (v3) */

/* v3: SeDebugPrivilege so OpenProcess succeeds against the protected
 * (Themida) game process when watcher runs non-elevated. Same helper as
 * dumpexe. */
static int enable_debug_priv(void) {
    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
        return 0;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(hTok); return 0;
    }
    BOOL ok = AdjustTokenPrivileges(hTok, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(hTok);
    return ok ? 1 : 0;
}

/* Open the game with the minimal rights injection actually needs; fall back
 * to full access if the minimal set is denied (elevated tooling). */
static HANDLE open_game_process(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                           PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                           FALSE, pid);
    if (!h) {
        DWORD e1 = GetLastError();
        h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!h)
            log_msg("OpenProcess(%lu) denied: min err=%lu, full err=%lu\n", pid, e1, GetLastError());
    }
    return h;
}

static void log_msg(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    SYSTEMTIME st;
    GetLocalTime(&st);
    char ts[64];
    snprintf(ts, sizeof(ts), "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    if (g_log) {
        fprintf(g_log, "%s", ts);
        vfprintf(g_log, fmt, args);
        fflush(g_log);
    }
    vprintf(fmt, args);
    va_end(args);
}

static DWORD find_process_by_name(const char *name) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    DWORD pid = 0;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, name) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pid;
}

// Find the game's main window (first visible top-level window of pid).
static BOOL CALLBACK find_win_enum(HWND hwnd, LPARAM lp) {
    struct { DWORD pid; HWND hwnd; } *ctx = (void*)lp;
    DWORD wpid = 0;
    GetWindowThreadProcessId(hwnd, &wpid);
    if (wpid == ctx->pid && IsWindowVisible(hwnd)) {
        ctx->hwnd = hwnd;
        return FALSE;
    }
    return TRUE;
}
static HWND find_process_window(DWORD pid) {
    struct { DWORD pid; HWND hwnd; } ctx = { pid, NULL };
    EnumWindows(find_win_enum, (LPARAM)&ctx);
    return ctx.hwnd;
}

// Wait until the game is likely fully loaded before injecting. The game's
// working set fluctuates heavily while loading scenes/animations, so a
// "stable memory" check is unreliable (it never stabilizes -> never injects).
// v2: window visible means the engine initialized; inject after a short
// settle delay (default 5s, configurable via --settle <ms>) instead of the
// old fixed 20s-from-detect (which wasted most of the wait). Timeout caps
// the total wait at 45s (v3: was 90s, user chose 45s).
static DWORD g_settle_ms = 5000;
static void wait_game_ready(DWORD pid, HANDLE hp) {
    log_msg("Waiting for game %lu to open its window + %lu ms settle...\n", pid, (unsigned long)g_settle_ms);
    DWORD t0 = GetTickCount();
    DWORD win_t = 0;
    for (;;) {
        if (WaitForSingleObject(hp, 0) == WAIT_OBJECT_0) return;   // exited
        if (!win_t && find_process_window(pid)) {
            win_t = GetTickCount();
            log_msg("Game %lu window visible\n", pid);
        }
        if (win_t && (GetTickCount() - win_t) > g_settle_ms) {     // window + settle
            log_msg("Game %lu ready (window + %lu ms settle, %lu ms total)\n",
                pid, (unsigned long)(GetTickCount() - win_t),
                (unsigned long)(GetTickCount() - t0));
            return;
        }
        if (GetTickCount() - t0 > 45000) {                         // hard cap 45s
            log_msg("Game %lu load-timeout (45s), injecting anyway\n", pid);
            return;
        }
        Sleep(2000);
    }
}

static int inject_dll(DWORD pid, const char *dll_path) {
    HANDLE hProcess = open_game_process(pid);
    if (!hProcess) {
        log_msg("Cannot open game process for injection\n");
        return -1;
    }
    size_t path_len = strlen(dll_path) + 1;
    LPVOID remote_mem = VirtualAllocEx(hProcess, NULL, path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        log_msg("VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }
    if (!WriteProcessMemory(hProcess, remote_mem, dll_path, path_len, NULL)) {
        log_msg("WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    LPVOID load_lib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!load_lib) {
        log_msg("LoadLibraryA proc failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)load_lib, remote_mem, 0, NULL);
    if (!hThread) {
        log_msg("CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    WaitForSingleObject(hThread, 5000);
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    if (exit_code == 0) {
        log_msg("WARNING: LoadLibrary returned NULL (PID %lu) - may have failed\n", pid);
    } else {
        log_msg("Injected OK (PID %lu, hModule=0x%p)\n", pid, (void *)exit_code);
    }
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return (exit_code != 0) ? 0 : -1;
}

static void log_usage(void) {
    printf("Usage: watcher.exe [process_name] [dll_path] [-once]\n");
    printf("  default: resident watch loop (auto-inject on game start)\n");
    printf("  -once:   inject once and exit\n");
}

int main(int argc, char *argv[]) {
    const char *process_name = "helldivers2.exe";
    const char *dll_path = "hd2_raycast_hook.dll";
    int once = 0;
    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "-once") == 0) once = 1;
        else if (_stricmp(argv[i], "--settle") == 0 && i + 1 < argc) g_settle_ms = (DWORD)atoi(argv[++i]);
        else if (_stricmp(argv[i], "-h") == 0 || _stricmp(argv[i], "--help") == 0) { log_usage(); return 0; }
        else if (!process_name || strcmp(process_name, "helldivers2.exe") == 0) process_name = argv[i];
        else dll_path = argv[i];
    }

    // exe dir as base for dll if relative
    char dll_full[MAX_PATH];
    if (strchr(dll_path, '\\') == NULL && strchr(dll_path, '/') == NULL && !GetFullPathNameA(dll_path, MAX_PATH, dll_full, NULL)) {
        char exe_dir[MAX_PATH];
        GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
        char *slash = strrchr(exe_dir, '\\');
        if (slash) *slash = 0;
        snprintf(dll_full, sizeof(dll_full), "%s\\%s", exe_dir, dll_path);
        dll_path = dll_full;
    } else if (GetFullPathNameA(dll_path, MAX_PATH, dll_full, NULL)) {
        dll_path = dll_full;
    }

    g_log = fopen("watcher_log.txt", "a");
    log_msg("=== HD2 watcher started (resident) ===\n");
    log_msg("SeDebugPrivilege: %s\n", enable_debug_priv() ? "OK" : "FAIL (run as admin if injection is denied)");
    log_msg("Target: %s | DLL: %s\n", process_name, dll_path);
    if (GetFileAttributesA(dll_path) == INVALID_FILE_ATTRIBUTES) {
        log_msg("ERROR: DLL not found: %s\n", dll_path);
        if (g_log) fclose(g_log);
        return 1;
    }

    int injected = 0;
    for (;;) {
        DWORD pid = find_process_by_name(process_name);
        if (pid && pid != injected) {
            log_msg("Game detected (PID %lu)\n", pid);
            // Wait until the game is fully loaded BEFORE injecting: injecting
            // during the startup/loading phase crashed the game (TSF/input
            // hooks ran too early). Late injection is safe.
            HANDLE hp0 = OpenProcess(SYNCHRONIZE, FALSE, pid);
            if (hp0) {
                wait_game_ready(pid, hp0);
                CloseHandle(hp0);
            } else {
                log_msg("OpenProcess(SYNCHRONIZE) failed %lu - injecting immediately\n", GetLastError());
            }
            log_msg("Injecting into game %lu...\n", pid);
            int r = inject_dll(pid, dll_path);
            if (r == 0) {
                injected = pid;
                // wait for process exit
                HANDLE hp = OpenProcess(SYNCHRONIZE, FALSE, pid);
                if (hp) {
                    log_msg("Watching game process %lu until exit...\n", pid);
                    // Poll with a timeout instead of INFINITE: a zombie
                    // process we cannot terminate would block injection
                    // forever, so a NEW game instance never gets the DLL.
                    for (;;) {
                        DWORD wr = WaitForSingleObject(hp, 3000);
                        if (wr == WAIT_OBJECT_0) break;      // exited
                        if (wr == WAIT_TIMEOUT) {
                            DWORD cur = find_process_by_name(process_name);
                            if (cur != pid && cur != 0) break; // new instance appeared
                        } else break;
                    }
                    CloseHandle(hp);
                    log_msg("Game exited - re-arming watcher.\n");
                    injected = 0;
                } else {
                    log_msg("OpenProcess(SYNCHRONIZE) failed %lu - sleeping.\n", GetLastError());
                    injected = 0;
                }
            } else {
                log_msg("Injection failed - will retry in 5s.\n");
                injected = 0;
            }
        }
        if (once && injected != 0) break;
        Sleep(2000);
    }

    log_msg("=== watcher exiting ===\n");
    if (g_log) fclose(g_log);
    return 0;
}
