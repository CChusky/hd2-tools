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
typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;
typedef NTSTATUS(NTAPI *NT_OPEN_PROCESS)(PHANDLE, ACCESS_MASK, PVOID, PCLIENT_ID);
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

/* v3.2: build a direct-syscall NtOpenProcess trampoline that bypasses the
 * Themida user-mode hook (which denies any OpenProcess whose access mask
 * contains PROCESS_CREATE_THREAD/VM_WRITE - read-only masks still pass).
 * The syscall number is read dynamically from the ntdll export prologue
 * (mov eax, SSN), so it works across Windows versions. */
static NT_OPEN_PROCESS make_syscall_open_process(void) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!nt) return NULL;
    BYTE *p = (BYTE *)GetProcAddress(nt, "NtOpenProcess");
    if (!p) return NULL;
    DWORD ssn = 0;
    if (p[0] == 0xB8) {                       /* mov eax, SSN (unhooked) */
        ssn = *(DWORD *)(p + 1);
    } else if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1) { /* mov r10,rcx */
        for (int i = 3; i < 24; i++)
            if (p[i] == 0xB8) { ssn = *(DWORD *)(p + i + 1); break; }
    }
    if (!ssn) return NULL;
    BYTE code[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0x0F, 0x05, 0xC3 };
    memcpy(code + 4, &ssn, 4);
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    if (!buf) return NULL;
    memcpy(buf, code, sizeof(code));
    return (NT_OPEN_PROCESS)buf;
}

static HANDLE open_game_process(DWORD pid) {
    /* v3.4: mirror dll_injector exactly - plain PROCESS_ALL_ACCESS first
     * (the manual injector succeeds with it at any time). Fall back to the
     * minimal set, then a direct syscall if denied. */
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (h) return h;
    DWORD e1 = GetLastError();
    h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                    PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                    FALSE, pid);
    if (h) {
        log_msg("OpenProcess min-set OK (ALL_ACCESS err=%lu)\n", e1);
        return h;
    }
    DWORD e2 = GetLastError();
    /* bypass Themida user-mode NtOpenProcess hook via direct syscall */
    static NT_OPEN_PROCESS ntop = NULL;
    if (!ntop) ntop = make_syscall_open_process();
    if (ntop) {
        CLIENT_ID cid = { (PVOID)(uintptr_t)pid, NULL };
        HANDLE hs = NULL;
        NTSTATUS st = ntop(&hs,
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            NULL, &cid);
        if (NT_SUCCESS(st) && hs) {
            log_msg("OpenProcess via direct syscall OK (ALL_ACCESS err=%lu, min err=%lu)\n", e1, e2);
            return hs;
        }
        log_msg("NtOpenProcess syscall denied: 0x%08lX (ALL_ACCESS err=%lu, min err=%lu)\n",
            (unsigned long)st, e1, e2);
    } else {
        log_msg("syscall trampoline build failed (ALL_ACCESS err=%lu, min err=%lu)\n", e1, e2);
    }
    return NULL;
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
/* v3.7: fixed-delay ready wait, NO process handle at all (dll_injector
 * never opens the target before injecting; Themida may flag callers that
 * opened a handle earlier). Pure sleep + polling by name only. */
static DWORD g_settle_ms = 8000;
static void wait_game_ready(DWORD pid) {
    log_msg("Waiting %lu ms for game %lu to initialize (fixed delay, no handles)...\n",
        (unsigned long)g_settle_ms, pid);
    Sleep(g_settle_ms);
    log_msg("Game %lu ready (fixed %lu ms delay)\n", pid, (unsigned long)g_settle_ms);
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

/* v3.5: after a successful injection, auto-start overlay.exe (same dir as
 * watcher) so the user does not have to launch it manually. */
static void ensure_overlay_started(void) {
    if (FindWindowW(L"HD2OverlayCls", NULL)) return; /* already running */
    char exe_dir[MAX_PATH];
    GetModuleFileNameA(NULL, exe_dir, sizeof exe_dir);
    char *slash = strrchr(exe_dir, '\\');
    if (slash) *slash = 0;
    char ov[MAX_PATH];
    snprintf(ov, sizeof ov, "%s\\overlay.exe", exe_dir);
    if (GetFileAttributesA(ov) == INVALID_FILE_ATTRIBUTES) return; /* overlay not present */
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    if (CreateProcessA(NULL, ov, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        log_msg("overlay.exe auto-started after injection\n");
    } else {
        log_msg("overlay.exe start failed: %lu\n", GetLastError());
    }
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
    /* v3.6: do NOT enable SeDebugPrivilege - Themida flags callers that hold
     * it as debugger-like and denies their OpenProcess (err 5). dll_injector,
     * which always works, never touches privilege APIs. Keep this log line so
     * we can confirm the tool no longer enables it. */
    log_msg("SeDebugPrivilege: disabled (v3.6 - mirrors dll_injector)\n");
    log_msg("Target: %s | DLL: %s\n", process_name, dll_path);
    if (GetFileAttributesA(dll_path) == INVALID_FILE_ATTRIBUTES) {
        log_msg("ERROR: DLL not found: %s\n", dll_path);
        if (g_log) fclose(g_log);
        return 1;
    }

    int injected = 0;
    int quick_retry = 0; /* v3.3: after a failed inject, retry every 10s without
                          * re-running the ready-wait (Themida lets injection
                          * through once the game finished loading). */
    for (;;) {
        DWORD pid = find_process_by_name(process_name);
        if (pid && pid != injected) {
            log_msg("Game detected (PID %lu)\n", pid);
            if (!quick_retry) {
                /* v3.7: no OpenProcess(SYNCHRONIZE) - dll_injector never
                 * opens the target before injecting. Pure delay. */
                wait_game_ready(pid);
            } else {
                log_msg("Quick retry (game window already seen)\n");
            }
            log_msg("Injecting into game %lu...\n", pid);
            int r = inject_dll(pid, dll_path);
            if (r == 0) {
                injected = pid;
                quick_retry = 0;
                ensure_overlay_started(); /* v3.5 */
                /* v3.7: watch for exit by polling the process name only
                 * (no process handle). */
                log_msg("Watching game %lu via polling...\n", pid);
                for (;;) {
                    Sleep(3000);
                    DWORD cur = find_process_by_name(process_name);
                    if (cur != pid) break; /* exited or new instance */
                }
                log_msg("Game exited - re-arming watcher.\n");
                injected = 0;
            } else {
                log_msg("Injection failed - retrying in 10s.\n");
                injected = 0;
                quick_retry = 1;
            }
        }
        if (once && injected != 0) break;
        Sleep(quick_retry ? 10000 : 2000);
    }

    log_msg("=== watcher exiting ===\n");
    if (g_log) fclose(g_log);
    return 0;
}
