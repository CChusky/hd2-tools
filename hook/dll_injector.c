// dll_injector.c
// Simple DLL injector for hd2_raycast_hook.dll
//
// Build: cl /O2 /W0 dll_injector.c /link /OUT:dll_injector.exe
//
// Usage: dll_injector.exe <process_name>
// Example: dll_injector.exe helldivers2.exe

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>

static DWORD find_process_by_name(const char *name) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed: %d\n", GetLastError());
        return 0;
    }
    
    if (!Process32First(hSnapshot, &pe32)) {
        printf("Process32First failed: %d\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }
    
    DWORD pid = 0;
    do {
        if (_stricmp(pe32.szExeFile, name) == 0) {
            pid = pe32.th32ProcessID;
            printf("Found process: %s (PID: %d)\n", name, pid);
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    
    if (pid == 0) {
        printf("Process '%s' not found\n", name);
    }
    
    return pid;
}

static int inject_dll(DWORD pid, const char *dll_path) {
    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("OpenProcess failed: %d\n", GetLastError());
        return -1;
    }
    
    // Allocate memory for DLL path in target process
    size_t path_len = strlen(dll_path) + 1;
    LPVOID remote_mem = VirtualAllocEx(hProcess, NULL, path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        printf("VirtualAllocEx failed: %d\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }
    
    // Write DLL path to target process
    if (!WriteProcessMemory(hProcess, remote_mem, dll_path, path_len, NULL)) {
        printf("WriteProcessMemory failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    
    // Get LoadLibraryA address
    LPVOID load_lib_addr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!load_lib_addr) {
        printf("GetProcAddress failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    
    // Create remote thread to load DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
        (LPTHREAD_START_ROUTINE)load_lib_addr, remote_mem, 0, NULL);
    if (!hThread) {
        printf("CreateRemoteThread failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    
    printf("DLL injection thread created. Waiting...\n");
    
    // Wait for thread to finish
    WaitForSingleObject(hThread, 5000);
    
    // Check exit code
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    if (exit_code == 0) {
        printf("WARNING: LoadLibrary returned NULL - DLL may have failed to load\n");
    } else {
        printf("DLL injected successfully! LoadLibrary returned: 0x%p\n", (void*)exit_code);
    }
    
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return 0;
}

int main(int argc, char *argv[]) {
    const char *process_name = "helldivers2.exe";
    const char *dll_path = "hd2_raycast_hook.dll";

    if (argc >= 2) {
        process_name = argv[1];
    }
    if (argc >= 3) {
        dll_path = argv[2];
    }

    printf("=== HD2 Raycast Hook DLL Injector ===\n");
    printf("Target process: %s\n", process_name);
    printf("DLL path: %s\n", dll_path);

    // Check DLL exists
    DWORD attrs = GetFileAttributesA(dll_path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        printf("ERROR: DLL file not found: %s\n", dll_path);
        return 1;
    }

    // Get full path of DLL
    char full_path[MAX_PATH];
    if (!GetFullPathNameA(dll_path, MAX_PATH, full_path, NULL)) {
        printf("GetFullPathName failed: %d\n", GetLastError());
        return 1;
    }
    printf("Full DLL path: %s\n", full_path);
    
    // Find process
    DWORD pid = find_process_by_name(process_name);
    if (pid == 0) {
        printf("\nWaiting for process... (press Ctrl+C to cancel)\n");
        while (pid == 0) {
            Sleep(1000);
            pid = find_process_by_name(process_name);
        }
        printf("Process found!\n");
    }
    
    // Inject
    printf("\nInjecting DLL...\n");
    int result = inject_dll(pid, full_path);
    
    if (result == 0) {
        printf("\n=== Injection successful ===\n");
        printf("Use DebugView to see output (filter: [RAYCAST])\n");
        printf("Keys in game:\n");
        printf("  F2 - Probe Lua API\n");
        printf("  F3 - Probe World/Raycast\n");
        printf("  F4 - Single raycast\n");
        printf("  F5 - Toggle continuous raycast\n");
        printf("  F6 - Probe Unit/Resource API\n");
    } else {
        printf("\n=== Injection FAILED ===\n");
    }
    
    return result;
}
