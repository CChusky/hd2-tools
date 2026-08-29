// hd2_raycast_hook.c (public build)
// Inline-hook lua_pcall (x64) in lua51.dll to inject raycast code
//
// Build: cl /LD /O2 /W4 hd2_raycast_hook_public.c hd2_addon_stub.c
//        /link /OUT:hd2_raycast_hook_public.dll user32.lib gdi32.lib
//
// Keys:
//   F4      - Raycast: lock target, real-time track + wireframe outline
//   Numpad1 - Scan nearby units: dump hash + resource_name for every unit
//
// Safety:
//   - Code runs in isolated lua_newthread coroutine
//   - SEH catches C-level segfaults (only coroutine is corrupted)
//   - 3-second cooldown after any segfault before retrying
//   - NtProtectVirtualMemory fallback bypasses anti-cheat VirtualProtect hooks

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include <intrin.h>

static volatile LONG g_segfault_flag = 0;
static volatile DWORD g_segfault_tick = 0;

// ============================================================
// Logging - to both DebugView and file
// ============================================================
static CRITICAL_SECTION g_log_cs;
/* v10.25: workspace moved per user instruction - all files now live in the
 * work-mode-projects dir; nothing is written to .trae-cn\work anymore. */
#define RC_DIR "C:\\Users\\Administrator\\AppData\\Roaming\\TRAE SOLO CN\\ModularData\\ai-agent\\work-mode-projects\\6a856504b9374ddbb7e87068\\"

/* v10.48: fopen() on Windows interprets the path with the ANSI (GBK) codepage,
 * but the /utf-8 flag compiles Chinese path literals as UTF-8 bytes. Opening
 * e.g. "哈希对照表.txt" through plain fopen() then fails -> use _wfopen with
 * a UTF-16 path converted from the UTF-8 literal. */
static FILE *rc_fopen_utf8(const char *utf8_path, const char *mode) {
    wchar_t wpath[1024], wmode[16];
    if (MultiByteToWideChar(CP_UTF8, 0, utf8_path, -1, wpath, 1024) <= 0) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 16) <= 0) return NULL;
    return _wfopen(wpath, wmode);
}

static FILE *g_log_file = NULL;
static volatile LONG g_log_line_count = 0;
static DWORD g_last_flush_tick = 0;

static void log_init(void) {
    InitializeCriticalSection(&g_log_cs);
    g_log_file = fopen(RC_DIR "raycast_log.txt", "a");
    if (g_log_file) {
        // UTF-8 BOM so Notepad etc. decode the Chinese names correctly
        // (they are stored as UTF-8; without the BOM GBK-default editors
        // show them as mojibake like "鐒﹀湡").
        if (ftell(g_log_file) == 0) {
            static const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
            fwrite(bom, 1, 3, g_log_file);
        }
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_log_file, "\n=== Session %04d-%02d-%02d %02d:%02d:%02d ===\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        fflush(g_log_file);
    }
}

static void log_msg(const char *fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    // DebugView: send UTF-16 so Chinese (UTF-8 in buf) renders correctly.
    // The log file below stays UTF-8.
    {
        wchar_t wbuf[1024];
        int wlen = MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, 1024);
        if (wlen > 0) OutputDebugStringW(wbuf);
    }
    
    EnterCriticalSection(&g_log_cs);
    if (g_log_file) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_log_file, "[%02d:%02d:%02d.%03d] %s",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
        // Batch flush: every 50 lines or every 2 seconds
        LONG count = InterlockedIncrement(&g_log_line_count);
        DWORD tick = GetTickCount();
        if (count >= 50 || (tick - g_last_flush_tick) > 2000) {
            fflush(g_log_file);
            InterlockedExchange(&g_log_line_count, 0);
            g_last_flush_tick = tick;
        }
    }
    LeaveCriticalSection(&g_log_cs);
}

// ============================================================
// x86-64 instruction length decoder (minimal)
// Used to ensure we overwrite whole instructions only
// ============================================================
static int x64_instr_len(const uint8_t *code) {
    int len = 0;
    int rex_w = 0;
    
    // Skip legacy prefixes
    while (len < 15) {
        uint8_t b = code[len];
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x64 || b == 0x65) {
            len++;
        } else {
            break;
        }
    }
    
    // REX prefix
    if (len < 15 && code[len] >= 0x40 && code[len] <= 0x4F) {
        rex_w = (code[len] >> 3) & 1;
        len++;
    }
    
    if (len >= 15) return len;
    
    uint8_t op = code[len];
    len++;
    
    // Two-byte opcode
    if (op == 0x0F) {
        if (len >= 15) return len;
        op = code[len];
        len++;
        
        // 3-byte opcode (0F 38 / 0F 3A)
        if (op == 0x38 || op == 0x3A) {
            if (len >= 15) return len;
            op = code[len];
            len++;
        }
        
        // Conditional near jumps (0F 80-8F) - rel32
        if (op >= 0x80 && op <= 0x8F) {
            return len + 4;
        }
        
        // Most 2-byte opcodes have ModRM
        if (len < 15) {
            uint8_t modrm = code[len];
            len++;
            
            int mod = (modrm >> 6) & 3;
            int rm = modrm & 7;
            
            // SIB byte
            if (rm == 4 && mod != 3 && len < 15) {
                uint8_t sib = code[len];
                len++;
                int base = sib & 7;
                if (mod == 0 && base == 5) len += 4;
                else if (mod == 1) len += 1;
                else if (mod == 2) len += 4;
            } else {
                if (mod == 0 && rm == 5) len += 4;
                else if (mod == 1) len += 1;
                else if (mod == 2) len += 4;
            }
        }
        return len;
    }
    
    // One-byte opcodes
    switch (op) {
        // Short jumps (rel8)
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        case 0xEB: case 0xE3:
            return len + 1;
            
        // Near call/jmp (rel32)
        case 0xE8: case 0xE9:
            return len + 4;
            
        // MOV accumulator, moffs
        case 0xA0: case 0xA1: case 0xA2: case 0xA3:
            return len + (rex_w ? 8 : 4);
            
        // MOV reg8, imm8
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            return len + 1;
            
        // MOV reg, imm32/imm64
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            return len + (rex_w ? 8 : 4);
            
        // Push imm
        case 0x6A: return len + 1;
        case 0x68: return len + 4;
            
        // RET
        case 0xC3: case 0xCB: return len;
        case 0xC2: case 0xCA: return len + 2;
            
        // INT 3 / INT n
        case 0xCC: return len;
        case 0xCD: return len + 1;
            
        // Single-byte no-operand instructions
        case 0x90: case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9C: case 0x9D:
        case 0x9E: case 0x9F: case 0xC9:
        case 0xF4: case 0xF5: case 0xF8: case 0xF9:
        case 0xFA: case 0xFB: case 0xFC: case 0xFD:
        case 0xA4: case 0xA5: case 0xA6: case 0xA7:
        case 0xAA: case 0xAB: case 0xAC: case 0xAD:
        case 0xAE: case 0xAF:
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            return len;
            
        // Arithmetic with accumulator, imm8
        case 0x04: case 0x0C: case 0x14: case 0x1C:
        case 0x24: case 0x2C: case 0x34: case 0x3C:
            return len + 1;
            
        // Arithmetic with accumulator, imm32
        case 0x05: case 0x0D: case 0x15: case 0x1D:
        case 0x25: case 0x2D: case 0x35: case 0x3D:
            return len + 4;
            
        // Instructions with ModRM
        default: {
            int has_modrm = 0;
            int imm_size = 0;
            
            if (op >= 0x00 && op <= 0x3F) {
                has_modrm = 1;
            } else if (op >= 0x80 && op <= 0x8F) {
                has_modrm = 1;
                // 0x81 (ALU r/m, imm32/imm64) was previously treated as
                // having NO immediate (and 0x82/0xC6/0xC7 were dead code in
                // this range). Underestimating the immediate makes the hook
                // size too small -> the trampoline copies a partial
                // instruction -> execution of garbage -> crash.
                if (op == 0x80) imm_size = 1;                        // ALU r/m8, imm8
                else if (op == 0x81) imm_size = rex_w ? 8 : 4;       // ALU r/m, imm32/64
                else if (op == 0x83) imm_size = 1;                   // ALU r/m, imm8 sext
            } else if (op == 0xC6) {
                has_modrm = 1;
                imm_size = 1;                                        // MOV r/m8, imm8
            } else if (op == 0xC7) {
                has_modrm = 1;
                imm_size = rex_w ? 8 : 4;                            // MOV r/m, imm32/64
            } else if (op >= 0xC0 && op <= 0xC1) {
                has_modrm = 1;
                imm_size = 1;
            } else if (op >= 0xD0 && op <= 0xD3) {
                has_modrm = 1;
            } else if (op == 0xF6 || op == 0xF7) {
                has_modrm = 1;
                imm_size = (op == 0xF6) ? 1 : 4;
                if (op == 0xF7 && rex_w) imm_size = 8;               // TEST r/m64, imm64
            } else if (op == 0xFE || op == 0xFF) {
                has_modrm = 1;
            } else {
                has_modrm = 0;
            }
            
            if (has_modrm && len < 15) {
                uint8_t modrm = code[len];
                len++;
                
                int mod = (modrm >> 6) & 3;
                int rm = modrm & 7;
                
                if (rm == 4 && mod != 3 && len < 15) {
                    uint8_t sib = code[len];
                    len++;
                    int base = sib & 7;
                    if (mod == 0 && base == 5) len += 4;
                    else if (mod == 1) len += 1;
                    else if (mod == 2) len += 4;
                } else {
                    if (mod == 0 && rm == 5) len += 4;
                    else if (mod == 1) len += 1;
                    else if (mod == 2) len += 4;
                }
                
                len += imm_size;
            }
            
            return len;
        }
    }
    
    return len;
}

// Calculate minimum safe hook size (covers at least min_bytes, aligned to instructions)
static int calc_hook_size(void *func, int min_bytes) {
    int total = 0;
    uint8_t *p = (uint8_t *)func;
    while (total < min_bytes) {
        int ilen = x64_instr_len(p + total);
        if (ilen <= 0 || ilen > 15) break;
        total += ilen;
    }
    return total > 0 ? total : min_bytes;
}

// ============================================================
// Lua 5.1 API (partial)
// ============================================================
typedef struct lua_State lua_State;
typedef int (*lua_CFunction)(lua_State *L);

typedef int (*lua_pcall_t)(lua_State *L, int nargs, int nresults, int errfunc);
typedef int (*luaL_loadstring_t)(lua_State *L, const char *s);
typedef const char *(*lua_tolstring_t)(lua_State *L, int idx, size_t *len);
typedef void (*lua_settop_t)(lua_State *L, int idx);
typedef int (*lua_gettop_t)(lua_State *L);
typedef int (*lua_type_t)(lua_State *L, int idx);
typedef const char *(*lua_typename_t)(lua_State *L, int tp);
typedef lua_State *(*lua_newthread_t)(lua_State *L);
typedef void *(*lua_touserdata_t)(lua_State *L, int idx);
typedef const void *(*lua_topointer_t)(lua_State *L, int idx);
typedef double (*lua_tonumber_t)(lua_State *L, int idx);
typedef void (*lua_getglobal_t)(lua_State *L, const char *name);
typedef void (*lua_setglobal_t)(lua_State *L, const char *name);
typedef void (*lua_pushnumber_t)(lua_State *L, double n);
typedef void (*lua_getfield_t)(lua_State *L, int idx, const char *k);
typedef lua_CFunction (*lua_tocfunction_t)(lua_State *L, int idx);
typedef const char *(*lua_getupvalue_t)(lua_State *L, int idx, int n);
typedef int (*lua_next_t)(lua_State *L, int idx);
typedef void (*lua_pushnil_t)(lua_State *L);
typedef void (*lua_rawgeti_t)(lua_State *L, int idx, int n);

#define LUA_TNIL          0
#define LUA_TBOOLEAN      1
#define LUA_TLIGHTUSERDATA 2
#define LUA_TNUMBER       3
#define LUA_TSTRING       4
#define LUA_TTABLE        5
#define LUA_TFUNCTION     6
#define LUA_TUSERDATA     7
#define LUA_GLOBALSINDEX  (-10002) // Stingray does not export lua_getglobal;
                                   // use lua_getfield(L, LUA_GLOBALSINDEX, name)

static lua_pcall_t       o_lua_pcall       = NULL;
static luaL_loadstring_t f_luaL_loadstring = NULL;
static lua_tolstring_t   f_lua_tolstring   = NULL;
static lua_settop_t      f_lua_settop      = NULL;
static lua_gettop_t      f_lua_gettop      = NULL;
static lua_type_t        f_lua_type        = NULL;
static lua_typename_t    f_lua_typename    = NULL;
static lua_newthread_t   f_lua_newthread   = NULL;
static lua_touserdata_t  f_lua_touserdata  = NULL;
static lua_topointer_t   f_lua_topointer   = NULL;
static lua_tonumber_t    f_lua_tonumber    = NULL;
static lua_getglobal_t   f_lua_getglobal   = NULL;
static lua_setglobal_t   f_lua_setglobal   = NULL;
static lua_pushnumber_t  f_lua_pushnumber  = NULL;
static lua_getfield_t    f_lua_getfield    = NULL;
static lua_tocfunction_t f_lua_tocfunction = NULL;
static lua_getupvalue_t  f_lua_getupvalue  = NULL;
static lua_next_t        f_lua_next        = NULL;
static lua_pushnil_t     f_lua_pushnil     = NULL;
static lua_rawgeti_t     f_lua_rawgeti     = NULL;
typedef int (*lua_gc_t)(lua_State *L, int what, int data);
static lua_gc_t f_lua_gc = NULL;
// Lua 5.1 lua_gc opcodes (lua.h). CRITICAL: the previous build used
// GCSTOP=1/GCRESTART=2 which actually mapped to GCRESTART/GCCOLLECT - so the
// scan-end call was FORCING A FULL COLLECTION every time (finalizers crash/
// stall). These values must match lua.h exactly.
#define LUA_GCSTOP        0
#define LUA_GCRESTART     1
#define LUA_GCCOLLECT     2
#define LUA_GCCOUNT       3
#define LUA_GCCOUNTB      4
#define LUA_GCSTEP        5
#define LUA_GCSETPAUSE    6
#define LUA_GCSETSTEPMUL  7

static lua_State *g_L = NULL;
static volatile LONG g_pcall_count = 0;
static volatile DWORD g_last_status_tick = 0;
static volatile BOOL g_continuous_raycast = FALSE;
static volatile BOOL g_continuous_viz = FALSE;
static volatile BOOL g_initialized = FALSE;

// Gui.text call monitor - observes how the game's own GUI layer
// renders text (real font names, arg order) so we can replicate it.
static const void *g_gui_text_ptr = NULL;
static volatile LONG g_gui_monitor_ready = 0;
static volatile LONG g_guitext_logged = 0;
static DWORD g_last_guitext_tick = 0;
static char g_font_seen[8][64];
static int g_font_seen_count = 0;
static volatile LONG g_guitext_total = 0;

// NtProtectVirtualMemory - direct call bypasses usermode hooks on VirtualProtect
typedef LONG(NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);
static NtProtectVirtualMemory_t f_NtProtectVirtualMemory = NULL;

// Helper: try VirtualProtect, then NtProtectVirtualMemory as fallback
static BOOL safe_virtual_protect(void *addr, SIZE_T size, DWORD new_prot, DWORD *old_prot) {
    if (VirtualProtect(addr, size, new_prot, old_prot))
        return TRUE;
    // Fallback to NtProtectVirtualMemory (bypasses usermode hooks)
    if (f_NtProtectVirtualMemory) {
        PVOID base = addr;
        SIZE_T region = size;
        ULONG nt_old = 0;
        LONG status = f_NtProtectVirtualMemory(
            GetCurrentProcess(),
            &base, &region,
            new_prot, &nt_old);
        *old_prot = nt_old;
        if (status == 0) return TRUE;
        log_msg("[RAYCAST] NtProtectVirtualMemory failed: 0x%08X\n", status);
    }
    return FALSE;
}

// ============================================================
// x64 inline hook (safe - instruction length aligned)
// ============================================================
#define JMP_STUB_SIZE 14  // mov rax, imm64; jmp rax

static void *build_trampoline(void *original_func, int num_bytes) {
    void *tramp = VirtualAlloc(NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return NULL;
    
    memcpy(tramp, original_func, num_bytes);
    
    // Jump back to original + num_bytes
    uint8_t *p = (uint8_t *)tramp + num_bytes;
    p[0] = 0x48; p[1] = 0xB8;
    *(uint64_t *)&p[2] = (uint64_t)((uint8_t *)original_func + num_bytes);
    p[10] = 0xFF; p[11] = 0xE0;
    
    return tramp;
}

static void install_hook(void **orig_tramp, void *hook_func, void *target_addr) {
    int hook_size = calc_hook_size(target_addr, JMP_STUB_SIZE);
    if (hook_size < JMP_STUB_SIZE) hook_size = JMP_STUB_SIZE;
    
    char dbg[256];
    snprintf(dbg, sizeof(dbg), "[RAYCAST] Hook size: %d bytes\n", hook_size);
    log_msg("%s", dbg);
    
    *orig_tramp = build_trampoline(target_addr, hook_size);
    if (!*orig_tramp) {
        log_msg("%s", "[RAYCAST] Failed to build trampoline\n");
        return;
    }
    
    DWORD old_protect;
    uint8_t *page_base = (uint8_t *)((uintptr_t)target_addr & ~(uintptr_t)0xFFF);
    if (!safe_virtual_protect(page_base, 0x2000, PAGE_EXECUTE_READWRITE, &old_protect)) {
        snprintf(dbg, sizeof(dbg), "[RAYCAST] safe_virtual_protect failed for hook\n");
        log_msg("%s", dbg);
        return;
    }
    
    uint8_t *p = (uint8_t *)target_addr;
    p[0] = 0x48; p[1] = 0xB8;
    *(uint64_t *)&p[2] = (uint64_t)hook_func;
    p[10] = 0xFF; p[11] = 0xE0;
    
    for (int i = 12; i < hook_size; i++) p[i] = 0xCC;
    
    DWORD dummy;
    safe_virtual_protect(page_base, 0x2000, old_protect, &dummy);
    FlushInstructionCache(GetCurrentProcess(), target_addr, hook_size);
}

static char g_last_result[16384] = {0};

// Quiet flag: when set, exec_lua still saves g_last_result for C-side
// parsing but suppresses the "OK(n): ..." log line. Used by per-frame
// shm_write_ui calls so the log is not flooded with draw payloads.
static volatile int g_quiet_exec = 0;
// Bypass the segfault cooldown for safe, SEH-isolated draw-path exec_lua
// calls (shm_write_hit / shm_write_ui). Those only project math into shared
// memory; they must never be starved by an unrelated engine crash in the
// 3D-line path (which would make fx show nothing even on a valid hit).
static volatile int g_exec_bypass = 0;

/* v10.47: strip Lua line/block comments from a chunk BEFORE loadstring.
 * The C call sites concatenate Lua with spaces (no newlines), so a '--'
 * comment would swallow everything to the end of the chunk - the cause of
 * the "passenger seat anchor" bug ('end' expected near '<eof>'). We keep
 * string literals ('...', "...", [[...]]) intact and only blank out real
 * comments, preserving newlines so line numbers stay valid. */
static void strip_lua_comments(const char *src, char *dst, size_t dst_sz) {
    size_t i = 0, o = 0, n = strlen(src);
    while (i < n && o + 1 < dst_sz) {
        char c = src[i];
        /* string literals: '...' or "..." (with \\ escapes) */
        if (c == '\'' || c == '"') {
            char q = c;
            dst[o++] = c; i++;
            while (i < n && o + 1 < dst_sz) {
                dst[o++] = src[i];
                if (src[i] == '\\' && i + 1 < n) { dst[o++] = src[i+1]; i += 2; continue; }
                i++;
                if (src[i-1] == q) break;
            }
            continue;
        }
        /* long string [[ ... ]] */
        if (c == '[' && i + 1 < n && src[i+1] == '[') {
            dst[o++] = c; i++;
            while (i < n && o + 1 < dst_sz) {
                dst[o++] = src[i];
                if (src[i] == ']' && i + 1 < n && src[i+1] == ']') {
                    dst[o++] = src[i+1]; i += 2; break;
                }
                i++;
            }
            continue;
        }
        /* comment: -- ... (line) or --[[ ... ]] (block) */
        if (c == '-' && i + 1 < n && src[i+1] == '-') {
            int is_block = 0;
            if (i + 2 < n && src[i+2] == '[') is_block = 1;
            if (is_block) {
                size_t j = i + 2;
                /* skip until ]] */
                while (j + 1 < n && !(src[j] == ']' && src[j+1] == ']')) j++;
                i = (j + 2 < n) ? j + 2 : n;
                dst[o++] = ' ';  /* block comment: safe to blank */
            } else {
                /* line comment: skip to newline or end. CRITICAL: emit a
                 * '\n' (not a space) so a space-concatenated single-line
                 * chunk ends the comment at the logical line and the code
                 * AFTER the comment survives loadstring. */
                while (i < n && src[i] != '\n') i++;
                if (o + 1 < dst_sz) dst[o++] = '\n';
            }
            continue;
        }
        dst[o++] = c; i++;
    }
    dst[o] = 0;
}

// ============================================================
// Execute Lua string in an isolated thread (coroutine)
// If a C-level segfault occurs, only the thread is corrupted;
// the game's main lua_State remains intact.
// ============================================================
static void exec_lua(const char *code) {
    if (!g_L || !f_luaL_loadstring || !o_lua_pcall) return;
    if (g_segfault_flag && !g_exec_bypass) return;
    if (!f_lua_newthread) {
        log_msg("%s", "[RAYCAST] lua_newthread not available\n");
        return;
    }

    g_last_result[0] = 0;

    int top = f_lua_gettop(g_L);

    lua_State *T = f_lua_newthread(g_L);
    if (!T) {
        log_msg("%s", "[RAYCAST] lua_newthread failed\n");
        f_lua_settop(g_L, top);
        return;
    }

    if (f_luaL_loadstring(T, code) != 0) {
        /* v10.47: retry after stripping comments - a space-concatenated
         * chunk (no newlines) can have a '--' comment swallow the rest. */
        size_t clen = strlen(code);
        char *stripped = (char *)_malloca(clen + 1);
        if (stripped) {
            strip_lua_comments(code, stripped, clen + 1);
            if (f_luaL_loadstring(T, stripped) != 0) {
                const char *err = f_lua_tolstring(T, -1, NULL);
                char buf[1024];
                snprintf(buf, sizeof(buf), "[RAYCAST] LOAD ERR: %s\n", err ? err : "?");
                log_msg("%s", buf);
                _freea(stripped);
                f_lua_settop(g_L, top);
                return;
            }
            _freea(stripped);
        } else {
            const char *err = f_lua_tolstring(T, -1, NULL);
            char buf[1024];
            snprintf(buf, sizeof(buf), "[RAYCAST] LOAD ERR: %s\n", err ? err : "?");
            log_msg("%s", buf);
            f_lua_settop(g_L, top);
            return;
        }
    }

    int ret;
    __try {
        ret = o_lua_pcall(T, 0, -1, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange((volatile LONG *)&g_segfault_tick, GetTickCount());
        InterlockedExchange(&g_segfault_flag, 1);
        char buf[256];
        // Diagnose WHERE it crashed: print RIP relative to lua51.dll and our dll
        uintptr_t rip = 0;
        PEXCEPTION_POINTERS ep = GetExceptionInformation();
        if (ep && ep->ContextRecord) rip = (uintptr_t)ep->ContextRecord->Rip;
        HMODULE lua = GetModuleHandleA("lua51.dll");
        HMODULE self = GetModuleHandleA("hd2_raycast_hook.dll");
        if (lua && rip >= (uintptr_t)lua && rip < (uintptr_t)lua + 0x200000)
            snprintf(buf, sizeof(buf), "[RAYCAST] SEH 0x%08X rip=lua51+0x%llX (thread isolated)\n", GetExceptionCode(), (unsigned long long)(rip - (uintptr_t)lua));
        else if (self && rip >= (uintptr_t)self && rip < (uintptr_t)self + 0x100000)
            snprintf(buf, sizeof(buf), "[RAYCAST] SEH 0x%08X rip=hook+0x%llX (thread isolated)\n", GetExceptionCode(), (unsigned long long)(rip - (uintptr_t)self));
        else
            snprintf(buf, sizeof(buf), "[RAYCAST] SEH 0x%08X rip=0x%llX (thread isolated)\n", GetExceptionCode(), (unsigned long long)rip);
        log_msg("%s", buf);
        f_lua_settop(g_L, top);
        return;
    }

    if (ret != 0) {
        const char *err = f_lua_tolstring(T, -1, NULL);
        char buf[1024];
        /* v10.51: in quiet mode (pin tick stages) don't spam RUN ERR every
         * 120ms; the tick loop already reports stage failures once. */
        if (!g_quiet_exec) {
            snprintf(buf, sizeof(buf), "[RAYCAST] RUN ERR: %s\n", err ? err : "?");
            log_msg("%s", buf);
        }
    } else {
        int nresults = f_lua_gettop(T);
        if (nresults > 0) {
            // Save first string result for C-side use (e.g. tostring() parsing)
            int t1 = f_lua_type(T, 1);
            if (t1 == LUA_TSTRING || t1 == LUA_TNUMBER) {
                const char *s = f_lua_tolstring(T, 1, NULL);
                if (s) {
                    strncpy(g_last_result, s, sizeof(g_last_result) - 1);
                    g_last_result[sizeof(g_last_result) - 1] = 0;
                }
            }
            char buf[4096];
            int pos = 0;
            // SAFE logging: snprintf returns the would-be length even when it
            // truncates; accumulate that into pos and clamp, otherwise pos can
            // exceed the buffer and the next write corrupts the stack (this
            // caused __scrt_fastfail /GS crashes when logging long payloads).
            #define LOG_PUT(fmt, ...) do { int _n = snprintf(buf + pos, sizeof(buf) - pos, fmt, __VA_ARGS__); if (_n > 0) pos += _n; if (pos > (int)sizeof(buf) - 96) pos = (int)sizeof(buf) - 96; } while (0)
            LOG_PUT("[RAYCAST] OK(%d): ", nresults);
            for (int i = 1; i <= nresults && pos < (int)sizeof(buf) - 96; i++) {
                int t = f_lua_type(T, i);
                if (t == LUA_TSTRING || t == LUA_TNUMBER) {
                    const char *s = f_lua_tolstring(T, i, NULL);
                    LOG_PUT("'%s' ", s ? s : "nil");
                } else if (t == LUA_TBOOLEAN) {
                    const char *s = f_lua_tolstring(T, i, NULL);
                    LOG_PUT("%s ", s ? s : "false");
                } else if (t == LUA_TNIL) {
                    LOG_PUT("nil ");
                } else if (t == LUA_TTABLE) {
                    LOG_PUT("[table] ");
                } else {
                    const char *tn = f_lua_typename ? f_lua_typename(T, t) : "?";
                    LOG_PUT("[%s] ", tn);
                }
            }
            LOG_PUT("\n", 0);
            #undef LOG_PUT
            if (!g_quiet_exec) log_msg("%s", buf);
        }
    }

    f_lua_settop(g_L, top);
}


// forward-declared here so F8 (defined above do_raycast) can read them;
// the actual assignments happen in do_raycast further down.
static float g_cam_x = 0, g_cam_y = 0, g_cam_z = 0;
static float g_fwd_x = 0, g_fwd_y = 0, g_fwd_z = 0;
static float g_cam_rx = 0, g_cam_ry = 0, g_cam_rz = 0;  /* camera right (unit) */
static float g_cam_ux = 0, g_cam_uy = 0, g_cam_uz = 0;  /* camera up (unit) */

// ============================================================
// Offline mesh edge tables (mesh_verts_<hash>.txt in D:\hd2_meshtables).
// Format: line1 "<hash_dec> <nverts> <nedges>", then nverts lines of
// "<x> <y> <z>" local-space vertices, then nedges lines of "ia ib"
// vertex-index pairs (triangle edges). Built offline by build_all2.py.
// ============================================================
#define MESH_TABLE_MAX 1024   /* bounded lazy-load cache (evicts oldest) */
#define MESH_VERTS_MAX 4096
#define MESH_EDGES_MAX 8192

typedef struct {
    uint64_t hash;
    uint32_t nverts;
    uint32_t nedges;
    float verts[MESH_VERTS_MAX][3];  /* local-space x,y,z */
    uint16_t edges[MESH_EDGES_MAX][2]; /* vertex index pairs (tri edges) */
} MeshTableEntry;

/* Lazy mesh-table cache. The offline build produced 5k+ tables (~800MB on
 * disk); preloading them all would pin ~450MB (80KB struct per entry) in
 * the game process and freeze the game thread for seconds on first use.
 * Instead each entry is loaded from disk on demand (one small file per
 * F4-hit entity) into a bounded cache; the oldest slot is evicted when
 * the cache fills up. */
static MeshTableEntry g_mesh_tables[MESH_TABLE_MAX];
static int g_mesh_table_count = 0;
static int g_mesh_table_next = 0;   /* next cache slot to fill/evict */

/* Resolve the mesh table file path for a hash (candidate only - used by
 * diagnostics/logging). Actual loading tries every location in order. */
static void mesh_table_path(char *full, size_t sz, uint64_t hash) {
    const char *env = getenv("HD2_MESH_DIR");
    if (env && env[0]) {
        snprintf(full, sz, "%s\\mesh_verts_%llu.txt", env, (unsigned long long)hash);
        return;
    }
    char dir[MAX_PATH];
    HMODULE self = GetModuleHandleA("hd2_raycast_hook.dll");
    if (self && GetModuleFileNameA(self, dir, sizeof(dir)) > 0) {
        char *slash = strrchr(dir, '\\');
        if (slash) {
            slash[1] = 0;
            snprintf(full, sz, "%smeshes\\mesh_verts_%llu.txt", dir, (unsigned long long)hash);
            return;
        }
    }
    snprintf(full, sz, "D:\\hd2_meshtables\\mesh_verts_%llu.txt", (unsigned long long)hash);
}

/* v10.60: try EVERY mesh-table location in priority order and return the
 * first FILE* that opens. The old code built only ONE candidate path
 * (GetModuleHandleA always succeeds, so the DLL-adjacent meshes\ folder
 * was chosen unconditionally and the legacy D:\hd2_meshtables fallback
 * never ran) - any unpack where the DLL had no meshes\ next to it silently
 * skipped every outline. */
static FILE *mesh_table_open(uint64_t hash, char *full, size_t sz) {
    char cand[MAX_PATH];
    const char *env = getenv("HD2_MESH_DIR");
    if (env && env[0]) {
        snprintf(cand, sizeof(cand), "%s\\mesh_verts_%llu.txt", env, (unsigned long long)hash);
        FILE *f = fopen(cand, "r");
        if (f) { snprintf(full, sz, "%s", cand); return f; }
    }
    HMODULE self = GetModuleHandleA("hd2_raycast_hook.dll");
    if (self) {
        char dir[MAX_PATH];
        if (GetModuleFileNameA(self, dir, sizeof(dir)) > 0) {
            char *slash = strrchr(dir, '\\');
            if (slash) {
                slash[1] = 0;
                snprintf(cand, sizeof(cand), "%smeshes\\mesh_verts_%llu.txt", dir, (unsigned long long)hash);
                FILE *f = fopen(cand, "r");
                if (f) { snprintf(full, sz, "%s", cand); return f; }
            }
        }
    }
    snprintf(cand, sizeof(cand), "D:\\hd2_meshtables\\mesh_verts_%llu.txt", (unsigned long long)hash);
    FILE *f = fopen(cand, "r");
    if (f) { snprintf(full, sz, "%s", cand); return f; }
    return NULL;
}

/* Parse ONE mesh_verts_<hash>.txt into e. Returns 1 on success. */
static int mesh_table_load_file(uint64_t hash, MeshTableEntry *e) {
    char full[MAX_PATH];
    FILE *f = mesh_table_open(hash, full, sizeof(full));
    if (!f) return 0;
    e->hash = hash;
    e->nverts = 0;
    e->nedges = 0;
    char buf[256];
    if (fgets(buf, sizeof(buf), f)) {
        unsigned long long hd; unsigned long nv, ne;
        if (sscanf(buf, "%llu %lu %lu", &hd, &nv, &ne) == 3 && hd == hash) {
            while (fgets(buf, sizeof(buf), f) && e->nverts < nv && e->nverts < MESH_VERTS_MAX) {
                float x, y, z;
                if (sscanf(buf, "%f %f %f", &x, &y, &z) == 3) {
                    e->verts[e->nverts][0] = x;
                    e->verts[e->nverts][1] = y;
                    e->verts[e->nverts][2] = z;
                    e->nverts++;
                }
            }
            while (fgets(buf, sizeof(buf), f) && e->nedges < ne && e->nedges < MESH_EDGES_MAX) {
                unsigned long a, b;
                if (sscanf(buf, "%lu %lu", &a, &b) == 2 && a < e->nverts && b < e->nverts) {
                    e->edges[e->nedges][0] = (uint16_t)a;
                    e->edges[e->nedges][1] = (uint16_t)b;
                    e->nedges++;
                }
            }
        }
    }
    fclose(f);
    return (e->nverts > 0 && e->nedges > 0) ? 1 : 0;
}

/* Kept as the call-site hook (do_raycast / scans call it before lookup).
 * Preloading is intentionally a no-op now - tables load lazily per hit. */
static void load_mesh_tables(void) {
}

static MeshTableEntry *mesh_table_find(uint64_t hash) {
    for (int i = 0; i < g_mesh_table_count; i++)
        if (g_mesh_tables[i].hash == hash) return &g_mesh_tables[i];
    /* cache miss: try the file for this hash, evicting the oldest slot
     * when the cache is full. A miss (no file) leaves the slot untouched. */
    MeshTableEntry *e = &g_mesh_tables[g_mesh_table_next];
    if (!mesh_table_load_file(hash, e)) return NULL;
    g_mesh_table_next = (g_mesh_table_next + 1) % MESH_TABLE_MAX;
    if (g_mesh_table_count < MESH_TABLE_MAX) g_mesh_table_count++;
    return e;
}

// ============================================================
// Screen-space outline via boundary tracing. Projected points are binned
// into a grid; boundary cells (occupied + empty neighbor) are then walked
// in an 8-neighbor chain starting from the topmost-leftmost boundary cell,
// producing a TRUE ordered contour (preserves concavities; no star-shaped
// artifacts like angle-sorting). Returns the ordered outline points.
// ============================================================
#define OUTLINE_GRID 96

// ============================================================
// ============================================================
// On-demand mesh table building. When F4 hits an entity whose mesh
// table is missing, the hash is queued. While the game window is
// unfocused (>60s, i.e. the user tabbed out), a helper python process
// is spawned to build the missing tables; on completion the C side
// reloads them. This keeps the table set growing with real usage
// instead of requiring a full offline prebuild.
// ============================================================
#define MESH_PENDING_MAX 512
static uint64_t g_mesh_pending[MESH_PENDING_MAX];
static int g_mesh_pending_count = 0;
static int g_mesh_builder_running = 0;

static int mesh_pending_add(uint64_t hash) {
    if (!hash) return 0;
    if (mesh_table_find(hash)) return 0;
    for (int i = 0; i < g_mesh_pending_count; i++)
        if (g_mesh_pending[i] == hash) return 0;
    if (g_mesh_pending_count < MESH_PENDING_MAX) {
        g_mesh_pending[g_mesh_pending_count++] = hash;
        return 1;
    }
    return 0;
}

// Write pending hashes to the request file (one dec per line).
static void mesh_pending_save(void) {
    if (g_mesh_pending_count <= 0) return;
    FILE *f = fopen("D:\\hd2_meshtables\\pending.txt", "w");
    if (!f) return;
    for (int i = 0; i < g_mesh_pending_count; i++)
        fprintf(f, "%llu\n", (unsigned long long)g_mesh_pending[i]);
    fclose(f);
    log_msg("[RAYCAST] mesh pending saved: %d hashes\n", g_mesh_pending_count);
}

// Reload any mesh tables that were just built by the helper.
static void mesh_tables_reload(void) {
    g_mesh_table_count = 0;   // clear the lazy cache; entries re-read from disk
    g_mesh_table_next = 0;
    // drop pending entries that now have tables (mesh_table_find lazily
    // reads the file, so newly-built tables are picked up here)
    int kept = 0;
    for (int i = 0; i < g_mesh_pending_count; i++) {
        if (!mesh_table_find(g_mesh_pending[i]))
            g_mesh_pending[kept++] = g_mesh_pending[i];
    }
    g_mesh_pending_count = kept;
    if (kept) mesh_pending_save();
}

// Called periodically (from the pcall hook). Cleans up when an offline
// mesh-table build finished (done-flag written by the helper).
static void mesh_builder_tick(void) {
    // builder finished? check via a done-flag file the helper writes
    if (g_mesh_builder_running) {
        FILE *f = fopen("D:\\hd2_meshtables\\build_done.flag", "r");
        if (f) {
            fclose(f);
            DeleteFileA("D:\\hd2_meshtables\\build_done.flag");
            g_mesh_builder_running = 0;
            mesh_tables_reload();
            log_msg("%s", "[RAYCAST] mesh tables reloaded after builder\n");
        }
    }
}





// ============================================================
// Dump a single unit's C++ struct from entities[idx]
// Always safe: only reads memory, no Lua Unit API calls
// ============================================================
static int g_ents_cnt = 0;

// Closest hit tracking for visualization
static float g_hit_x = 0, g_hit_y = 0, g_hit_z = 0;
static float g_hit_dist = 9999.0f;
static char g_hit_rn[128] = {0};
static char g_hit_nh[128] = {0};
static int g_has_hit = 0;
static int g_verbose_log = 0; // 1=F4 manual press (verbose), 0=continuous (quiet)

/* v10.8: real-time tracking of the F4-locked target. g_track_key is the
 * hex id from the locked unit's resource_name ("#ID[xxxxxxxxxxxxxxxx]");
 * every ~100ms track_locked_target() re-locates that unit and refreshes
 * the hit state, so the HUD box/distance/label follow the moving target.
 * The same periodic refresh also re-submits cmd_feedback into the label
 * (row 5) - fixing feedback that never appeared because the label was only
 * built during the F4 scan. */
static int g_tracking = 0;
static int g_track_fail_count = 0; /* v10.28: consecutive track fails before giving up */
static char g_track_key[32] = {0};
static int g_track_idx = 0;
static int g_last_hit_idx = 0;
/* v10.18: resource_name is a PREFAB id - multiple vehicles of the same
 * type share it, so rn matching alone can lock onto the wrong instance.
 * Remember the locked world position and pick the matching instance
 * nearest to it. */
static float g_track_ox = 0, g_track_oy = 0, g_track_oz = 0;

static const char *hash_lookup(uint64_t h);

// ReShade addon core (hd2_addon_core.cpp, linked into this DLL).
// Registers this module as an EXTERNAL addon with ReShade at runtime,
// bypassing the official builds' "limited add-on functionality" scan limit.
extern void hd2_addon_attach(HMODULE self_module);
extern void hd2_addon_try_register(void);
extern void hd2_addon_detach(void);
extern int hd2_addon_status(void);
extern const char *hd2_addon_last_error(void);
static void shm_write_ui(void);

// ============================================================
// Shared memory protocol: this DLL (game thread) writes hit/box
// data, the ReShade addon (render thread) reads it and draws the
// ImGui overlay. Cross-thread safe via seq (writer commits data
// first, then bumps seq; reader re-reads while seq changed).
// ============================================================
#define RC_SHM_NAME "Local\\HD2RaycastShm"
#define RC_SHM_MAGIC 0x52434432u   /* 'RCD2' */
#define RC_SHM_VERSION 4
#define RC_SHM_BOXES_MAX 256
#define RC_COMP_MAX_UNITS 64
#define RC_COMP_MAX_PER_UNIT 24
#define RC_COMP_MAX_ITEMS (RC_COMP_MAX_UNITS * RC_COMP_MAX_PER_UNIT) /* 1536 */
#define RC_COMP_MAX_TYPES 128

struct rc_shm_box {
    float x, y, z;     /* world center (ship-anchor space) */
    float hx, hy, hz;  /* half extents */
};

struct rc_shm_data {
    volatile uint32_t magic;
    volatile uint32_t version;
    volatile uint32_t seq;    /* bumped after each commit */
    volatile uint32_t flags;  /* 1 = hit valid, 2 = boxes valid */
    float cam_x, cam_y, cam_z;
    float fwd_x, fwd_y, fwd_z;
    float cam_rx, cam_ry, cam_rz;  /* camera right (unit) for mesh projection */
    float cam_ux, cam_uy, cam_uz;  /* camera up (unit) */
    float hit_x, hit_y, hit_z;
    float hit_dist;
    uint64_t hit_hash64;
    uint32_t hit_thin;
    char hit_name[96];
    char hit_rn[128];
    uint32_t box_count;
    struct rc_shm_box boxes[RC_SHM_BOXES_MAX];
    /* screen-space UI elements (projected by the game-thread Lua, drawn by
     * the ReShade fx shader). Coordinates are render-resolution pixels. */
    uint32_t ui_line[4];       /* unused (kept for layout) */
    float ui_hit[3];           /* hit mark: nx, ny (0..1), on */
    float ui_hitbox[8][2];     /* 3D AABB corner projections 0..1 */
    uint32_t ui_mark_count;    /* scan-box screen marks */
    float ui_marks[128][2];    /* nx, ny (0..1) */
    uint32_t ui_scanbox_count; /* scan-box wireframes (<=16) */
    float ui_scanbox[16][8][2];
    /* method-comparison boxes: 4 candidate coordinate methods, each an 8-corner
     * wireframe. Index: 0=box-minmax(red) 1=box-center(green)
     * 2=world_position(blue) 3=local_position(cyan). nx=-1 means hidden. */
    float ui_mbox[4][8][2];
    /* v3: hit-entity real mesh outline. The C side projects the hit unit's
     * mesh vertices (from the offline mesh_verts_<hash>.txt table) through
     * the camera and writes normalized screen points here; the fx shader
     * draws them as a point cloud so the box hugs the real model shape. */
    uint32_t ui_mesh_count;
    float ui_mesh[8192][2];  /* projected edge endpoints (2 per edge) */
    /* v2: self-rendered text. The C side collects the unique UTF-8 chars of
     * the current label into atlas_chars; the addon renders them into a glyph
     * atlas texture (GDI + system font) and the fx shader draws the label
     * using label_slots (per-char index into the atlas). */
    volatile uint32_t atlas_rev; /* bumped when atlas chars change */
    uint32_t atlas_count;        /* number of unique chars */
    char atlas_chars[256];       /* UTF-8 bytes, concatenated per char */
    int32_t label_count;         /* chars in current label */
    int32_t label_slots[96];     /* char indices into atlas, -1 = end, -2 = newline */
    float label_widths[96];      /* per-char advance width in atlas px (GDI-measured) */
    /* component explorer fields: kept for overlay ABI compatibility (the
     * public hook build no longer fills them). */
    volatile uint32_t comp_seq;      /* bumped after each component refresh */
    uint32_t comp_refresh;           /* addon sets 1 to force a refresh */
    uint32_t comp_unit_count;        /* units with components (sorted) */
    uint32_t comp_units[RC_COMP_MAX_UNITS];
    float comp_unit_pos[RC_COMP_MAX_UNITS][3]; /* world pos per unit (may be 0) */
    uint32_t comp_type_count;        /* discovered type entries */
    struct rc_comp_type {
        uint32_t type_id;
        char name[48];
    } comp_types[RC_COMP_MAX_TYPES];
    uint32_t comp_item_count;
    struct rc_comp_item {
        uint32_t unit;               /* owning unit id */
        uint32_t type_id;            /* component type id */
        uint32_t valid;              /* object+0x14 bit0 */
        uint32_t flags;              /* spare */
        uint64_t obj;                /* component object address */
        char type_name[48];
    } comp_items[RC_COMP_MAX_ITEMS];
    uint32_t comp_evt_count;
    char comp_evt[6][192];
    uint32_t hit_unit_id;            /* unit id of the current F4 hit (0=none) */
    /* command area (addon -> hook) */
    volatile uint32_t cmd_seq;       /* bumped by addon to issue a command */
    uint32_t cmd_type;               /* 0 none, 1 write u32, 2 write f32, 3 refresh */
    uint64_t cmd_addr;               /* target game address */
    uint32_t cmd_val32;
    float    cmd_valf;
    volatile uint32_t cmd_done;      /* hook echoes cmd_seq when processed */
    /* v10.4: command feedback - written by se-cmd/exit handlers, rendered
     * by the addon at the bottom of the screen */
    char cmd_feedback[128];
};

static HANDLE g_shm_handle = NULL;
static struct rc_shm_data *g_shm = NULL;

static void shm_init(void) {
    if (g_shm) return;
    g_shm_handle = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
        0, sizeof(struct rc_shm_data), RC_SHM_NAME);
    if (!g_shm_handle)
        g_shm_handle = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, RC_SHM_NAME);
    if (g_shm_handle) {
        g_shm = (struct rc_shm_data *)MapViewOfFile(g_shm_handle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(struct rc_shm_data));
        if (g_shm) {
            if (g_shm->magic != RC_SHM_MAGIC) {
                memset(g_shm, 0, sizeof(struct rc_shm_data));
                g_shm->magic = RC_SHM_MAGIC;
                g_shm->version = RC_SHM_VERSION;
            }
            log_msg("%s", "[RAYCAST] shared memory ready\n");
        } else {
            log_msg("%s", "[RAYCAST] shared memory map FAILED\n");
        }
    } else {
        log_msg("%s", "[RAYCAST] shared memory create FAILED\n");
    }
}

static uint64_t parse_id64_from_rn(const char *rn) {
    if (!rn) return 0;
    const char *p = strstr(rn, "#ID[");
    if (!p) return 0;
    return (uint64_t)strtoull(p + 4, NULL, 16);
}

/* ---- self-rendered text label: UTF-8 glyph atlas (C side) ----
 * Unique UTF-8 characters are accumulated in g_atlas_bytes; the addon turns
 * them into a glyph atlas texture once per atlas_rev bump. label_build()
 * maps the current label text to per-char atlas slot indices. */
static char g_atlas_bytes[256];
static int g_atlas_nbytes = 0;
static int g_atlas_nchars = 0;
static uint32_t g_atlas_rev = 0;
/* v10.6: timestamp of the last rc_set_feedback, for the 6s on-screen expiry */
static ULONGLONG g_feedback_ts = 0;

static int utf8_seq_len(unsigned char c) {
    if (c < 0x80) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return 1;
}

/* ---- per-char advance widths (GDI, cached) ----
 * The fx shader places glyphs at their real advance width so narrow chars
 * (digits/latin) don't consume a full 48px atlas cell ("huge letter spacing").
 * Font parameters MUST match the addon's render_atlas (YaHei, size 34). */
#define ATLAS_CELL_PX 48
#define ATLAS_FONT_PX (ATLAS_CELL_PX - 14)
static HDC g_measure_dc = NULL;
static HFONT g_measure_font = NULL;
static wchar_t g_wcache_ch[512];
static float g_wcache_w[512];
static int g_wcache_n = 0;

static void ensure_measure(void) {
    if (!g_measure_dc) g_measure_dc = CreateCompatibleDC(NULL);
    if (!g_measure_font) {
        g_measure_font = CreateFontA(ATLAS_FONT_PX, 0, 0, 0, FW_BOLD, 0, 0, 0,
            DEFAULT_CHARSET, 0, 0, ANTIALIASED_QUALITY, 0, "Microsoft YaHei");
        if (g_measure_font) SelectObject(g_measure_dc, g_measure_font);
    }
}

static float measure_char_w(const unsigned char *p, int len) {
    wchar_t wc[8] = {0};
    int wn = MultiByteToWideChar(CP_UTF8, 0, (const char *)p, len, wc, 7);
    if (wn <= 0) return (float)ATLAS_CELL_PX;
    for (int i = 0; i < g_wcache_n; i++)
        if (g_wcache_ch[i] == wc[0]) return g_wcache_w[i];
    ensure_measure();
    SIZE sz = {};
    if (g_measure_dc && GetTextExtentPoint32W(g_measure_dc, wc, 1, &sz) && sz.cx > 0) {
        float w = (float)sz.cx;
        if (g_wcache_n < 512) {
            g_wcache_ch[g_wcache_n] = wc[0];
            g_wcache_w[g_wcache_n] = w;
            g_wcache_n++;
        }
        return w;
    }
    return (float)ATLAS_CELL_PX;
}

static void label_build(const char *text, int32_t *slots, float *widths, int max_slots, int *out_count) {
    int n = 0;
    const unsigned char *p = (const unsigned char *)text;
    if (!p) { *out_count = 0; return; }
    while (*p && n < max_slots) {
        int len = utf8_seq_len(*p);
        /* find this char in the atlas (by UTF-8 byte sequence) */
        int slot = -1;
        const unsigned char *q = (const unsigned char *)g_atlas_bytes;
        int off = 0, ci = 0;
        while (off < g_atlas_nbytes) {
            int cl = utf8_seq_len(q[off]);
            if (cl == len && memcmp(q + off, p, len) == 0) { slot = ci; break; }
            off += cl;
            ci++;
        }
        if (slot < 0) {
            if (g_atlas_nbytes + len > (int)sizeof(g_atlas_bytes) || g_atlas_nchars >= 128)
                break;
            memcpy(g_atlas_bytes + g_atlas_nbytes, p, len);
            g_atlas_nbytes += len;
            slot = g_atlas_nchars++;
            g_atlas_rev++;
        }
        slots[n] = slot;
        widths[n] = measure_char_w(p, len);
        n++;
        p += len;
    }
    *out_count = n;
}

// Multi-line label: rows are concatenated into `slots`, separated by the
// sentinel -2 (the fx shader treats -2 as a newline, -1 as end). Per-char
// advance widths go into `widths` (index-aligned with slots). Row 5 is the
// optional command feedback line (v10.6) - NULL/empty rows are skipped.
static void label_build_rows(const char *row1, const char *row2, const char *row3,
                             const char *row4, const char *row5, int32_t *slots, float *widths,
                             int max_slots, int *out_count) {
    int n = 0;
    const char *rows[5] = { row1, row2, row3, row4, row5 };
    for (int r = 0; r < 5 && n < max_slots; r++) {
        const char *text = rows[r];
        if (!text || !text[0]) continue;   // skip empty rows
        if (n > 0) {                        // separator before every new row
            if (n < max_slots) { slots[n] = -2; widths[n] = 0.0f; n++; }
            else break;
        }
        int sub = 0;
        label_build(text, slots + n, widths + n, max_slots - n, &sub);
        n += sub;
    }
    *out_count = n;
}

/* Commit current camera + hit state to shared memory. */
// Re-enable Lua GC after a scan. The restart runs a full GC cycle whose
// engine userdata finalizers crash or STALL at engine code; SEH-protect with
// a few retries so the game survives. Raise the GC pause first so the
// restart does NOT immediately collect everything (which is what stalls).
static void gc_restart_safe(void) {
    if (!f_lua_gc || !g_L) return;
    log_msg("%s", "[RAYCAST] GC restart begin\n");
    for (int t = 0; t < 3; t++) {
        __try {
            f_lua_gc(g_L, LUA_GCSETPAUSE, 120);   // collect after +120% growth (was 200)
            f_lua_gc(g_L, LUA_GCRESTART, 0);
            log_msg("%s", "[RAYCAST] GC restart done\n");
            return;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            log_msg("[RAYCAST] GC restart SEH 0x%08X (attempt %d) - engine finalizer\n",
                GetExceptionCode(), t + 1);
            Sleep(100);
        }
    }
}

static void shm_write_hit(void) {
    if (!g_shm) shm_init();
    if (!g_shm) return;
    struct rc_shm_data *s = g_shm;
    s->seq++;  // write-in-progress (seqlock): reader sees seq change and retries
    s->cam_x = g_cam_x; s->cam_y = g_cam_y; s->cam_z = g_cam_z;
    s->fwd_x = g_fwd_x; s->fwd_y = g_fwd_y; s->fwd_z = g_fwd_z;
    if (g_has_hit) {
        s->hit_x = g_hit_x; s->hit_y = g_hit_y; s->hit_z = g_hit_z;
        s->hit_dist = g_hit_dist;
        s->hit_hash64 = parse_id64_from_rn(g_hit_rn);
        s->hit_thin = (uint32_t)(s->hit_hash64 >> 32);
        snprintf(s->hit_rn, sizeof(s->hit_rn), "%s", g_hit_rn[0] ? g_hit_rn : "unknown");
        const char *nm = s->hit_hash64 ? hash_lookup(s->hit_hash64) : NULL;
        if (nm && nm[0]) {
            /* Reject hash-shaped "names" (16-19 pure digits): the lookup
             * table can carry a foreign entity's hash in the name column,
             * and showing it as the entity's name is garbage (seen with
             * habs_landing_pad_01 showing the LAS-58 revolver's hash). */
            const unsigned char *cp = (const unsigned char *)nm;
            int dig = 0;
            for (; *cp; cp++) { if (*cp < '0' || *cp > '9') { dig = -1; break; } dig++; }
            if (dig >= 16 && dig <= 19) nm = NULL;
        }
        if (nm && nm[0]) {
            snprintf(s->hit_name, sizeof(s->hit_name), "%s", nm);
        } else {
            // Never show hex ids or the binary name_hash blob: the user wants
            // pure-decimal numbers (thin = high 32 bits, decimal, no letters).
            snprintf(s->hit_name, sizeof(s->hit_name), "thin=%u",
                (unsigned)(uint32_t)(s->hit_hash64 >> 32));
        }
        s->flags |= 1u;
        /* build the multi-line text label. Row 1 = Archive (first path
         * segment - the SDK requires picking an Archive before searching),
         * row 2 = rest of the resource path, row 3 = distance, row 4 = full
         * DECIMAL hash (pure digits). */
        {
            int32_t slots[96];
            float lwidths[96];
            int nslot = 0;
            char line_arch[48], line_rest[80], line_arch_f[56];
            const char *slash = strchr(s->hit_name, '/');
            if (slash && slash > s->hit_name) {
                size_t al = (size_t)(slash - s->hit_name);
                if (al > 47) al = 47;
                memcpy(line_arch, s->hit_name, al);
                line_arch[al] = 0;
                snprintf(line_rest, sizeof(line_rest), "%s", slash + 1);
            } else {
                snprintf(line_arch, sizeof(line_arch), "?");
                snprintf(line_rest, sizeof(line_rest), "%s", s->hit_name);
            }
            snprintf(line_arch_f, sizeof(line_arch_f), "Archive: %s", line_arch);
            char line2[64], line3[32];
            snprintf(line2, sizeof(line2), "dist=%.1fm", s->hit_dist);
            if (s->hit_hash64)
                snprintf(line3, sizeof(line3), "%llu", (unsigned long long)s->hit_hash64);
            else
                line3[0] = 0;
            /* v10.6: command feedback rides the F4 label as row 5, using the
             * same glyph-atlas pipeline as the target label (so CJK works).
             * Expires 6s after the last rc_set_feedback. */
            char line_fb[128];
            const char *fb_row = NULL;
            if (s->cmd_feedback[0]) {
                ULONGLONG now = GetTickCount64();
                if (now - g_feedback_ts < 6000) {
                    snprintf(line_fb, sizeof(line_fb), "%s", s->cmd_feedback);
                    fb_row = line_fb;
                } else {
                    s->cmd_feedback[0] = 0; /* expired */
                }
            }
            label_build_rows(line_arch_f, line_rest, line2, line3, fb_row, slots, lwidths, 96, &nslot);
            /* v10.10: only log the label when its content changed - the
             * periodic 100ms refresh was spamming DebugView/raycast_log.
             * v10.49: exclude dist (line2) from the dedup key - distance
             * changes every refresh, so including it logged every frame. */
            {
                static char s_last_label[256] = {0};
                char labsum[256];
                snprintf(labsum, sizeof(labsum), "%s|%s|%s|%d",
                    line_arch_f, line_rest, line3[0] ? line3 : "(none)", nslot);
                if (strcmp(s_last_label, labsum) != 0) {
                    strncpy(s_last_label, labsum, sizeof(s_last_label) - 1);
                    log_msg("[RAYCAST] label arch='%s' rest='%s' dist='%s' hash='%s' slots=%d\n",
                        line_arch_f, line_rest, line2, line3[0] ? line3 : "(none)", nslot);
                }
            }
            s->atlas_count = (uint32_t)g_atlas_nchars;
            memset(s->atlas_chars, 0, sizeof(s->atlas_chars));
            if (g_atlas_nbytes > 0)
                memcpy(s->atlas_chars, g_atlas_bytes, g_atlas_nbytes < (int)sizeof(s->atlas_chars) ? g_atlas_nbytes : (int)sizeof(s->atlas_chars));
            s->atlas_rev = g_atlas_rev;
            s->label_count = nslot;
            for (int k = 0; k < 96; k++) {
                s->label_slots[k] = (k < nslot) ? slots[k] : -1;
                s->label_widths[k] = (k < nslot) ? lwidths[k] : 0.0f;
            }
        }
    } else {
        s->flags &= ~1u;
        s->label_count = 0;
        s->label_slots[0] = -1;
    }
    s->seq++;
}

/* Read _G.rc_scan_boxes via Lua, serialize to string, parse into shm. */
static void shm_write_boxes(void) {
    if (!g_shm) shm_init();
    if (!g_shm) return;
    g_quiet_exec = 1;
    exec_lua(
        "local b = _G.rc_scan_boxes or {} "
        "local parts = {} "
        "for i = 1, math.min(#b, 256) do "
        "  local e = b[i] "
        "  if e and e[1] and e[2] and e[3] then "
        "    table.insert(parts, string.format('%.3f,%.3f,%.3f', e[1], e[2], e[3])) "
        "  end "
        "end "
        "return table.concat(parts, ';')"
    );
    g_quiet_exec = 0;
    struct rc_shm_data *s = g_shm;
    s->seq++;  // write-in-progress (seqlock)
    uint32_t n = 0;
    if (g_last_result[0]) {
        char buf[16384];
        strncpy(buf, g_last_result, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;
        char *tok = strtok(buf, ";");
        while (tok && n < RC_SHM_BOXES_MAX) {
            float a, b, c;
            if (sscanf(tok, "%f,%f,%f", &a, &b, &c) == 3) {
                struct rc_shm_box *bx = &s->boxes[n];
                bx->x = a; bx->y = b; bx->z = c;
                bx->hx = 0.25f; bx->hy = 0.25f; bx->hz = 0.25f;
                n++;
            }
            tok = strtok(NULL, ";");
        }
    }
    s->box_count = n;
    if (n > 0) s->flags |= 2u; else s->flags &= ~2u;
    s->seq++;
    log_msg("[RAYCAST] shm boxes=%u\n", n);
}


static int rc_safe_read8(uint64_t a, uint8_t *out) {
    __try { *out = *(volatile uint8_t *)a; return 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
static int rc_safe_read32(uint64_t a, uint32_t *out) {
    __try { *out = *(volatile uint32_t *)a; return 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
static int rc_safe_read64(uint64_t a, uint64_t *out) {
    __try { *out = *(volatile uint64_t *)a; return 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}


/* build version banner - printed once at load so we can ALWAYS tell which
 * DLL the injector actually loaded */
#define RC_BUILD_VER "v10.62"
static void rc_print_version_banner(void) {
    static volatile LONG done = 0;
    if (InterlockedExchange(&done, 1) == 0) {
        log_msg("[RAYCAST] hd2_raycast_hook %s built %s %s loaded (base=%p)\n",
            RC_BUILD_VER, __DATE__, __TIME__, (void *)GetModuleHandleA("game.dll"));
    }
}


/* Sync screen-space UI elements (ray line, hit mark, scan marks) from the
 * Lua-side projection (_G.rc_ui_s) into shared memory for the fx shader.
 * Projection runs inside exec_lua (lua_newthread + SEH isolation) so any
 * engine-API crash cannot take down the game. */
static void shm_write_ui(void) {
    if (!g_shm) shm_init();
    if (!g_shm) return;

    // Per-frame draw payload: suppress OK() logging for both exec_lua calls.
    // Bypass the segfault cooldown: this path only projects math into shared
    // memory and must stay live even when the 3D-line path crashed.
    g_quiet_exec = 1;
    g_exec_bypass = 1;
    exec_lua(
        "local S = stingray\n"
        "local w = S.Application.main_world()\n"
        "local okp, pose = pcall(S.World.debug_camera_pose, w)\n"
        "local ui = {}\n"
        "if okp and pose then\n"
        "  local okf, fw = pcall(S.Matrix4x4.forward, pose)\n"
        "  local okc, cm = pcall(S.Matrix4x4.translation, pose)\n"
        "  if okf and okc and fw and fw.x and cm and cm.x then\n"
        "    local camx, camy, camz = cm.x, cm.y, cm.z\n"
        "    local fx2, fy2, fz2 = fw.x, fw.y, fw.z\n"
        "-- camera basis: prefer engine right/up columns (handles pitch/roll);\n"
        "-- fall back to up=(0,1,0) construction only if they are unavailable\n"
        "    local rxx, rxy, rxz = -fz2, 0, fx2\n"
        "    local uxx, uxy, uxz = nil\n"
        "    local okr2, rv = pcall(S.Matrix4x4.right, pose)\n"
        "    if okr2 and rv and rv.x then\n"
        "      local rl2 = math.sqrt(rv.x*rv.x+rv.y*rv.y+rv.z*rv.z)\n"
        "      if rl2 > 1e-6 then rxx, rxy, rxz = rv.x/rl2, rv.y/rl2, rv.z/rl2 end\n"
        "    end\n"
        "    local oku2, uv2 = pcall(S.Matrix4x4.up, pose)\n"
        "    if oku2 and uv2 and uv2.x then\n"
        "      local ul2 = math.sqrt(uv2.x*uv2.x+uv2.y*uv2.y+uv2.z*uv2.z)\n"
        "      if ul2 > 1e-6 then uxx, uxy, uxz = uv2.x/ul2, uv2.y/ul2, uv2.z/ul2 end\n"
        "    end\n"
        "    if not uxx then\n"
        "      uxx, uxy, uxz = rxy*fz2-rxz*fy2, rxz*fx2-rxx*fz2, rxx*fy2-rxy*fx2\n"
        "      local ul = math.sqrt(uxx*uxx+uxy*uxy+uxz*uxz)\n"
        "      if ul > 1e-6 then uxx, uxy, uxz = uxx/ul, uxy/ul, uxz/ul end\n"
        "    end\n"
        "    -- stash camera basis for the C-side mesh outline projection\n"
        "    _G.rc_cam_pos = {camx, camy, camz}\n"
        "    _G.rc_cam_fwd = {fx2, fy2, fz2}\n"
        "    _G.rc_cam_right = {rxx, rxy, rxz}\n"
        "    _G.rc_cam_up = {uxx, uxy, uxz}\n"
        "    local rw, rh = 1920, 1080\n"
        "    local g = _G.rc_panel_gui\n"
        "    if g then local okrr, rr1, rr2 = pcall(S.Gui.render_resolution, g); if okrr and rr1 then rw, rh = rr1, rr2 end end\n"
        "    _G.rc_cam_rw, _G.rc_cam_rh = rw, rh\n"
        "    local fov = 90 * math.pi / 180\n"
        "    local fp = 1 / math.tan(fov/2)\n"
        "    local asp = rw / rh\n"
        "    local function proj(px2, py2, pz2)\n"
        "      local lx, ly, lz = px2-camx, py2-camy, pz2-camz\n"
        "      local vz2 = lx*fx2+ly*fy2+lz*fz2\n"
        "      if vz2 <= 0.05 then return nil end\n"
        "      local vx2 = lx*rxx+ly*rxy+lz*rxz\n"
        "      local vy2 = lx*uxx+ly*uxy+lz*uxz\n"
        "      local sx = (vx2*fp/asp/vz2*0.5+0.5)\n"
        "      local sy = (-vy2*fp/vz2*0.5+0.5)\n"
        "      return sx, sy\n"
        "    end\n"
        "    local vd = _G.rc_vd or 0\n"
        "    if vd > 0.5 and vd < 200 and _G.rc_vx then\n"
        "      local hxs, hys = proj(_G.rc_vx, _G.rc_vy, _G.rc_vz)\n"
        "      if hxs then table.insert(ui, 'H'..hxs..','..hys..',1') end\n"
        "    end\n"
        "    local hb = _G.rc_hitbox\n"
        "    if hb and #hb == 8 then\n"
        "      local pts = {}\n"
        "      local allok = true\n"
        "      for i3 = 1, 8 do\n"
        "        local e3 = hb[i3]\n"
        "        if e3 and e3[1] then\n"
        "          local x3, y3 = proj(e3[1], e3[2], e3[3])\n"
        "          if x3 then table.insert(pts, x3..','..y3) else table.insert(pts, '-1,-1'); allok = false end\n"
        "        else table.insert(pts, '-1,-1'); allok = false end\n"
        "      end\n"
        "      if allok then table.insert(ui, 'B'..table.concat(pts, '|')) end\n"
        "    end\n"
        "    local bxs = _G.rc_scan_boxes\n"
        "    local mcount = 0\n"
        "    if bxs then\n"
        "      -- hard cap first: huge lists made per-frame exec_lua SEH-crash\n"
        "      if #bxs > 128 then\n"
        "        local tcap = {}\n"
        "        for ic = 1, 128 do tcap[ic] = bxs[ic] end\n"
        "        bxs = tcap\n"
        "        _G.rc_scan_boxes = tcap\n"
        "      end\n"
        "      -- NOTE: no table.sort here. The scan already sorts+truncates the\n"
        "      -- list once; re-sorting every frame with a hand-written comparator\n"
        "      -- caused engine-level crashes (bad elements / weak ordering).\n"
        "      for i2 = 1, math.min(#bxs, 128) do\n"
        "        local e2 = bxs[i2]\n"
        "        if e2 and e2[1] then\n"
        "          local mxs, mys = proj(e2[1], e2[2], e2[3])\n"
        "          if mxs and mcount < 128 then\n"
        "            mcount = mcount + 1\n"
        "            table.insert(ui, 'M'..mxs..','..mys)\n"
        "          end\n"
        "        end\n"
        "      end\n"
        "    end\n"
        "    _G.rc_ui_mark_count = mcount\n"
        "    -- scan box wireframes (first 16 boxes, 8 corners each)\n"
        "    if bxs then\n"
        "      local fcount = 0\n"
        "      for i2 = 1, math.min(#bxs, 128) do\n"
        "        local e2 = bxs[i2]\n"
        "        if e2 and e2[1] and fcount < 16 then\n"
        "          local cx2, cy2, cz2 = e2[1], e2[2], e2[3]\n"
        "          local hsx, hsy, hsz = math.max(e2[4] or 0.25, 0.15), math.max(e2[5] or 0.25, 0.15), math.max(e2[6] or 0.25, 0.15)\n"
        "          local corners = {{cx2-hsx,cy2-hsy,cz2-hsz},{cx2+hsx,cy2-hsy,cz2-hsz},{cx2-hsx,cy2+hsy,cz2-hsz},{cx2+hsx,cy2+hsy,cz2-hsz},{cx2-hsx,cy2-hsy,cz2+hsz},{cx2+hsx,cy2-hsy,cz2+hsz},{cx2-hsx,cy2+hsy,cz2+hsz},{cx2+hsx,cy2+hsy,cz2+hsz}}\n"
        "          local pts = {}\n"
        "          local allok = true\n"
        "          for i4 = 1, 8 do\n"
        "            local c4 = corners[i4]\n"
        "            local x4, y4 = proj(c4[1], c4[2], c4[3])\n"
        "            if x4 then table.insert(pts, x4..','..y4) else table.insert(pts, '-1,-1'); allok = false end\n"
        "          end\n"
        "          if allok then\n"
        "            fcount = fcount + 1\n"
        "            table.insert(ui, 'F'..table.concat(pts, '|'))\n"
        "          end\n"
        "        end\n"
        "      end\n"
        "    end\n"
        "    _G.rc_ui_scanbox_count = fcount\n"
        "    -- method-comparison boxes: DISABLED (debug only, 4-color frames\n"
        "    -- were for eyeballing coordinate sources; the real mesh outline\n"
        "    -- + world_position(u,1) path is production now).\n"
        "  end\n"
        "end\n"
        "_G.rc_ui_s = table.concat(ui, ';')\n"
        "return 'ui'\n"
    );

    exec_lua("return _G.rc_ui_s or ''");
    g_quiet_exec = 0;
    g_exec_bypass = 0;
    struct rc_shm_data *s = g_shm;
    s->seq++;  // write-in-progress (seqlock)
    s->ui_line[0] = s->ui_line[1] = s->ui_line[2] = s->ui_line[3] = 0;
    s->ui_hit[0] = s->ui_hit[1] = s->ui_hit[2] = 0;
    for (int b = 0; b < 8; b++) { s->ui_hitbox[b][0] = -1.0f; s->ui_hitbox[b][1] = -1.0f; }
    s->ui_mark_count = 0;
    s->ui_scanbox_count = 0;
    for (int sb = 0; sb < 16; sb++)
        for (int c2 = 0; c2 < 8; c2++) { s->ui_scanbox[sb][c2][0] = -1.0f; s->ui_scanbox[sb][c2][1] = -1.0f; }
    for (int mb = 0; mb < 4; mb++)
        for (int c3 = 0; c3 < 8; c3++) { s->ui_mbox[mb][c3][0] = -1.0f; s->ui_mbox[mb][c3][1] = -1.0f; }
    if (g_last_result[0]) {
        char buf[16384];
        strncpy(buf, g_last_result, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;
        char *tok = strtok(buf, ";");
        while (tok) {
            if (tok[0] == 'L') {
                float x1, y1, x2, y2;
                if (sscanf(tok + 1, "%f,%f,%f,%f", &x1, &y1, &x2, &y2) == 4) {
                    s->ui_line[0] = (uint32_t)x1; s->ui_line[1] = (uint32_t)y1;
                    s->ui_line[2] = (uint32_t)x2; s->ui_line[3] = (uint32_t)y2;
                }
            } else if (tok[0] == 'H') {
                float x, y, on;
                if (sscanf(tok + 1, "%f,%f,%f", &x, &y, &on) == 3) {
                    s->ui_hit[0] = x; s->ui_hit[1] = y; s->ui_hit[2] = on;
                }
            } else if (tok[0] == 'B' || tok[0] == 'F') {
                /* B: hit box 8 corners. F: scan box wireframe corners.
                   Manual '|' split (strtok cannot nest). */
                int isF = (tok[0] == 'F');
                int box_idx = (isF && s->ui_scanbox_count < 16) ? (int)s->ui_scanbox_count : -1;
                char *start = tok + 1;
                int c = 0;
                while (c < 8) {
                    char *end = strchr(start, '|');
                    char tmp[32];
                    if (end) {
                        size_t n = (size_t)(end - start);
                        if (n > 31) n = 31;
                        memcpy(tmp, start, n); tmp[n] = 0;
                    } else {
                        strncpy(tmp, start, 31); tmp[31] = 0;
                    }
                    float x = -1.0f, y = -1.0f;
                    sscanf(tmp, "%f,%f", &x, &y);
                    if (isF && box_idx >= 0) { s->ui_scanbox[box_idx][c][0] = x; s->ui_scanbox[box_idx][c][1] = y; }
                    else { s->ui_hitbox[c][0] = x; s->ui_hitbox[c][1] = y; }
                    c++;
                    if (!end) break;
                    start = end + 1;
                }
                if (isF && box_idx >= 0) s->ui_scanbox_count++;
            } else if (tok[0] == 'C') {
                /* C<idx>:x1,y1|x2,y2|... method-comparison box (idx 0..3) */
                int mi = tok[1] - '0';
                if (mi >= 0 && mi < 4) {
                    char *start = tok + 2;
                    int c = 0;
                    while (c < 8) {
                        char *end = strchr(start, '|');
                        char tmp[32];
                        if (end) {
                            size_t n = (size_t)(end - start);
                            if (n > 31) n = 31;
                            memcpy(tmp, start, n); tmp[n] = 0;
                        } else {
                            strncpy(tmp, start, 31); tmp[31] = 0;
                        }
                        float x = -1.0f, y = -1.0f;
                        sscanf(tmp, "%f,%f", &x, &y);
                        s->ui_mbox[mi][c][0] = x;
                        s->ui_mbox[mi][c][1] = y;
                        c++;
                        if (!end) break;
                        start = end + 1;
                    }
                }
            } else if (tok[0] == 'M') {
                float x, y;
                if (sscanf(tok + 1, "%f,%f", &x, &y) == 2 && s->ui_mark_count < 128) {
                    s->ui_marks[s->ui_mark_count][0] = x;
                    s->ui_marks[s->ui_mark_count][1] = y;
                    s->ui_mark_count++;
                }
            }
            tok = strtok(NULL, ";");
        }
    }
    /* v3: hit-entity real mesh outline. Project the offline mesh vertices
     * (local space) through the entity's rotation+position (stashed by the
     * F4 hit branch) and the camera (stashed above), writing normalized
     * screen points for the fx shader to draw as a point cloud. */
    s->ui_mesh_count = 0;
    if (g_has_hit && s->hit_hash64) {
        MeshTableEntry *mt = mesh_table_find(s->hit_hash64);
        if (!mt) {
            /* hit an entity with no offline mesh table yet - queue it so the
             * on-demand builder can generate it while the game is unfocused */
            if (mesh_pending_add(s->hit_hash64))
                mesh_pending_save();
            /* v10.58: the previous code was silent about missing tables,
             * which made "outline didn't draw" impossible to diagnose.
             * Log the miss with the resolved path, throttled to 3s. */
            static DWORD last_mesh_miss_log = 0;
            DWORD now_mm = GetTickCount();
            if ((now_mm - last_mesh_miss_log) > 3000) {
                last_mesh_miss_log = now_mm;
                char mpath[MAX_PATH];
                mesh_table_path(mpath, sizeof(mpath), s->hit_hash64);
                log_msg("[RAYCAST] mesh outline SKIPPED: no table for hash=%llu path=%s (queued for builder)\n",
                    (unsigned long long)s->hit_hash64, mpath);
            }
        }
        if (mt && mt->nedges > 0) {
            g_quiet_exec = 1;
            g_exec_bypass = 1;
            /* v10.29: refresh the mesh-outline transform from the locked unit
             * independently of track (track stays at v10.25 logic). Runs on the
             * mesh projection cadence; any failure silently keeps old values. */
            exec_lua(
                "local u = _G.rc_hit_unit "
                "if u then pcall(function() "
                "local S = stingray "
                "if not S then return end "
                "local okw, w = pcall(S.Unit.world_position, u, 1) "
                "if okw and w and w.x then "
                "  local okp, po = pcall(S.Unit.world_pose, u, 1) "
                "  if okp and po then "
                "    local M = S.Matrix4x4 "
                "    local rv, uv, fv = M.right(po), M.up(po), M.forward(po) "
                "    if rv and uv and fv and rv.x and uv.x and fv.x then "
                "      local rl = math.sqrt(rv.x*rv.x+rv.y*rv.y+rv.z*rv.z) "
                "      local ul = math.sqrt(uv.x*uv.x+uv.y*uv.y+uv.z*uv.z) "
                "      local fl = math.sqrt(fv.x*fv.x+fv.y*fv.y+fv.z*fv.z) "
                "      if rl > 1e-6 and ul > 1e-6 and fl > 1e-6 then "
                "        _G.rc_mesh_pos = {w.x, w.y, w.z} "
                "        _G.rc_mesh_rot = {rv.x/rl,rv.y/rl,rv.z/rl, uv.x/ul,uv.y/ul,uv.z/ul, fv.x/fl,fv.y/fl,fv.z/fl} "
                "      end "
                "    end "
                "  end "
                "end "
                "end) end"
            );
            exec_lua(
                "local r = _G.rc_mesh_rot "
                "local p = _G.rc_mesh_pos "
                "local c = _G.rc_cam_pos "
                "local f = _G.rc_cam_fwd "
                "local rr = _G.rc_cam_right "
                "local u = _G.rc_cam_up "
                "if not r then return 'MISS rot' end "
                "if not p then return 'MISS pos' end "
                "if not c then return 'MISS cam' end "
                "if not f then return 'MISS fwd' end "
                "if not rr then return 'MISS right' end "
                "if not u then return 'MISS up' end "
                "return string.format('%.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f', "
                "r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9], p[1],p[2],p[3], c[1],c[2],c[3], f[1],f[2],f[3], rr[1],rr[2],rr[3], u[1],u[2],u[3])"
            );
            g_quiet_exec = 0;
            g_exec_bypass = 0;
            float rot[9], pos[3], cam[3], fwd[3], right[3], up[3];
            int nread = sscanf(g_last_result, "%f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f",
                &rot[0], &rot[1], &rot[2], &rot[3], &rot[4], &rot[5], &rot[6], &rot[7], &rot[8],
                &pos[0], &pos[1], &pos[2], &cam[0], &cam[1], &cam[2],
                &fwd[0], &fwd[1], &fwd[2], &right[0], &right[1], &right[2],
                &up[0], &up[1], &up[2]);
            /* diagnostics (throttled): why the mesh outline may not draw.
             * Disabled by default - spammy (2s cadence) and the SEH crash
             * loop it accompanies made the log useless. */
            if (0) {
            static DWORD mesh_diag_t0 = 0;
            DWORD mtick = GetTickCount();
            if (mtick - mesh_diag_t0 > 2000) {
                mesh_diag_t0 = mtick;
                log_msg("[RAYCAST] meshdiag: hash=%llu table=%p nread=%d first='%.60s'\n",
                    (unsigned long long)s->hit_hash64, (void*)mt, nread, g_last_result);
            }
            }
            if (nread == 24) {
                float rw = 1920.0f, rh = 1080.0f;
                g_quiet_exec = 1; g_exec_bypass = 1;
                exec_lua("return string.format('%.0f %.0f', _G.rc_cam_rw or 1920, _G.rc_cam_rh or 1080)");
                g_quiet_exec = 0; g_exec_bypass = 0;
                float a = 1920, b = 1080;
                if (sscanf(g_last_result, "%f %f", &a, &b) == 2 && a > 0 && b > 0) { rw = a; rh = b; }
                float asp = rw / rh;
                float fp = 1.0f / (float)tan(90.0 * 3.14159265 / 360.0);

                /* ---- v10.62: v10.55 adaptive mesh normalization (RESTORED) ----
                 * User request: the v10.55 projection (NOT the v10.59 Z-up
                 * rework, NOT the v10.29 legacy fallback) is the intended
                 * line-outline logic. Restored verbatim from git 54d886b. */
                float box_cx = pos[0], box_cy = pos[1], box_cz = pos[2];
                float box_hx = 0, box_hy = 0, box_hz = 0;
                int have_box = 0;
                g_quiet_exec = 1; g_exec_bypass = 1;
                exec_lua(
                    "local u = _G.rc_hit_unit "
                    "if u then "
                    "  local ok_b, b1, b2 = pcall(stingray.Unit.box, u) "
                    "  if ok_b and b1 and b2 and b1.x and b2.x then "
                    "    if b2.x >= b1.x and b2.y >= b1.y and b2.z >= b1.z then "
                    "      return string.format('%.4f %.4f %.4f %.4f %.4f %.4f', (b1.x+b2.x)/2,(b1.y+b2.y)/2,(b1.z+b2.z)/2,(b2.x-b1.x)/2,(b2.y-b1.y)/2,(b2.z-b1.z)/2) "
                    "    else "
                    "      return string.format('%.4f %.4f %.4f %.4f %.4f %.4f', b1.x,b1.y,b1.z,b2.x/2,b2.y/2,b2.z/2) "
                    "    end "
                    "  end "
                    "end "
                    "return ''"
                );
                g_quiet_exec = 0; g_exec_bypass = 0;
                if (sscanf(g_last_result, "%f %f %f %f %f %f",
                    &box_cx, &box_cy, &box_cz, &box_hx, &box_hy, &box_hz) == 6) {
                    if (box_hx > 0.02f && box_hy > 0.02f && box_hz > 0.02f &&
                        box_hx < 500.0f && box_hy < 500.0f && box_hz < 500.0f)
                        have_box = 1;
                }
                float mmin[3] = {1e9f,1e9f,1e9f}, mmax[3] = {-1e9f,-1e9f,-1e9f};
                if (have_box) {
                    for (uint32_t vi = 0; vi < mt->nverts; vi++) {
                        float x = mt->verts[vi][0], y = mt->verts[vi][1], z = mt->verts[vi][2];
                        if (x < mmin[0]) mmin[0] = x; if (x > mmax[0]) mmax[0] = x;
                        if (y < mmin[1]) mmin[1] = y; if (y > mmax[1]) mmax[1] = y;
                        if (z < mmin[2]) mmin[2] = z; if (z > mmax[2]) mmax[2] = z;
                    }
                }
                float mcenter[3] = {(mmin[0]+mmax[0])/2,(mmin[1]+mmax[1])/2,(mmin[2]+mmax[2])/2};
                float mspan[3] = {mmax[0]-mmin[0],mmax[1]-mmin[1],mmax[2]-mmin[2]};
                float sclx = 1, scly = 1, sclz = 1;
                int up_is_z = 1; /* 1=Z-up, 0=Y-up, -1=X-up */
                if (have_box && mspan[0] > 1e-4f && mspan[1] > 1e-4f && mspan[2] > 1e-4f) {
                    float bh = 2.0f * box_hy; /* box height, world up = Y */
                    float r0 = mspan[0] / bh, r1 = mspan[1] / bh, r2 = mspan[2] / bh;
                    float d0 = (float)fabs(logf(r0)), d1 = (float)fabs(logf(r1)), d2 = (float)fabs(logf(r2));
                    int up = (d0 < d1) ? ((d0 < d2) ? 0 : 2) : ((d1 < d2) ? 1 : 2);
                    up_is_z = (up == 2) ? 1 : (up == 1 ? 0 : -1);
                    if (up_is_z == 1) {          /* mesh Z = up: x->bx, z->bh, y->bz */
                        sclx = (2*box_hx) / mspan[0];
                        scly = (2*box_hz) / mspan[1];
                        sclz = bh / mspan[2];
                    } else if (up_is_z == 0) {   /* mesh Y = up: direct */
                        sclx = (2*box_hx) / mspan[0];
                        scly = bh / mspan[1];
                        sclz = (2*box_hz) / mspan[2];
                    } else {                     /* mesh X = up: x->bh, y->bz, z->bx */
                        sclx = bh / mspan[0];
                        scly = (2*box_hz) / mspan[1];
                        sclz = (2*box_hx) / mspan[2];
                    }
                } else if (have_box) {
                    have_box = 0; /* degenerate mesh AABB, fall back */
                }

                /* project every vertex once */
                float spx[MESH_VERTS_MAX], spy[MESH_VERTS_MAX];
                unsigned char spv[MESH_VERTS_MAX];
                for (uint32_t vi = 0; vi < mt->nverts; vi++) {
                    spv[vi] = 0;
                    float wx, wy, wz;
                    if (have_box) {
                        /* normalized local -> unit-local -> world:
                         * world = box_center + R * axis_map((local-mid)*scale) */
                        float lx = (mt->verts[vi][0] - mcenter[0]) * sclx;
                        float ly = (mt->verts[vi][1] - mcenter[1]) * scly;
                        float lz = (mt->verts[vi][2] - mcenter[2]) * sclz;
                        float ux, uy, uz;
                        if (up_is_z == 1)      { ux = lx; uy = lz; uz = ly; }
                        else if (up_is_z == 0) { ux = lx; uy = ly; uz = lz; }
                        else                   { ux = lz; uy = lx; uz = ly; }
                        wx = box_cx + rot[0]*ux + rot[6]*uz + rot[3]*uy;
                        wy = box_cy + rot[1]*ux + rot[7]*uz + rot[4]*uy;
                        wz = box_cz + rot[2]*ux + rot[8]*uz + rot[5]*uy;
                    } else {
                        /* v10.29 legacy path: world = pos + R * local (Z-up) */
                        float lx = mt->verts[vi][0], ly = mt->verts[vi][1], lz = mt->verts[vi][2];
                        wx = pos[0] + rot[0]*lx + rot[6]*ly + rot[3]*lz;
                        wy = pos[1] + rot[1]*lx + rot[7]*ly + rot[4]*lz;
                        wz = pos[2] + rot[2]*lx + rot[8]*ly + rot[5]*lz;
                    }
                    float cx = wx - cam[0], cy = wy - cam[1], cz = wz - cam[2];
                    float vz = cx*fwd[0] + cy*fwd[1] + cz*fwd[2];
                    if (vz <= 0.05f) continue;
                    float vx = cx*right[0] + cy*right[1] + cz*right[2];
                    float vy = cx*up[0] + cy*up[1] + cz*up[2];
                    float sx = (vx * fp / asp / vz * 0.5f + 0.5f);
                    float sy = (-vy * fp / vz * 0.5f + 0.5f);
                    if (sx < -0.05f || sx > 1.05f || sy < -0.05f || sy > 1.05f) continue;
                    spx[vi] = sx; spy[vi] = sy; spv[vi] = 1;
                }
                /* emit projected edges as endpoint pairs (2 pts per edge).
                 * Capped at 3072 points (1536 edges) to match HD2HUD.fx's
                 * rc_mesh[3072] - the effect's D3D11 constant buffer cannot
                 * exceed 4096 float4 entries (8192 would fail to compile
                 * and hang the game at startup). */
                uint32_t out = 0;
                for (uint32_t ei = 0; ei < mt->nedges && out + 1 < 3072; ei++) {
                    uint16_t ia = mt->edges[ei][0], ib = mt->edges[ei][1];
                    if (!spv[ia] || !spv[ib]) continue;   /* either endpoint behind cam */
                    s->ui_mesh[out][0] = spx[ia]; s->ui_mesh[out][1] = spy[ia]; out++;
                    s->ui_mesh[out][0] = spx[ib]; s->ui_mesh[out][1] = spy[ib]; out++;
                }
                s->ui_mesh_count = out;
            }
        }
    }
    s->seq++;
}



static void rc_set_feedback(const char *fmt, ...);

/* on-screen command feedback (rendered as row 5 of the F4 label by the
 * addon/fx pipeline; g_feedback_ts drives the 6s expiry in shm_write_hit) */
static void rc_set_feedback(const char *fmt, ...)
{
    if (!g_shm) return;
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_shm->cmd_feedback, sizeof(g_shm->cmd_feedback), fmt, args);
    va_end(args);
    g_feedback_ts = GetTickCount64();
}



// ============================================================
// Hash lookup table loaded from 哈希对照表.txt (generated offline
// from Excel + HD2SDK friendlynames). Used to name hashes in-game.
// ============================================================
typedef struct { uint64_t hash; char name[160]; } HashEntry;
static HashEntry g_htab[32768];
static int g_htab_count = 0;

// Is this token a source marker (4th column)? The file mixes 4 and 5 column
// rows: "dec hex thin name" vs "dec hex thin src name". Source tokens are
// +-prefixed or start with one of {SDK, Excel, AH, Dump} (also covers
// combos like "Excel/SDK" or "AH/Dump" since they start with a whitelist
// word). ONLY the first whitespace-delimited segment is checked - a name
// like "SDK scope thing" must not be mistaken for a source marker.
static int is_src_token(const char *t) {
    if (!t || !*t) return 0;
    if (t[0] == '+') return 1;
    const char *p = t;
    while (*p && *p != '/' && *p != ' ' && *p != '\t' && *p != '\n') p++;
    int n = (int)(p - t);
    if (n == 3 && strncmp(t, "SDK", 3) == 0) return 1;
    if (n == 5 && strncmp(t, "Excel", 5) == 0) return 1;
    if (n == 2 && strncmp(t, "AH", 2) == 0) return 1;
    if (n == 4 && strncmp(t, "Dump", 4) == 0) return 1;
    return 0;
}

// Parse a hash-table line. See is_src_token for the mixed-format handling.
static int parse_htab_line(char *line, uint64_t *dec, char *name, int name_sz) {
    char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p < '0' || *p > '9') return 0;
    *dec = strtoull(p, &p, 10);
    for (int k = 0; k < 2; k++) {           // skip hex, thin
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '\n') return 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
    }
    while (*p == ' ' || *p == '\t') p++;
    if (!*p || *p == '\n') return 0;
    if (is_src_token(p)) {                   // source marker, skip to name
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '\n') return 0;
    }
    char *end = p + strlen(p);               // trim trailing ws/newline
    while (end > p && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\n' || end[-1] == '\r')) end--;
    int n = (int)(end - p);
    if (n >= name_sz) n = name_sz - 1;
    memcpy(name, p, n);
    name[n] = 0;
    return 1;
}

static int htab_cmp(const void *a, const void *b) {
    uint64_t ha = ((const HashEntry *)a)->hash;
    uint64_t hb = ((const HashEntry *)b)->hash;
    return (ha < hb) ? -1 : (ha > hb) ? 1 : 0;
}

static void load_hash_table(void) {
    if (g_htab_count) return;
    FILE *f = rc_fopen_utf8(RC_DIR "哈希对照表.txt", "r");
    if (!f) {
        log_msg("%s", "[RAYCAST] hash table not found (skip name lookup)\n");
        return;
    }
    char buf[512];
    fgets(buf, sizeof(buf), f); // header
    while (fgets(buf, sizeof(buf), f) && g_htab_count < 32768) {
        uint64_t dec;
        char name[200];
        if (parse_htab_line(buf, &dec, name, (int)sizeof(name))) {
            g_htab[g_htab_count].hash = dec;
            snprintf(g_htab[g_htab_count].name, sizeof(g_htab[0].name), "%s", name);
            g_htab_count++;
        }
    }
    fclose(f);
    // hash_lookup uses binary search - sort here instead of trusting the
    // file's order (a shuffled file previously made lookups silently fail).
    if (g_htab_count > 1)
        qsort(g_htab, (size_t)g_htab_count, sizeof(HashEntry), htab_cmp);
    log_msg("[RAYCAST] hash table loaded: %d entries\n", g_htab_count);
}

static const char *hash_lookup(uint64_t h) {
    if (!g_htab_count) return NULL;
    // binary search (table sorted by dec)
    int lo = 0, hi = g_htab_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (g_htab[mid].hash == h) return g_htab[mid].name;
        if (g_htab[mid].hash < h) lo = mid + 1; else hi = mid - 1;
    }
    return NULL;
}

// forward decl (defined later in file)
static void install_update_drawer(void);
static void crash_skip_add(int idx);
static int crash_skip_has(int idx);
static void draw_3d_lines_game_thread(void);
static volatile int g_scan_boxes_dirty = 0;

// ============================================================
// Numpad1 - Entity scan: enumerate World.entities, extract the
// 64-bit hash from resource_name's "#ID[<16hex>]" representation,
// dedupe, and output one hash per line for Excel comparison.
// ============================================================
static void scan_nearby_units(void) {
    log_msg("%s", "[RAYCAST] === Numpad1: Entity hash scan ===\n");
    load_hash_table();
    load_mesh_tables();
    install_update_drawer();
    // Stop Lua GC for the scan (same reason as do_raycast: heavy per-entity
    // compilation -> GC -> engine finalizer crash at fixed RIP).
    if (f_lua_gc && g_L) f_lua_gc(g_L, LUA_GCSTOP, 0);

    // Step 1: get unit list into _G.rc_ents.
    // World.units(w) returns ALL units (dynamic spawns: enemies, player,
    // props). World.entities(w) misses most units on planets (nearly all
    // entries report dead / no hash there). units first, entities fallback.
    exec_lua(
        "local S = stingray "
        "local w = S.Application.main_world() "
        "local okp, pose = pcall(S.World.debug_camera_pose, w) "
        "if okp and pose then local cm = S.Matrix4x4.translation(pose) _G.rc_cam = {cm.x, cm.y, cm.z} "
        "local okf2, fw2 = pcall(S.Matrix4x4.forward, pose) "
        "if okf2 and fw2 and fw2.x then _G.rc_cam_fwd = {fw2.x, fw2.y, fw2.z} end end "
        "_G.rc_ents = {} "
        "local nunits, nent = -1, -1 "
        "local ok1, u1 = pcall(S.World.units, w) "
        "if ok1 and type(u1) == 'table' then _G.rc_ents = u1; nunits = #u1 end "
        "local ok2, e2 = pcall(S.World.entities, w) "
        "if ok2 and type(e2) == 'table' then nent = #e2 end "
        "if nunits <= 0 and nent > 0 then _G.rc_ents = e2 end "
        "return 'units='..nunits..' entities='..nent"
    );

    // parse count BEFORE any further exec_lua (they overwrite g_last_result)
    // Prefer the units= count (World.units is the primary source).
    int nents = 0;
    const char *ru = strstr(g_last_result, "units=");
    if (ru) {
        int u = atoi(ru + 6);
        if (u > 0) nents = u;
    }
    if (nents <= 0) {
        const char *r0 = strstr(g_last_result, "entities=");
        if (r0) nents = atoi(r0 + 9);
    }
    if (nents <= 0) {
        log_msg("[RAYCAST] no units (%s)\n", g_last_result[0] ? g_last_result : "?");
        return;
    }
    if (nents > 20000) nents = 20000;
    log_msg("[RAYCAST] %s -> scanning %d units\n", g_last_result, nents);

    // clear the scan-box list (populated per-entity below, drawn by Present hook)
    exec_lua("_G.rc_scan_boxes = {}");

    int seen = 0, alive_n = 0, crashed = 0, skipped = 0;
    uint64_t seen_hashes[4096];
    int seen_count = 0;

    // Define the per-entity probe ONCE through the SEH-protected exec_lua
    // path (a raw luaL_loadstring+setglobal on the live state hung the
    // game; exec_lua cannot). rc_add_box is defined first so the probe is a
    // lean call; the loop below calls rc_scan_probe(i) on a FRESH coroutine
    // per unit, removing the per-unit ~4KB loadstring that froze the game
    // for many seconds over 20k planet units.
    {
        exec_lua(
            "if not rc_add_box then "
            "rc_add_box = function(x, y, z, hx2, hy2, hz2, d2) "
            "  local b = _G.rc_scan_boxes "
            "  if not b then return end "
            "  local n = #b "
            "  if n < 64 then "
            "    local pos = n + 1 "
            "    for i = 1, n do if b[i][7] > d2 then pos = i break end end "
            "    table.insert(b, pos, {x, y, z, hx2, hy2, hz2, d2}) "
            "  else "
            "    if d2 < b[64][7] then "
            "      b[64] = {x, y, z, hx2, hy2, hz2, d2} "
            "      for i = 63, 1, -1 do "
            "        if b[i][7] > b[i+1][7] then b[i], b[i+1] = b[i+1], b[i] else break end "
            "      end "
            "    end "
            "  end "
            "end "
            "end");
        char def[4096];
        snprintf(def, sizeof(def),
            "function rc_scan_probe(i0) "
            "local ents = _G.rc_ents "
            "local u = ents[i0] "
            "if not u then return 'oob' end "
            "local S = stingray "
            "local oka, a = pcall(S.Unit.alive, u) "
            "-- skip dead entities early (dead ones crash on resource_name/box)\n"
            "if not oka or not a then return 'dead' end "
            "local okr, rn = pcall(S.Unit.resource_name, u) "
            "local s = okr and tostring(rn) or '' "
            "local h = s and s:match('#ID%%[%%x+%%]') "
            "if not h then return 'nohash' end "
            "local hexfull = h:sub(5, -2) "
            "-- world center + half-size for scan box (world-anchor space)\n"
            "local px, py, pz, hx2, hy2, hz2\n"
            "-- world_position(u,1) FIRST (node=1 = root scene-graph node ->\n"
            "-- real world coords, verified in F4). box/local_position are\n"
            "-- local-space garbage for most HD2 units, keep as fallback only.\n"
            "local ok_wp1, wp1 = pcall(S.Unit.world_position, u, 1)\n"
            "if ok_wp1 and wp1 and wp1.x and (math.abs(wp1.x) > 1 or math.abs(wp1.y) > 1 or math.abs(wp1.z) > 1) then\n"
            "  px, py, pz = wp1.x, wp1.y, wp1.z\n"
            "end\n"
            "if not px then\n"
            "  local ok_b2, bA, bB = pcall(S.Unit.box, u)\n"
            "  if ok_b2 and bA and bA.x then\n"
            "    if bB and bB.x and bB.x >= bA.x and bB.y >= bA.y and bB.z >= bA.z then\n"
            "      px = (bA.x+bB.x)/2; py = (bA.y+bB.y)/2; pz = (bA.z+bB.z)/2\n"
            "      hx2 = (bB.x-bA.x)/2; hy2 = (bB.y-bA.y)/2; hz2 = (bB.z-bA.z)/2\n"
            "    else\n"
            "      px, py, pz = bA.x, bA.y, bA.z\n"
            "      hx2, hy2, hz2 = bB.x/2, bB.y/2, bB.z/2\n"
            "    end\n"
            "  end\n"
            "end\n"
            "if not px then\n"
            "  local ok_np, np = pcall(S.Unit.local_position, u, 0)\n"
            "  if ok_np and np and np.x then px, py, pz = np.x, np.y, np.z end\n"
            "end\n"
            "-- point-sized degenerate box = player self / attached helpers\n"
            "-- (F4's 'pointbox' rule). Hide it before the 0.25 default below\n"
            "-- so the player's own body never gets a screen-space box.\n"
            "local ok_b0, b0A, b0B = pcall(S.Unit.box, u)\n"
            "if ok_b0 and b0A and b0A.x and b0B and b0B.x then\n"
            "  if math.abs(b0B.x) <= 0.02 and math.abs(b0B.y) <= 0.02 and math.abs(b0B.z) <= 0.02 then return 'point' end\n"
            "end\n"
            "if not hx2 then hx2, hy2, hz2 = 0.25, 0.25, 0.25 end\n"
            "if px and _G.rc_scan_boxes then\n"
            "  if (px ~= 0 or py ~= 0 or pz ~= 0) and (px ~= 1 or py ~= 1 or pz ~= 1) then\n"
            "    local cc = _G.rc_cam\n"
            "    if cc and cc[1] then\n"
            "      local d2 = (px-cc[1])^2 + (py-cc[2])^2 + (pz-cc[3])^2\n"
            "      -- own-cluster exclusion: only units within 1m of the lens\n"
            "      -- are the player's held gear (F4 uses the same 1m self\n"
            "      -- rule). Everything at >=1m - including targets you stand\n"
            "      -- next to - is kept.\n"
            "      if d2 >= 1.0 and d2 <= 90000 then "
            "        -- player-root exclusion: the camera sits ~2.2m BEHIND the\n"
            "        -- player, so the player's own body + attached gear\n"
            "        -- (weapon, backpack, stratagem) all live within ~2m of\n"
            "        -- P = cam - fwd*2.2 while staying 1-3m from the lens.\n"
            "        -- A real target 1m in FRONT of the lens is ~3.2m from P\n"
            "        -- and survives the cut.\n"
            "        local cf = _G.rc_cam_fwd\n"
            "        if cf and cf[1] then\n"
            "          local prx, pry, prz = cc[1]-cf[1]*2.2, cc[2]-cf[2]*2.2, cc[3]-cf[3]*2.2\n"
            "          local dr2 = (px-prx)^2 + (py-pry)^2 + (pz-prz)^2\n"
            "          if dr2 < 4.0 then return 'selfgear' end\n"
            "        end\n"
            "        rc_add_box(px, py, pz, hx2, hy2, hz2, d2) "
            "end\n"
            "    else\n"
            "      rc_add_box(px, py, pz, hx2, hy2, hz2, 1e18)\n"
            "    end\n"
            "  end\n"
            "end\n"
            "local diag = px and string.format('c=(%%.1f,%%.1f,%%.1f)', px, py, pz) or 'nobox'\n"
            "return hexfull, tostring(tonumber(hexfull:sub(1, 8), 16) or 0), '1', diag "
            "end");
        exec_lua(def);
    }

    for (int i = 1; i <= nents; i++) {
        // progress log every 500 entities (planet missions can have 10k+)
        if (i % 500 == 0) {
            log_msg("[RAYCAST] scan progress %d/%d\n", i, nents);
        }
        // Crash recovery: after an SEH the engine's Lua state may need a
        // moment to settle; a short sleep + the crash_skip registry keeps
        // the scan complete without risking a corrupted main state.
        // (1ms: the old 5ms per crash added ~5s to 20k-unit planet scans
        // that hit 1000+ stale-handle crashes near the player's own units.)
        if (g_segfault_flag) {
            Sleep(1);
            InterlockedExchange(&g_segfault_flag, 0);
            log_msg("[RAYCAST] resumed after SEH crash (idx=%d)\n", i);
        }
        // Skip known crashers (same registry as F4)
        if (crash_skip_has(i)) continue;
        // OUTER SEH (same protection as the F4 loop): a crash in
        // newthread/loadstring/result-parsing/settop must not silently
        // kill the game main thread - log it, crash-skip the entity,
        // and stop the scan instead of cascading.
        __try {
        int top = f_lua_gettop(g_L);
        lua_State *T = f_lua_newthread(g_L);
        if (!T) break;

        /* lua_getglobal is a Lua 5.1 MACRO (not exported) - use lua_getfield
         * with LUA_GLOBALSINDEX (-10002) instead. */
        f_lua_getfield(T, -10002, "rc_scan_probe");
        f_lua_pushnumber(T, (double)i);
        int sehere = 0;
        __try {
            o_lua_pcall(T, 1, 4, 0);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedExchange(&g_segfault_flag, 1);
            g_segfault_tick = GetTickCount();
            crashed++;
            sehere = 1;
            if (crashed <= 20) {
                log_msg("[RAYCAST] SEH crash at idx=%d code=0x%08X\n", i, GetExceptionCode());
            }
            crash_skip_add(i);
        }
        if (!sehere) {
            const char *s0 = f_lua_tolstring(T, 1, NULL);
            if (s0 && s0[0]) {
                if (i <= 5) {
                    const char *d0 = f_lua_tolstring(T, 4, NULL);
                    log_msg("[RAYCAST] scan unit[%d] st=%s %s\n", i, s0, d0 ? d0 : "");
                }
                if (strcmp(s0, "oob") != 0 && strcmp(s0, "nohash") != 0 && strcmp(s0, "dead") != 0) {
                    // s0 is a 16-char hex hash
                    uint64_t h = 0;
                    int okh = 1;
                    for (int k = 0; k < 16; k++) {
                        char c = s0[k];
                        int d;
                        if (c >= '0' && c <= '9') d = c - '0';
                        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                        else { okh = 0; break; }
                        h = (h << 4) | d;
                    }
                    if (okh) {
                        int dup = 0;
                        for (int k = 0; k < seen_count; k++) {
                            if (seen_hashes[k] == h) { dup = 1; break; }
                        }
                        if (!dup && seen_count < 4096) {
                            seen_hashes[seen_count++] = h;
                            const char *nm = hash_lookup(h);
                            const char *posd = f_lua_tolstring(T, 4, NULL);  // "c=(x,y,z)" or "nobox"
                            log_msg("[RAYCAST] %016llx thin=%llu%s%s%s%s\n",
                                (unsigned long long)h,
                                (unsigned long long)(h >> 32),
                                posd && posd[0] ? " @ " : "", posd && posd[0] ? posd : "",
                                nm ? "  -> " : "",
                                nm ? nm : "");
                            seen++;
                        }
                        if (f_lua_tolstring(T, 3, NULL) && strcmp(f_lua_tolstring(T, 3, NULL), "1") == 0)
                            alive_n++;
                    }
                }
            }
        }
        f_lua_settop(g_L, top);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Crash outside the pcall SEH (newthread/loadstring/parsing/
            // settop). Record the offending entity, mark crash, and stop
            // the scan rather than risk a cascade on a corrupt L state.
            uintptr_t rip2 = 0;
            PEXCEPTION_POINTERS ep2 = GetExceptionInformation();
            if (ep2 && ep2->ContextRecord) rip2 = (uintptr_t)ep2->ContextRecord->Rip;
            HMODULE lua2 = GetModuleHandleA("lua51.dll");
            if (lua2 && rip2 >= (uintptr_t)lua2 && rip2 < (uintptr_t)lua2 + 0x200000)
                log_msg("[RAYCAST] SCAN LOOP SEH idx=%d code=0x%08X rip=lua51+0x%llX (scan aborted)\n",
                    i, GetExceptionCode(), (unsigned long long)(rip2 - (uintptr_t)lua2));
            else
                log_msg("[RAYCAST] SCAN LOOP SEH idx=%d code=0x%08X rip=0x%llX (scan aborted)\n",
                    i, GetExceptionCode(), (unsigned long long)rip2);
            InterlockedExchange(&g_segfault_flag, 1);
            g_segfault_tick = GetTickCount();
            crash_skip_add(i);
            break;
        }
    }

    log_msg("[RAYCAST] scan done: unique=%d alive=%d crashed=%d skipped=%d\n",
        seen, alive_n, crashed, skipped);

    // Drop every box within 1m of the camera (safety net for the same
    // self-cluster the in-scan d2>=1.0 filter excludes: held gear right at
    // the lens). Real targets at >=1m are never touched, so standing next
    // to an enemy/terminal keeps its box.
    __try {
        g_quiet_exec = 1;
        g_exec_bypass = 1;
        exec_lua(
            "local b = _G.rc_scan_boxes "
            "if b and #b > 0 then "
            "  local keep = {} "
            "  for i = 1, #b do "
            "    local d = b[i][7] or 1e30 "
            "    if d >= 1.0 then keep[#keep + 1] = b[i] end "
            "  end "
            "  _G.rc_scan_boxes = keep "
            "end "
            "return 'ok'");
        g_quiet_exec = 0;
        g_exec_bypass = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_quiet_exec = 0;
        g_exec_bypass = 0;
        log_msg("%s", "[RAYCAST] self-box removal SEH (skipped)\n");
    }

    g_scan_boxes_dirty = 1;

    // Publish scan boxes to the ReShade addon (shared memory)
    shm_write_boxes();

    // Re-enable Lua GC (was stopped at scan start); SEH-protected with retry.
    gc_restart_safe();
}

// MurmurHash2 64-bit - the Stingray IdString64 hash. m/r/seed match the
// game (verified: "content/env_ship/hangar/bay_12m_doors" ->
// 0x99bf6b9ee8b02fe8). Unaligned reads are fine on x64 Windows.
static uint64_t murmur2_64(const void *key, size_t len) {
    const uint64_t m = 0xc6a4a7935bd1e995ULL;
    const int r = 47;
    uint64_t h = 0ULL ^ (len * m);
    const uint8_t *data = (const uint8_t *)key;
    while (len >= 8) {
        uint64_t k;
        memcpy(&k, data, 8);
        k *= m; k ^= k >> r; k *= m;
        h ^= k; h *= m;
        data += 8; len -= 8;
    }
    switch (len) {
    case 7: h ^= (uint64_t)data[6] << 48; /* fallthrough */
    case 6: h ^= (uint64_t)data[5] << 40; /* fallthrough */
    case 5: h ^= (uint64_t)data[4] << 32; /* fallthrough */
    case 4: h ^= (uint64_t)data[3] << 24; /* fallthrough */
    case 3: h ^= (uint64_t)data[2] << 16; /* fallthrough */
    case 2: h ^= (uint64_t)data[1] << 8;  /* fallthrough */
    case 1: h ^= (uint64_t)data[0]; h *= m;
    }
    h ^= h >> r; h *= m; h ^= h >> r;
    return h;
}

// ============================================================
// Visualization: draw 3D wireframe box + 2D text panel for hit
// ============================================================
static int g_viz_probed = 0;
static int g_viz_step = 0;  // diagnostic step counter

static void draw_visualization(void) {
    if (!g_has_hit) return;

    // One-time API probe - ENUMERATE ONLY. Never create engine objects here:
    // create_line_object / create_screen_gui on the game (script) thread can
    // hang or trip the anti-cheat (observed: main thread stalled right after
    // "Drawing viz" with no crash report - a stall, not an exception).
    if (!g_viz_probed) {
        g_viz_probed = 1;
        exec_lua(
            "local S = stingray\n"
            "local parts = {}\n"
            "table.insert(parts, 'LineObject='..type(S.LineObject))\n"
            "if type(S.LineObject) == 'table' then\n"
            "  local ms = {}\n"
            "  for k,v in pairs(S.LineObject) do table.insert(ms, k) end\n"
            "  table.sort(ms)\n"
            "  table.insert(parts, 'LO.methods='..table.concat(ms, ','))\n"
            "end\n"
            "table.insert(parts, 'create_line_object='..type(S.World.create_line_object))\n"
            "table.insert(parts, 'create_screen_gui='..type(S.World.create_screen_gui))\n"
            "table.insert(parts, 'Gui.text='..tostring(type(S.Gui.text)))\n"
            "table.insert(parts, 'Gui.rect='..tostring(type(S.Gui.rect)))\n"
            "table.insert(parts, 'Vector3='..tostring(type(S.Vector3)))\n"
            "table.insert(parts, 'Color='..tostring(type(S.Color)))\n"
            "return table.concat(parts, ' | ')\n"
        );
    }

    // Set hit info in Lua globals
    char set_code[256];
    snprintf(set_code, sizeof(set_code),
        "_G.rc_vx=%f _G.rc_vy=%f _G.rc_vz=%f _G.rc_vd=%f",
        g_hit_x, g_hit_y, g_hit_z, g_hit_dist);
    exec_lua(set_code);

    // Clear SEH flag for step diagnosis (lua_newthread isolates crashes)
    if (g_segfault_flag) {
        DWORD elapsed = GetTickCount() - g_segfault_tick;
        if (elapsed > 200) {
            InterlockedExchange(&g_segfault_flag, 0);
        } else {
            return;
        }
    }

    // NOTE: 2D panel is drawn by the _G.update wrapper; 3D lines by
    // draw_3d_lines_game_thread() from hk_lua_pcall (both game thread).
}


// ============================================================
// Crash-skip registry: entity indices that reliably SEH-crash are
// recorded here and skipped on subsequent scans (avoids repeated
// crashes + cooldown blocking while keeping the scan complete).
// Persisted to a file so a NEW process/session skips the crashers
// from the start (crashers are stable indices, e.g. 2/4/5 on the
// ship) instead of crashing once to learn them.
// ============================================================
static int g_crash_skip[8192];
static int g_crash_skip_count = 0;

#define CRASH_SKIP_FILE RC_DIR "crash_skip.txt"

static void crash_skip_load(void) {
    /* v10.44: the skip registry is PER-SESSION. Entity array indices change
     * every mission, so persisting last session's crashed indices across
     * restarts wrongly skips valid entities this session (e.g. the FRV
     * landing on a previously-crashed index -> "FRV not found"). Reset the
     * file on load so each session starts with a clean registry; indices
     * crashed DURING this session are still skipped (correct: same session,
     * same entity array). */
    g_crash_skip_count = 0;
    FILE *f = fopen(CRASH_SKIP_FILE, "w");
    if (f) fclose(f);
    log_msg("[RAYCAST] crash-skip registry reset (per-session)\n");
}

static void crash_skip_save(void) {
    FILE *f = fopen(CRASH_SKIP_FILE, "w");
    if (!f) return;
    for (int k = 0; k < g_crash_skip_count; k++) {
        fprintf(f, "%d\n", g_crash_skip[k]);
    }
    fclose(f);
}

static void crash_skip_add(int idx) {
    for (int k = 0; k < g_crash_skip_count; k++) {
        if (g_crash_skip[k] == idx) return;
    }
    if (g_crash_skip_count < 8192) {
        g_crash_skip[g_crash_skip_count++] = idx;
        if (g_crash_skip_count <= 20) {
            log_msg("[RAYCAST] crash-skip registry +%d (total %d)\n", idx, g_crash_skip_count);
        }
        crash_skip_save();
    }
}

static int crash_skip_has(int idx) {
    for (int k = 0; k < g_crash_skip_count; k++) {
        if (g_crash_skip[k] == idx) return 1;
    }
    return 0;
}

// ============================================================
/* v10.24: real-time tracking WITHOUT enumeration. F4's rc_f4_probe
 * already stores the locked unit in _G.rc_hit_unit; tracking just reads
 * world_position on that unit directly - one call, zero traversal, and
 * no Lua memory growth (no per-tick tables/strings). */
static void track_locked_target(void) {
    if (!g_tracking || !g_L) return;
    if (g_segfault_flag) return;
    static int def_done = 0;
    if (!def_done) {
        def_done = 1;
        exec_lua(
            "function rc_f4_track_fast() "
            "local u = _G.rc_hit_unit "
            "if not u then return 0, 'nou' end "
            "local S = stingray "
            "if not S then return 0, 'nostingray' end "
            "local ok_a, a = pcall(S.Unit.alive, u) "
            "if not ok_a or not a then return 0, ok_a and 'dead' or 'alive-err' end "
            "local ok_w, w = pcall(S.Unit.world_position, u, 1) "
            "if not ok_w or not w or not w.x then return 0, ok_w and 'nowp' or 'wp-err' end "
            "local wcx, wcy, wcz = w.x, w.y, w.z "
            "local ok_c, c = pcall(S.Application.main_world) "
            "local ok_p, pose = pcall(S.World.debug_camera_pose, ok_c and c or nil) "
            "local cmx, cmy, cmz = 0, 0, 0 "
            "if ok_p and pose then "
            "  local M = S.Matrix4x4 "
            "  local t = M.translation(pose) "
            "  cmx, cmy, cmz = t.x, t.y, t.z "
            "end "
            "_G.rc_hitbox = {{wcx-0.5,wcy-0.5,wcz-0.5},{wcx+0.5,wcy-0.5,wcz-0.5},{wcx-0.5,wcy+0.5,wcz-0.5},{wcx+0.5,wcy+0.5,wcz-0.5},{wcx-0.5,wcy-0.5,wcz+0.5},{wcx+0.5,wcy-0.5,wcz+0.5},{wcx-0.5,wcy+0.5,wcz+0.5},{wcx+0.5,wcy+0.5,wcz+0.5}} "
            "_G.rc_vx, _G.rc_vy, _G.rc_vz = wcx, wcy, wcz "
            "_G.rc_vd = math.sqrt((wcx-cmx)^2 + (wcy-cmy)^2 + (wcz-cmz)^2) "
            "return 1, wcx, wcy, wcz, cmx, cmy, cmz "
            "end"
        );
    }

    int top = f_lua_gettop(g_L);
    lua_State *T = f_lua_newthread(g_L);
    if (!T) return;
    if (f_luaL_loadstring(T, "return rc_f4_track_fast()") == 0) {
        __try {
            o_lua_pcall(T, 0, 7, 0);
            int st = (int)f_lua_tonumber(T, 1);
            if (st == 1) {
                g_track_fail_count = 0;
                /* v10.30: incremental Lua GC step every ~2s so the per-tick
                 * table churn (rc_hitbox/rc_vx/...) is collected without a
                 * stop-the-world pause; SEH-guarded against the engine
                 * finalizer crash the full GC run causes during scans. */
                static int gc_step_n = 0;
                if (++gc_step_n >= 10) {
                    gc_step_n = 0;
                    __try { if (f_lua_gc && g_L) f_lua_gc(g_L, LUA_GCSTEP, 50); }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
                g_hit_x = (float)f_lua_tonumber(T, 2);
                g_hit_y = (float)f_lua_tonumber(T, 3);
                g_hit_z = (float)f_lua_tonumber(T, 4);
                g_cam_x = (float)f_lua_tonumber(T, 5);
                g_cam_y = (float)f_lua_tonumber(T, 6);
                g_cam_z = (float)f_lua_tonumber(T, 7);
                float dx = g_hit_x - g_cam_x, dy = g_hit_y - g_cam_y, dz = g_hit_z - g_cam_z;
                g_hit_dist = sqrtf(dx * dx + dy * dy + dz * dz);
                g_has_hit = 1;
                static int ok_log = 0;
                if ((++ok_log % 5) == 1)
                    log_msg("[RAYCAST] track ok: dist=%.1f pos=(%.1f,%.1f,%.1f)\n",
                        g_hit_dist, g_hit_x, g_hit_y, g_hit_z);
            } else if (st == 0) {
                /* v10.28: report WHY tracking failed (reason string returned
                 * by the Lua fn) and only stop after 5 consecutive fails so
                 * transient alive/wp hiccups don't freeze the visuals. */
                const char *reason = f_lua_tolstring(T, 2, NULL);
                if (!reason) reason = "?";
                g_track_fail_count++;
                if (g_track_fail_count <= 3 || (g_track_fail_count % 20) == 0)
                    log_msg("[RAYCAST] track: locked unit lost (%s) fail#%d\n", reason, g_track_fail_count);
                if (g_track_fail_count >= 5) {
                    g_tracking = 0;
                    log_msg("[RAYCAST] track: giving up after %d consecutive fails\n", g_track_fail_count);
                }
            } else {
                g_track_fail_count = 0;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedExchange((volatile LONG *)&g_segfault_flag, 1);
            g_segfault_tick = GetTickCount();
            log_msg("[RAYCAST] track SEH 0x%08X\n", GetExceptionCode());
        }
    }
    f_lua_settop(g_L, top);
}

// ============================================================
static void do_raycast(void) {
    log_msg("%s", "[RAYCAST] === F4: Raycast ===\n");
    load_hash_table();
    load_mesh_tables();
    install_update_drawer();
    // Stop Lua GC for the scan. Per-entity compilation of ~12KB chunks
    // allocates heavily; the resulting GC runs trigger engine userdata
    // finalizers that crash the game thread at a fixed RIP (observed
    // 0x7FFAFE29C204 at idx=3/6/7). Restart at the end of this function.
    if (f_lua_gc && g_L) f_lua_gc(g_L, LUA_GCSTOP, 0);
    log_msg("[RAYCAST] addon status=%d (0=none 1=reg 3=reg+shm 7=+fx-ready 9=reg+fx-failed)\n",
        hd2_addon_status());
    {
        const char *aerr = hd2_addon_last_error();
        if (aerr && aerr[0]) log_msg("[RAYCAST] addon last-error: %s\n", aerr);
    }

    // Step 1: Camera pos + forward + store entities in _G.rc_ents
    InterlockedExchange(&g_segfault_flag, 0);
    if (g_L && f_luaL_loadstring && o_lua_pcall && f_lua_newthread && f_lua_tonumber) {
        int top = f_lua_gettop(g_L);
        lua_State *T = f_lua_newthread(g_L);
        if (T) {
            const char *code =
                "local S = stingray\n"
                "local w = S.Application.main_world()\n"
                "local M = S.Matrix4x4\n"
                "local pose = S.World.debug_camera_pose(w)\n"
                "local cam = M.translation(pose)\n"
                "local fwd = M.forward(pose)\n"
                "-- World.units first (dynamic spawns), World.entities fallback\n"
                "local cnt = 0\n"
                "local ok1, u1 = pcall(S.World.units, w)\n"
                "if ok1 and type(u1) == 'table' and #u1 > 0 then _G.rc_ents = u1; cnt = #u1\n"
                "else local ok2, e2 = pcall(S.World.entities, w)\n"
                "  if ok2 and type(e2) == 'table' then _G.rc_ents = e2; cnt = #e2 end\n"
                "end\n"
                "return cam.x, cam.y, cam.z, fwd.x, fwd.y, fwd.z, cnt";

            if (f_luaL_loadstring(T, code) == 0) {
                __try {
                    o_lua_pcall(T, 0, 7, 0);
                    g_cam_x = (float)f_lua_tonumber(T, 1);
                    g_cam_y = (float)f_lua_tonumber(T, 2);
                    g_cam_z = (float)f_lua_tonumber(T, 3);
                    g_fwd_x = (float)f_lua_tonumber(T, 4);
                    g_fwd_y = (float)f_lua_tonumber(T, 5);
                    g_fwd_z = (float)f_lua_tonumber(T, 6);
                    int cnt = (int)f_lua_tonumber(T, 7);
                    g_ents_cnt = cnt;
                    log_msg("[RAYCAST] cam=(%.1f,%.1f,%.1f) fwd=(%.3f,%.3f,%.3f) ents=%d\n",
                        g_cam_x, g_cam_y, g_cam_z, g_fwd_x, g_fwd_y, g_fwd_z, cnt);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    log_msg("[RAYCAST] Step1 SEH 0x%08X\n", GetExceptionCode());
                }
            }
            f_lua_settop(g_L, top);
        }
    }

    // Step 2: Try each entity individually with SEH protection.
    // PERFORMANCE: the per-entity Lua is compiled ONCE into a reusable
    // closure `rc_f4_proc(i)`; the loop just calls it with the index. This
    // removes ~N luaL_loadstring calls per F4 (was 4-5 s at 5000 units,
    // and the cap itself missed targets on planets with 20k units).
    int max_try = g_ents_cnt;
    if (max_try <= 0 || max_try > 40000) max_try = 40000;
    int hits = 0, crashed = 0, dead = 0, box_fail = 0, miss = 0;
    int nolp_n = 0, huge_n = 0, inside_n = 0;
    int axis_n = 0, behind_n = 0, no_overlap_n = 0, too_far_n = 0;
    int dist_buckets[7] = {0, 0, 0, 0, 0, 0, 0};
    int mode_minmax = 0, mode_center = 0, mode_struct = 0, mode_posfb = 0;
    int pointbox_n = 0;
    float g_aim_cos[5] = {0, 0, 0, 0, 0};
    int g_aim_idx[5] = {0, 0, 0, 0, 0};
    float g_aim_t[5] = {0, 0, 0, 0, 0};
    float g_aim_cd[5] = {0, 0, 0, 0, 0};
    // cone (loose) fallback slot: remembered separately, only promoted to a
    // real hit when NO strict slab hit exists anywhere.
    float g_cone_dist = 9999.0f;
    char g_cone_rn[256] = {0};
    char g_cone_nh[64] = {0};
    int hits_c = 0;
    int g_cha_diag_count = 0;
    g_has_hit = 0;
    g_hit_dist = 9999.0f;
    // Clear the 2D panel for this frame - only set on hit.
    // rc_hit_d tracks the CLOSEST STRICT (slab) hit across all per-entity
    // pcalls. Loose cone hits go to rc_cone_* (fallback slot) so a nearby
    // object inside the wide cone can never steal the wireframe from the
    // object the ray actually passes through.
    exec_lua("_G.rc_vd = -1 _G.rc_hitbox = nil _G.rc_hit_d = nil _G.rc_cone_d = nil _G.rc_cone_hitbox = nil _G.rc_cone_vx = nil _G.rc_cone_vy = nil _G.rc_cone_vz = nil _G.rc_cone_unit = nil");

    // Per-entity probe: define the probe ONCE through the SEH-protected
    // exec_lua path (a raw luaL_loadstring+setglobal on the live state hung
    // the game's main thread - zombie; exec_lua uses the same protected
    // machinery as every other exec call and cannot zombie). The loop below
    // fetches and calls rc_f4_probe(i) on a FRESH coroutine per unit, which
    // removes the per-unit loadstring cost (4-5s at 5000 units, far worse
    // on 20k-unit planets).
    {
        char def[13000];
        snprintf(def, sizeof(def),
            "function rc_f4_probe(i0) "
            "local ents = _G.rc_ents "
            "if not ents then return 'noents' end "
            "local u = ents[i0] "
            "if not u then return 'oob' end "
            "local S = stingray\n"
            "local ok_a, a = pcall(S.Unit.alive, u)\n"
            "if not ok_a or not a then return 'dead' end\n"
            "local ok_rn, rn = pcall(S.Unit.resource_name, u)\n"
            "local rn_str = ok_rn and tostring(rn) or '?'\n"
            "local ok_nh, nh = pcall(S.Unit.name_hash, u)\n"
            "local nh_str = ok_nh and tostring(nh) or '?'\n"
            "-- Unit.box: dual interpretation -> LOCAL min/max + center/half-size\n"
            "-- (04:18 session hit proved box center IS usable directly in world space:\n"
            "--  units sit on the ship anchor origin; camera is ~22m away in the hull.)\n"
            "local ok_b, b1, b2 = pcall(S.Unit.box, u)\n"
            "if not ok_b then return 'boxfail', rn_str, nh_str end\n"
            "local wcx, wcy, wcz, hx, hy, hz, boxmode\n"
            "if b1 and b2 and b1.x ~= nil and b2.x ~= nil then\n"
            "  if b2.x >= b1.x and b2.y >= b1.y and b2.z >= b1.z then\n"
            "    wcx = (b1.x+b2.x)/2; wcy = (b1.y+b2.y)/2; wcz = (b1.z+b2.z)/2\n"
            "    hx = (b2.x-b1.x)/2; hy = (b2.y-b1.y)/2; hz = (b2.z-b1.z)/2\n"
            "    boxmode = 'minmax'\n"
            "  else\n"
            "    wcx, wcy, wcz = b1.x, b1.y, b1.z\n"
            "    hx, hy, hz = b2.x/2, b2.y/2, b2.z/2\n"
            "    boxmode = 'center'\n"
            "  end\n"
            "elseif b1 and b1.center then\n"
            "  wcx, wcy, wcz = b1.center.x, b1.center.y, b1.center.z\n"
            "  hx, hy, hz = b1.size.x/2, b1.size.y/2, b1.size.z/2\n"
            "  boxmode = 'struct'\n"
            "else\n"
            "  -- Unit.box unavailable on most planet units: fall back to\n"
            "  -- world_position node 1 as a point target (0.5m slab) so the\n"
            "  -- ray can still hit vehicles/entities the box API cannot see.\n"
            "  local ok_w, w = pcall(S.Unit.world_position, u, 1)\n"
            "  if ok_w and w and w.x and (math.abs(w.x) > 1 or math.abs(w.y) > 1 or math.abs(w.z) > 1) then\n"
            "    wcx, wcy, wcz = w.x, w.y, w.z\n"
            "    hx, hy, hz = 0.5, 0.5, 0.5\n"
            "    boxmode = 'posfb'\n"
            "  else return 'badbox', rn_str, nh_str end\n"
            "end\n"
            "-- Degenerate center fallback: local_position (world fns all return fake values)\n"
            "if not (wcx and wcy and wcz) or ((wcx == 0 and wcy == 0 and wcz == 0) or (wcx == 1 and wcy == 1 and wcz == 1)) then\n"
            "  local ok_p, p = pcall(S.Unit.local_position, u, 0)\n"
            "  if ok_p and p and p.x then wcx, wcy, wcz = p.x, p.y, p.z; boxmode = boxmode..'+posfb' end\n"
            "end\n"
            "if not wcx then return 'nolp', rn_str, nh_str end\n"
            "-- point-sized degenerate boxes (player self, helpers): skip, not a target\n"
            "if hx <= 0.001 and hy <= 0.001 and hz <= 0.001 then return 'pointbox', rn_str, nh_str end\n"
            "-- min visual thickness for wireframes (flat boxes look stuck in the floor)\n"
            "local mhx, mhy, mhz = math.max(hx, 0.15), math.max(hy, 0.15), math.max(hz, 0.15)\n"
            "-- camera pos as locals first; compute distance via vars, not inline floats\n"
            "-- (negative cam coords inline would produce '--' which Lua reads as a comment)\n"
            "local ox, oy, oz = _G.rc_f4_ox, _G.rc_f4_oy, _G.rc_f4_oz\n"
            "local cdist = math.sqrt((wcx-ox)^2 + (wcy-oy)^2 + (wcz-oz)^2)\n"
            "-- v10.57: huge filter relaxed 10m -> 50m half-size. Units with a\n"
            "-- box half > 50m are treated as world/terrain background and\n"
            "-- skipped; large interactables (ship parts, big props - the\n"
            "-- entities players actually aim at) now participate in hit\n"
            "-- detection instead of being silently dropped (was: >10m skip,\n"
            "-- which made big targets unscannable while small near units won).\n"
            "if hx > 50 or hy > 50 or hz > 50 then return 'huge', rn_str, nh_str, wcx, wcy, wcz, hx, hy, hz, cdist, 'huge', boxmode end\n"
            "-- World-space AABB from center + half-size\n"
            "local minx, miny, minz = wcx - hx, wcy - hy, wcz - hz\n"
            "local maxx, maxy, maxz = wcx + hx, wcy + hy, wcz + hz\n"
            "-- Camera ray direction (precomputed in C)\n"
            "local dx, dy, dz = _G.rc_f4_dx, _G.rc_f4_dy, _G.rc_f4_dz\n"
            "-- slab: ray vs AABB intersection, returns hit distance or nil\n"
            "local function slab(ox0, oy0, oz0, minx0, miny0, minz0, maxx0, maxy0, maxz0)\n"
            "  local tm0, tx0 = -1e30, 1e30\n"
            "  if dx ~= 0 then\n"
            "    local t1 = (minx0 - ox0) / dx\n"
            "    local t2 = (maxx0 - ox0) / dx\n"
            "    if t1 > t2 then t1, t2 = t2, t1 end\n"
            "    if t1 > tm0 then tm0 = t1 end\n"
            "    if t2 < tx0 then tx0 = t2 end\n"
            "  elseif ox0 < minx0 or ox0 > maxx0 then return nil end\n"
            "  if dy ~= 0 then\n"
            "    local t1 = (miny0 - oy0) / dy\n"
            "    local t2 = (maxy0 - oy0) / dy\n"
            "    if t1 > t2 then t1, t2 = t2, t1 end\n"
            "    if t1 > tm0 then tm0 = t1 end\n"
            "    if t2 < tx0 then tx0 = t2 end\n"
            "  elseif oy0 < miny0 or oy0 > maxy0 then return nil end\n"
            "  if dz ~= 0 then\n"
            "    local t1 = (minz0 - oz0) / dz\n"
            "    local t2 = (maxz0 - oz0) / dz\n"
            "    if t1 > t2 then t1, t2 = t2, t1 end\n"
            "    if t1 > tm0 then tm0 = t1 end\n"
            "    if t2 < tx0 then tx0 = t2 end\n"
            "  elseif oz0 < minz0 or oz0 > maxz0 then return nil end\n"
            "  if tx0 < tm0 or tx0 <= 0 then return nil end\n"
            "  return math.max(tm0, 0)\n"
            "end\n"
            "-- strict slab on prefab box (static objects sit at their box center)\n"
            "local dbox = slab(ox, oy, oz, minx, miny, minz, maxx, maxy, maxz)\n"
            "local reason = 'miss'\n"
            "if dbox then\n"
            "  if dbox <= 0.01 then reason = 'inside'\n"
            "  elseif dbox > 200 then reason = 'too-far'\n"
            "  else\n"
            "    if dbox <= 100 and (not _G.rc_hit_d or dbox < _G.rc_hit_d) then\n"
            "      _G.rc_hit_d = dbox\n"
            "      _G.rc_hit_unit = u\n"
            "      _G.rc_hitbox = {{wcx-mhx,wcy-mhy,wcz-mhz},{wcx+mhx,wcy-mhy,wcz-mhz},{wcx-mhx,wcy+mhy,wcz-mhz},{wcx+mhx,wcy+mhy,wcz-mhz},{wcx-mhx,wcy-mhy,wcz+mhz},{wcx+mhx,wcy-mhy,wcz+mhz},{wcx-mhx,wcy+mhy,wcz+mhz},{wcx+mhx,wcy+mhy,wcz+mhz}}\n"
            "      _G.rc_vx, _G.rc_vy, _G.rc_vz = wcx, wcy, wcz\n"
            "      _G.rc_vd = dbox\n"
            "    end\n"
            "    return 'hit', rn_str, nh_str, wcx, wcy, wcz, hx, hy, hz, cdist, 'hit', dbox, boxmode end\n"
            "end\n"
            "-- loose hit: cone test - box center within ~18deg of ray direction.\n"
            "-- Fallback only: writes rc_cone_* (never steals the strict slot),\n"
            "-- and returns 'hit-c' so C never compares it against real hits.\n"
            "local lxx, lyy, lzz = wcx-ox, wcy-oy, wcz-oz\n"
            "local tproj = lxx*dx + lyy*dy + lzz*dz\n"
            "local cosv = -1\n"
            "if cdist > 0.001 then cosv = tproj / cdist end\n"
            "if tproj > 0 and tproj < 30 and cosv >= 0.95 then\n"
            "  if tproj <= 100 and (not _G.rc_cone_d or tproj < _G.rc_cone_d) then\n"
            "    _G.rc_cone_d = tproj\n"
            "    _G.rc_cone_unit = u\n"
            "    _G.rc_cone_hitbox = {{wcx-mhx,wcy-mhy,wcz-mhz},{wcx+mhx,wcy-mhy,wcz-mhz},{wcx-mhx,wcy+mhy,wcz-mhz},{wcx+mhx,wcy+mhy,wcz-mhz},{wcx-mhx,wcy-mhy,wcz+mhz},{wcx+mhx,wcy-mhy,wcz+mhz},{wcx-mhx,wcy+mhy,wcz+mhz},{wcx+mhx,wcy+mhy,wcz+mhz}}\n"
            "    _G.rc_cone_vx, _G.rc_cone_vy, _G.rc_cone_vz = wcx, wcy, wcz\n"
            "  end\n"
            "  return 'hit-c', rn_str, nh_str, wcx, wcy, wcz, hx, hy, hz, cdist, 'loose', tproj, boxmode, tproj, cosv\n"
            "end\n"
            "-- world_position candidate: dynamic entities (NPCs) do not sit at\n"
            "-- their prefab box center; build an instance AABB and strict-slab it.\n"
            "-- node=1 is the ROOT scene-graph node (verified: node=0 -> off=-1 ->\n"
            "-- garbage (1,1,1); node=1 -> real world position).\n"
            "local ok_wp, wp = pcall(S.Unit.world_position, u, 1)\n"
            "if ok_wp and wp and wp.x and (math.abs(wp.x) > 1 or math.abs(wp.y) > 1 or math.abs(wp.z) > 1) then\n"
            "  local lx2, ly2, lz2 = wp.x-ox, wp.y-oy, wp.z-oz\n"
            "  local t2 = lx2*dx + ly2*dy + lz2*dz\n"
            "  local c2 = math.sqrt(lx2*lx2+ly2*ly2+lz2*lz2)\n"
            "  if c2 < 1.0 then return 'self', rn_str, nh_str end\n"
            "  local cos2 = -1\n"
            "  if c2 > 0.001 then cos2 = t2 / c2 end\n"
            "  local dwp = slab(ox, oy, oz, wp.x-hx, wp.y-hy, wp.z-hz, wp.x+hx, wp.y+hy, wp.z+hz)\n"
            "  if dwp and dwp > 0.01 and dwp <= 200 then\n"
            "    if dwp <= 100 and (not _G.rc_hit_d or dwp < _G.rc_hit_d) then\n"
            "      _G.rc_hit_d = dwp\n"
            "      _G.rc_hit_unit = u\n"
            "      _G.rc_vx, _G.rc_vy, _G.rc_vz = wp.x, wp.y, wp.z\n"
            "      _G.rc_vd = dwp\n"
            "      local obb = false\n"
            "      local okpo, po = pcall(S.Unit.world_pose, u, 1)\n"
            "      if okpo and po then\n"
            "        local rv2 = S.Matrix4x4.right(po)\n"
            "        local uv2 = S.Matrix4x4.up(po)\n"
            "        local fv2 = S.Matrix4x4.forward(po)\n"
            "        if rv2 and uv2 and fv2 and rv2.x and uv2.x and fv2.x then\n"
            "          local rl = math.sqrt(rv2.x*rv2.x+rv2.y*rv2.y+rv2.z*rv2.z)\n"
            "          local ul = math.sqrt(uv2.x*uv2.x+uv2.y*uv2.y+uv2.z*uv2.z)\n"
            "          local fl = math.sqrt(fv2.x*fv2.x+fv2.y*fv2.y+fv2.z*fv2.z)\n"
            "          if rl > 1e-6 and ul > 1e-6 and fl > 1e-6 then\n"
            "            local rx2, ry2, rz2 = rv2.x/rl, rv2.y/rl, rv2.z/rl\n"
            "            local ux2, uy2, uz2 = uv2.x/ul, uv2.y/ul, uv2.z/ul\n"
            "            local fx2, fy2, fz2 = fv2.x/fl, fv2.y/fl, fv2.z/fl\n"
            "            local function oc(sx, sy, sz) return {wp.x+sx*rx2+sy*ux2+sz*fx2, wp.y+sx*ry2+sy*uy2+sz*fy2, wp.z+sx*rz2+sy*uz2+sz*fz2} end\n"
            "            _G.rc_hitbox = {oc(-mhx,-mhy,-mhz),oc(mhx,-mhy,-mhz),oc(-mhx,mhy,-mhz),oc(mhx,mhy,-mhz),oc(-mhx,-mhy,mhz),oc(mhx,-mhy,mhz),oc(-mhx,mhy,mhz),oc(mhx,mhy,mhz)}\n"
            "            _G.rc_obb = 1\n"
            "            obb = true\n"
            "            -- real-mesh outline: stash the unit's rotation basis so the\n"
            "            -- C side can transform offline mesh_verts_<hash>.txt local\n"
            "            -- vertices into world space (rows of the rotation matrix).\n"
            "            _G.rc_mesh_rot = {rx2,ry2,rz2, ux2,uy2,uz2, fx2,fy2,fz2}\n"
            "            _G.rc_mesh_pos = {wp.x, wp.y, wp.z}\n"
            "          end\n"
            "        end\n"
            "      end\n"
            "      if not obb then\n"
            "        _G.rc_hitbox = {{wp.x-mhx,wp.y-mhy,wp.z-mhz},{wp.x+mhx,wp.y-mhy,wp.z-mhz},{wp.x-mhx,wp.y+mhy,wp.z-mhz},{wp.x+mhx,wp.y+mhy,wp.z-mhz},{wp.x-mhx,wp.y-mhy,wp.z+mhz},{wp.x+mhx,wp.y-mhy,wp.z+mhz},{wp.x-mhx,wp.y+mhy,wp.z+mhz},{wp.x+mhx,wp.y+mhy,wp.z+mhz}}\n"
            "        _G.rc_obb = 0\n"
            "      end\n"
            "    end\n"
            "    return 'hit', rn_str, nh_str, wp.x, wp.y, wp.z, hx, hy, hz, c2, 'wp', dwp, boxmode, dwp, cos2\n"
            "  end\n"
            "  if t2 > 0 and t2 < 30 and cos2 >= 0.95 then\n"
            "    if t2 <= 100 and (not _G.rc_cone_d or t2 < _G.rc_cone_d) then\n"
            "      _G.rc_cone_d = t2\n"
            "      _G.rc_cone_hitbox = {{wp.x-mhx,wp.y-mhy,wp.z-mhz},{wp.x+mhx,wp.y-mhy,wp.z-mhz},{wp.x-mhx,wp.y+mhy,wp.z-mhz},{wp.x+mhx,wp.y+mhy,wp.z-mhz},{wp.x-mhx,wp.y-mhy,wp.z+mhz},{wp.x+mhx,wp.y-mhy,wp.z+mhz},{wp.x-mhx,wp.y+mhy,wp.z+mhz},{wp.x+mhx,wp.y+mhy,wp.z+mhz}}\n"
            "      _G.rc_cone_vx, _G.rc_cone_vy, _G.rc_cone_vz = wp.x, wp.y, wp.z\n"
            "    end\n"
            "    return 'hit-c', rn_str, nh_str, wp.x, wp.y, wp.z, hx, hy, hz, c2, 'wp-c', t2, boxmode, t2, cos2\n"
            "  end\n"
            "end\n"
            "-- Near-miss diagnostics: any unit within 30m that failed to hit\n"
            "-- gets its box coords surfaced, so dynamic entities (captain,\n"
            "-- soldiers, bugs) with local-space boxes are visible instead of\n"
            "-- silently missing. Character-class names get priority.\n"
            "local diag = ''\n"
            "local ischar = rn_str and (rn_str:find('cha_', 1, true) or rn_str:find('soldier', 1, true) or rn_str:find('bug', 1, true) or rn_str:find('enemy', 1, true) or rn_str:find('hulk', 1, true) or rn_str:find('overseer', 1, true) or rn_str:find('voteless', 1, true) or rn_str:find('harvester', 1, true) or rn_str:find('admiral', 1, true) or rn_str:find('helmsman', 1, true) or rn_str:find('mechanic', 1, true))\n"
            "if ischar or (cdist and cdist < 30) then\n"
            "  diag = string.format('CHA box=(%%.2f,%%.2f,%%.2f) half=(%%.2f,%%.2f,%%.2f) cdist=%%.1f%%s', wcx, wcy, wcz, hx, hy, hz, cdist, ischar and ' [char]' or '')\n"
            "end\n"
            "return 'miss', rn_str, nh_str, wcx, wcy, wcz, hx, hy, hz, cdist, reason, -1, diag, tproj, cosv "
            "end");
        exec_lua(def);
        // camera values read by the probe through _G (same values the old
        // per-unit string embedded via %f)
        char gs[256];
        snprintf(gs, sizeof(gs),
            "_G.rc_f4_ox=%.6f _G.rc_f4_oy=%.6f _G.rc_f4_oz=%.6f "
            "_G.rc_f4_dx=%.6f _G.rc_f4_dy=%.6f _G.rc_f4_dz=%.6f",
            g_cam_x, g_cam_y, g_cam_z, g_fwd_x, g_fwd_y, g_fwd_z);
        exec_lua(gs);
    }

    for (int i = 1; i <= max_try; i++) {
        if (g_segfault_flag) {
            Sleep(1);
            InterlockedExchange(&g_segfault_flag, 0);
            if (crashed <= 20) log_msg("[RAYCAST] F4 resumed after crash (idx=%d)\n", i);
        }
        if (crash_skip_has(i)) continue;
        // Progress tick every 128 entities: if the game thread dies mid-scan
        // (hang or crash outside the pcall SEH), the log pinpoints the last
        // idx that started processing.
        if ((i & 127) == 1 || i == max_try)
            log_msg("[RAYCAST] F4 idx=%d/%d\n", i, max_try);
        // OUTER SEH: protects the parts of the per-entity loop that the inner
        // pcall __try does NOT cover (newthread/result parsing/settop). A
        // crash there previously killed the game main thread silently.
        volatile int f4_step = 0;   // 1=gettop 2=newthread 3=push 5=pcall 6=parse 7=settop
        __try {
        f4_step = 1;
        int top = f_lua_gettop(g_L);
        f4_step = 2;
        lua_State *T = f_lua_newthread(g_L);
        if (!T) break;

        f4_step = 3;
        /* lua_getglobal/lua_setglobal are MACROS in Lua 5.1, NOT exported
         * from lua51.dll - GetProcAddress returns NULL and calling it AVs
         * at rip=0. Use lua_getfield with LUA_GLOBALSINDEX (-10002), which
         * IS exported. */
        f_lua_getfield(T, -10002, "rc_f4_probe");
        f_lua_pushnumber(T, (double)i);

        int sehere = 0;
        f4_step = 5;
        __try {
            o_lua_pcall(T, 1, 13, 0);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedExchange(&g_segfault_flag, 1);
            g_segfault_tick = GetTickCount();
            crashed++;
            sehere = 1;
            if (crashed <= 20) {
                uintptr_t rip = 0;
                PEXCEPTION_POINTERS ep = GetExceptionInformation();
                if (ep && ep->ContextRecord) rip = (uintptr_t)ep->ContextRecord->Rip;
                HMODULE lua = GetModuleHandleA("lua51.dll");
                if (lua && rip >= (uintptr_t)lua && rip < (uintptr_t)lua + 0x200000)
                    log_msg("[RAYCAST] F4 SEH idx=%d code=0x%08X rip=lua51+0x%llX\n", i, GetExceptionCode(), (unsigned long long)(rip - (uintptr_t)lua));
                else
                    log_msg("[RAYCAST] F4 SEH idx=%d code=0x%08X rip=0x%llX\n", i, GetExceptionCode(), (unsigned long long)rip);
            }
            crash_skip_add(i);
        }

        f4_step = 6;
        if (!sehere) {
            const char *status = f_lua_tolstring(T, 1, NULL);
            if (status) {
                // Full diagnostic for the first 8 units (verbose mode only;
                // continuous mode stays quiet to avoid log flooding)
                if (i <= 8 && g_verbose_log) {
                    const char *rn0 = f_lua_tolstring(T, 2, NULL);
                    const char *mode0 = f_lua_tolstring(T, 13, NULL);
                    const char *rs0 = f_lua_tolstring(T, 11, NULL);
                    log_msg("[RAYCAST] unit[%d] st=%s mode=%s c=(%.1f,%.1f,%.1f) h=(%.2f,%.2f,%.2f) cdist=%.1f rs=%s d=%g\n",
                        i, status, mode0 ? mode0 : "?",
                        (float)f_lua_tonumber(T, 4), (float)f_lua_tonumber(T, 5), (float)f_lua_tonumber(T, 6),
                        (float)f_lua_tonumber(T, 7), (float)f_lua_tonumber(T, 8), (float)f_lua_tonumber(T, 9),
                        (float)f_lua_tonumber(T, 10), rs0 ? rs0 : "?", (float)f_lua_tonumber(T, 12));
                }
                if (strcmp(status, "hit") == 0) {
                    float dist = (float)f_lua_tonumber(T, 12);
                    const char *rn = f_lua_tolstring(T, 2, NULL);
                    const char *nh = f_lua_tolstring(T, 3, NULL);
                    hits++;
                    if (g_verbose_log) {
                        uint64_t hh = 0;
                        if (rn) {
                            const char *p = strstr(rn, "#ID[");
                            if (p) hh = (uint64_t)strtoull(p + 4, NULL, 16);
                        }
                        const char *nm = hh ? hash_lookup(hh) : NULL;
                        float bx = (float)f_lua_tonumber(T, 4);
                        float by = (float)f_lua_tonumber(T, 5);
                        float bz = (float)f_lua_tonumber(T, 6);
                        // NOTE: no nh here - Unit.name_hash tostring() is a
                        // binary "#IDPRE_..." blob that garbles DebugView.
                        log_msg("[RAYCAST] HIT idx=%d rn=%s dist=%.2f box=(%.1f,%.1f,%.1f) rel=(%.1f,%.1f,%.1f)%s%s\n",
                            i, rn ? rn : "?", dist,
                            bx, by, bz,
                            bx - g_cam_x, by - g_cam_y, bz - g_cam_z,
                            nm ? "  -> " : "", nm ? nm : "");
                    }
                    if (dist < g_hit_dist) {
                        g_hit_dist = dist;
                        g_last_hit_idx = i;
                        g_hit_x = g_cam_x + g_fwd_x * dist;
                        g_hit_y = g_cam_y + g_fwd_y * dist;
                        g_hit_z = g_cam_z + g_fwd_z * dist;
                        if (rn) {
                            strncpy(g_hit_rn, rn, sizeof(g_hit_rn)-1);
                            g_hit_rn[sizeof(g_hit_rn)-1] = 0;
                        }
                        if (nh) {
                            strncpy(g_hit_nh, nh, sizeof(g_hit_nh)-1);
                            g_hit_nh[sizeof(g_hit_nh)-1] = 0;
                        }
                        g_has_hit = 1;
                    }
                } else if (strcmp(status, "boxfail") == 0 || strcmp(status, "badbox") == 0) {
                    box_fail++;
                } else if (strcmp(status, "hit-c") == 0) {
                    // loose cone fallback: record it, but it never competes
                    // with strict slab hits (the C-side "closest" compare).
                    hits_c++;
                    float d2c = (float)f_lua_tonumber(T, 12);
                    if (d2c > 0 && d2c < g_cone_dist) {
                        g_cone_dist = d2c;
                        const char *rn2 = f_lua_tolstring(T, 2, NULL);
                        if (rn2) { strncpy(g_cone_rn, rn2, sizeof(g_cone_rn) - 1); g_cone_rn[sizeof(g_cone_rn) - 1] = 0; }
                        const char *nh2 = f_lua_tolstring(T, 3, NULL);
                        if (nh2) { strncpy(g_cone_nh, nh2, sizeof(g_cone_nh) - 1); g_cone_nh[sizeof(g_cone_nh) - 1] = 0; }
                    }
                } else if (strcmp(status, "dead") == 0) {
                    // Diag: print the first few "dead" units so we can see
                    // whether alive=false is wrongly filtering live NPCs
                    // (e.g. the captain). If the captain shows up here,
                    // Unit.alive is not a reliable filter and we must stop
                    // skipping dead units (SEH already protects the calls).
                    if (dead < 5) {
                        const char *rn3 = f_lua_tolstring(T, 2, NULL);
                        log_msg("[RAYCAST] dead[%d] idx=%d rn=%s\n", dead, i, rn3 ? rn3 : "?");
                    }
                    dead++;
                } else if (strcmp(status, "nolp") == 0) {
                    nolp_n++;
                } else if (strcmp(status, "pointbox") == 0) {
                    pointbox_n++;
                } else if (strcmp(status, "huge") == 0) {
                    huge_n++;
                } else if (strcmp(status, "miss") == 0) {
                    miss++;
                    // classify miss reason
                    const char *rs = f_lua_tolstring(T, 11, NULL);
                    if (rs) {
                        if (strcmp(rs, "axis") == 0) axis_n++;
                        else if (strcmp(rs, "behind") == 0) behind_n++;
                        else if (strcmp(rs, "no-overlap") == 0) no_overlap_n++;
                        else if (strcmp(rs, "too-far") == 0) too_far_n++;
                        else if (strcmp(rs, "inside") == 0) inside_n++;
                    }
                    // character-class diagnostic: T13 holds "CHA box=..." for
                    // humanoid/enemy units that missed, print the first 12
                    const char *diag = f_lua_tolstring(T, 13, NULL);
                    if (diag && diag[0] && strncmp(diag, "CHA", 3) == 0) {
                        if (g_cha_diag_count < 12) {
                            const char *rn3 = f_lua_tolstring(T, 2, NULL);
                            log_msg("[RAYCAST] %s rn=%s\n", diag, rn3 ? rn3 : "?");
                            g_cha_diag_count++;
                        }
                    }
                }
                // distance histogram for any unit with a valid center
                float cdist = (float)f_lua_tonumber(T, 10);
                if (cdist > 0.0f) {
                    if (cdist < 2.0f) dist_buckets[0]++;
                    else if (cdist < 5.0f) dist_buckets[1]++;
                    else if (cdist < 10.0f) dist_buckets[2]++;
                    else if (cdist < 20.0f) dist_buckets[3]++;
                    else if (cdist < 50.0f) dist_buckets[4]++;
                    else if (cdist < 200.0f) dist_buckets[5]++;
                    else dist_buckets[6]++;
                }
                // box interpretation distribution
                const char *mode = f_lua_tolstring(T, 13, NULL);
                if (mode) {
                    if (strcmp(mode, "minmax") == 0) mode_minmax++;
                    else if (strcmp(mode, "center") == 0) mode_center++;
                    else if (strcmp(mode, "struct") == 0) mode_struct++;
                    else if (strcmp(mode, "pos_fb") == 0) mode_posfb++;
                }
                // aim diagnostics: keep the 5 boxes whose centers are closest
                // to the ray direction (cosv = dot(fwd, toCenter) / dist)
                {
                    float tproj = (float)f_lua_tonumber(T, 14);
                    float cosv = (float)f_lua_tonumber(T, 15);
                    if (cosv > 0.0f && cosv <= 1.0f && tproj > 0.0f) {
                        for (int s = 0; s < 5; s++) {
                            if (cosv > g_aim_cos[s]) {
                                for (int t2 = 4; t2 > s; t2--) {
                                    g_aim_cos[t2] = g_aim_cos[t2 - 1];
                                    g_aim_idx[t2] = g_aim_idx[t2 - 1];
                                    g_aim_t[t2] = g_aim_t[t2 - 1];
                                    g_aim_cd[t2] = g_aim_cd[t2 - 1];
                                }
                                g_aim_cos[s] = cosv;
                                g_aim_idx[s] = i;
                                g_aim_t[s] = tproj;
                                g_aim_cd[s] = cdist;
                                break;
                            }
                        }
                    }
                }
            }
        }

        f4_step = 7;
        f_lua_settop(g_L, top);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Crash outside the pcall's own SEH (newthread/loadstring/
            // parsing/settop). Lua main state may be corrupt - record the
            // offending entity, mark crash, and stop the scan entirely
            // rather than risk a cascade of further crashes.
            uintptr_t rip2 = 0;
            PEXCEPTION_POINTERS ep2 = GetExceptionInformation();
            if (ep2 && ep2->ContextRecord) rip2 = (uintptr_t)ep2->ContextRecord->Rip;
            HMODULE lua2 = GetModuleHandleA("lua51.dll");
            HMODULE self2 = GetModuleHandleA("hd2_raycast_hook.dll");
            if (lua2 && rip2 >= (uintptr_t)lua2 && rip2 < (uintptr_t)lua2 + 0x200000)
                log_msg("[RAYCAST] F4 LOOP SEH idx=%d step=%d code=0x%08X rip=lua51+0x%llX (scan aborted)\n",
                    i, (int)f4_step, GetExceptionCode(), (unsigned long long)(rip2 - (uintptr_t)lua2));
            else if (self2 && rip2 >= (uintptr_t)self2 && rip2 < (uintptr_t)self2 + 0x200000)
                log_msg("[RAYCAST] F4 LOOP SEH idx=%d step=%d code=0x%08X rip=hook+0x%llX (scan aborted)\n",
                    i, (int)f4_step, GetExceptionCode(), (unsigned long long)(rip2 - (uintptr_t)self2));
            else
                log_msg("[RAYCAST] F4 LOOP SEH idx=%d step=%d code=0x%08X rip=0x%llX (scan aborted)\n",
                    i, (int)f4_step, GetExceptionCode(), (unsigned long long)rip2);
            InterlockedExchange(&g_segfault_flag, 1);
            g_segfault_tick = GetTickCount();
            crash_skip_add(i);
            break;
        }
    }

    if (g_verbose_log) {
        log_msg("[RAYCAST] Scan: tried=%d hits=%d boxfail=%d miss=%d dead=%d nolp=%d pointbox=%d huge=%d crashed=%d\n",
            max_try, hits, box_fail, miss, dead, nolp_n, pointbox_n, huge_n, crashed);
        log_msg("[RAYCAST]   miss-reasons: axis=%d behind=%d no-overlap=%d too-far=%d inside=%d\n",
            axis_n, behind_n, no_overlap_n, too_far_n, inside_n);
        log_msg("[RAYCAST]   box-cdist: <2m=%d <5m=%d <10m=%d <20m=%d <50m=%d <200m=%d >200m=%d\n",
            dist_buckets[0], dist_buckets[1], dist_buckets[2], dist_buckets[3],
            dist_buckets[4], dist_buckets[5], dist_buckets[6]);
        log_msg("[RAYCAST]   box-modes: minmax=%d center=%d struct=%d posfb=%d\n",
            mode_minmax, mode_center, mode_struct, mode_posfb);
        log_msg("[RAYCAST]   aim: closest-to-ray centers ->\n");
        for (int s = 0; s < 5; s++) {
            if (g_aim_cos[s] > 0.0f)
                log_msg("[RAYCAST]     top%d idx=%d cos=%.3f tproj=%.1f cdist=%.1f\n",
                    s + 1, g_aim_idx[s], g_aim_cos[s], g_aim_t[s], g_aim_cd[s]);
        }
    } else {
        log_msg("[RAYCAST] Scan: hits=%d miss=%d dead=%d crashed=%d skipped_crash=%d\n",
            hits, miss, dead, crashed, g_crash_skip_count);
    }

    // Promote the loose-cone fallback ONLY when no strict slab hit exists.
    // Lua-side: copy rc_cone_* into the main slots so the fx wireframe and
    // shm_write_ui see a hitbox.
    if (!g_has_hit) {
        exec_lua("if _G.rc_cone_d and not _G.rc_hit_d then _G.rc_hit_d = _G.rc_cone_d _G.rc_hitbox = _G.rc_cone_hitbox _G.rc_vx, _G.rc_vy, _G.rc_vz = _G.rc_cone_vx, _G.rc_cone_vy, _G.rc_cone_vz _G.rc_vd = _G.rc_cone_d end");
        if (g_cone_dist < 9990.0f) {
            g_has_hit = 1;
            g_hit_dist = g_cone_dist;
            g_hit_x = g_cam_x + g_fwd_x * g_cone_dist;
            g_hit_y = g_cam_y + g_fwd_y * g_cone_dist;
            g_hit_z = g_cam_z + g_fwd_z * g_cone_dist;
            strncpy(g_hit_rn, g_cone_rn, sizeof(g_hit_rn) - 1);
            g_hit_rn[sizeof(g_hit_rn) - 1] = 0;
            strncpy(g_hit_nh, g_cone_nh, sizeof(g_hit_nh) - 1);
            g_hit_nh[sizeof(g_hit_nh) - 1] = 0;
            log_msg("[RAYCAST] cone fallback hit d=%.2f hits_c=%d rn=%s\n",
                g_cone_dist, hits_c, g_cone_rn[0] ? g_cone_rn : "?");
        }
    }

    // Draw visualization if we have a hit
    if (g_has_hit) {
        log_msg("[RAYCAST] Drawing viz: hit at (%.1f,%.1f,%.1f) dist=%.1f\n",
            g_hit_x, g_hit_y, g_hit_z, g_hit_dist);
        /* v10.8: arm real-time tracking of this locked target */
        g_tracking = 1;
        g_track_idx = g_last_hit_idx;
        g_track_ox = g_hit_x; g_track_oy = g_hit_y; g_track_oz = g_hit_z;
        const char *idp = strstr(g_hit_rn, "#ID[");
        if (idp) {
            snprintf(g_track_key, sizeof(g_track_key), "%.16s", idp + 4);
            log_msg("[RAYCAST] track armed: key=%s idx=%d\n", g_track_key, g_track_idx);
        } else {
            g_track_key[0] = 0;
            g_tracking = 0;
        }
        draw_visualization();
        log_msg("%s", "[RAYCAST] viz done\n");
    }

    // Publish camera + hit state to the ReShade addon (shared memory)
    shm_write_hit();
    log_msg("%s", "[RAYCAST] shm hit done\n");

    // Re-enable Lua GC (was stopped at scan start); SEH-protected with retry.
    gc_restart_safe();
    log_msg("%s", "[RAYCAST] F4 done\n");
}

// ============================================================
// Gui.text monitor - observes real game GUI text rendering
// ============================================================
static void init_gui_text_monitor(void) {
    if (g_gui_monitor_ready) return;
    if (!g_L) return;
    if (g_segfault_flag) return;

    // Get Gui.text function pointer on an isolated coroutine.
    // tostring() is patched by Stingray to return "[function]",
    // and lua_getglobal is not exported, so use loadstring+pcall.
    // Whole body is SEH-protected: a crash here must never take the game
    // down (this runs on every pcall until it succeeds).
    int top = f_lua_gettop(g_L);
    __try {
        lua_State *T = f_lua_newthread(g_L);
        if (T) {
            if (f_luaL_loadstring(T, "return stingray.Gui.text") == 0) {
                o_lua_pcall(T, 0, 1, 0);
                if (!g_segfault_flag && f_lua_type(T, -1) == LUA_TFUNCTION) {
                    g_gui_text_ptr = f_lua_topointer(T, -1);
                    log_msg("[RAYCAST] Gui.text ptr=%p - monitoring game text calls\n", g_gui_text_ptr);
                } else {
                    log_msg("[RAYCAST] Gui.text resolve failed (type=%d)\n",
                        g_segfault_flag ? -1 : f_lua_type(T, -1));
                }
            }
            f_lua_settop(g_L, top);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange((volatile LONG *)&g_segfault_tick, GetTickCount());
        InterlockedExchange(&g_segfault_flag, 1);
        log_msg("[RAYCAST] Gui.text monitor crashed (SEH 0x%08X), disabled\n", GetExceptionCode());
        f_lua_settop(g_L, top);
    }
    g_gui_monitor_ready = 1; // never retry: repeated crashes are the crash itself
}

// Called from hk_lua_pcall before the real call. lua_pcall convention:
// stack = [arg1, arg2, ..., argN, func]; func is at top.
static void maybe_log_gui_text(lua_State *L, int nargs) {
    if (!g_gui_text_ptr || nargs < 2) return; // need at least gui + text
    InterlockedIncrement(&g_guitext_total);

    int top = f_lua_gettop(L);
    if (top < 2) return;
    if (f_lua_type(L, top) != LUA_TFUNCTION) return;
    if (f_lua_topointer(L, top) != g_gui_text_ptr) return;

    // args: arg_i at index (top - nargs + i - 1)
    // Gui.text(gui, text, font, size, pos, color) - arg order to be confirmed
    int idx_gui   = top - nargs;
    int idx_text  = top - nargs + 1;
    int idx_font  = top - nargs + 2;
    int idx_size  = top - nargs + 3;
    int idx_arg5  = top - nargs + 4;
    int idx_arg6  = top - nargs + 5;

    const char *text = NULL;
    if (f_lua_type(L, idx_text) == LUA_TSTRING) text = f_lua_tolstring(L, idx_text, NULL);

    const char *font = NULL;
    int font_t = f_lua_type(L, idx_font);
    if (font_t == LUA_TSTRING) font = f_lua_tolstring(L, idx_font, NULL);
    else if (font_t == LUA_TUSERDATA) font = "(userdata)";
    else if (font_t == LUA_TNUMBER) font = "(number)";
    else font = "(other)";

    double size = 0;
    if (f_lua_type(L, idx_size) == LUA_TNUMBER) size = f_lua_tonumber(L, idx_size);

    // Throttle: 800ms between logs, and only log each distinct font a few times
    DWORD tick = GetTickCount();
    if (tick - g_last_guitext_tick < 800) return;
    g_last_guitext_tick = tick;

    log_msg("[RAYCAST] GuiText nargs=%d text='%s' font=%s size=%.0f t5=%d t6=%d total=%ld\n",
        nargs, text ? text : "?", font, size,
        f_lua_type(L, idx_arg5), f_lua_type(L, idx_arg6), g_guitext_total);

    // Collect distinct font strings
    if (font && font[0] && font[0] != '(') {
        for (int i = 0; i < g_font_seen_count; i++) {
            if (strcmp(g_font_seen[i], font) == 0) return;
        }
        if (g_font_seen_count < 8) {
            strncpy(g_font_seen[g_font_seen_count], font, sizeof(g_font_seen[0]) - 1);
            g_font_seen[g_font_seen_count][sizeof(g_font_seen[0]) - 1] = 0;
            g_font_seen_count++;
            log_msg("[RAYCAST] NEW FONT: '%s' (arg4 type=%d, arg5 type=%d)\n",
                font, font_t, f_lua_type(L, idx_arg5));
        }
    }
}

// ============================================================
// Hook function
// ============================================================
static int __fastcall hk_lua_pcall(lua_State *L, int nargs, int nresults, int errfunc) {
    g_L = L;
    InterlockedIncrement(&g_pcall_count);
    rc_print_version_banner();

    // Lazy-load the persisted crash-skip registry here (NOT in DllMain: file
    // I/O inside DllMain can deadlock the loader and the inject never lands).
    {
        static int loaded = 0;
        if (!loaded) { loaded = 1; crash_skip_load(); }
    }


    // Lazily init Gui.text monitor on first pcall
    if (!g_gui_monitor_ready) init_gui_text_monitor();
    // Gui.text monitoring kept enabled (user feature). It inspects every
    // game pcall stack, so wrap it in SEH to keep a bad stack layout from
    // taking down the game.
    if (g_gui_text_ptr) {
        __try { maybe_log_gui_text(L, nargs); }
        __except (EXCEPTION_EXECUTE_HANDLER) { g_gui_text_ptr = NULL; }
    }

    // Install the per-frame update drawer ASAP so the ray line / scan marks
    // are visible without pressing any key first.
    {
        static int g_drawer_attempted = 0;
        if (!g_drawer_attempted) {
            g_drawer_attempted = 1;
            install_update_drawer();
        }
    }

    if (g_segfault_flag) {
        DWORD elapsed = GetTickCount() - g_segfault_tick;
        if (elapsed > 3000) {
            InterlockedExchange(&g_segfault_flag, 0);
            log_msg("%s", "[RAYCAST] Cooldown expired, resuming\n");
        }
    }

    int result;
    __try {
        result = o_lua_pcall(L, nargs, nresults, errfunc);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // A native crash inside game Lua (e.g. engine API called at a bad
        // time) must NOT take down the process. Mark it, return an error
        // code, and let the game carry on.
        InterlockedExchange(&g_segfault_flag, 1);
        g_segfault_tick = GetTickCount();
        result = -1;
    }

    DWORD tick = GetTickCount();

    // Register with ReShade as an external addon (game thread - safe).
    // One-shot; no-op after success.
    hd2_addon_try_register();


    // Sync projected screen-space UI (ray line / hit mark / scan marks)
    // from Lua into shared memory ~10x/sec. The fx shader draws these.
    {
        static DWORD last_ui_sync = 0;
        if (tick - last_ui_sync > 100) {
            last_ui_sync = tick;
            shm_write_ui();
        }
    }

    // On-demand mesh table builder: checks unfocus state ~1x/sec and spawns
    // the python helper when the game has been tabbed out with pending hashes.
    {
        static DWORD last_mesh_tick = 0;
        if (tick - last_mesh_tick > 1000) {
            last_mesh_tick = tick;
            mesh_builder_tick();
        }
    }

    // Panel status every 5s - log only when the state CHANGES. The vd
    // (distance) float changed every check (3.35 -> 3.3521 -> ...) which
    // made the comparison always differ and flooded the log; round it to
    // one decimal so a stable scene produces zero log lines.
    static DWORD last_panel_status = 0;
    static char last_panel_state[160] = {0};
    if (tick - last_panel_status > 5000) {
        last_panel_status = tick;
        g_quiet_exec = 1;  // suppress the per-call "OK(1)" line; only log on change
        g_exec_bypass = 1;
        exec_lua(
            "local g = _G.rc_panel_gui "
            "return 'panel_gui='..tostring(g ~= nil)..' vd='..string.format('%.1f', _G.rc_vd or 0)..' rects='..tostring((_G.rc_panel_ids and #_G.rc_panel_ids) or 0)"
        );
        g_quiet_exec = 0;
        g_exec_bypass = 0;
        if (g_last_result[0] && strcmp(g_last_result, last_panel_state) != 0) {
            strncpy(last_panel_state, g_last_result, sizeof(last_panel_state) - 1);
            last_panel_state[sizeof(last_panel_state) - 1] = 0;
            log_msg("[RAYCAST] panel %s\n", g_last_result);
        }
    }
    
    // Continuous visualization (30fps, using last known hit info)
    static DWORD last_viz = 0;
    if (g_continuous_viz && g_has_hit && (tick - last_viz > 33)) {
        last_viz = tick;
        draw_visualization();
    }

    // v10.8: real-time track of the F4-locked target (5Hz) + periodic
    // label refresh. shm_write_hit() re-submits the label every 200ms, so
    // cmd_feedback (row 5) appears right after a Numpad press without a
    // new F4 scan, and the box/distance follow the moving target.
    static DWORD last_track = 0;
    if (g_has_hit && (tick - last_track > 200)) {
        last_track = tick;
        if (g_tracking) track_locked_target();
        shm_write_hit();
    }
    
    

    // F4 - single raycast (find_units_intersecting + ray-sphere)
    static DWORD last_f4 = 0;
    if ((GetAsyncKeyState(VK_F4) & 0x8000) && (tick - last_f4 > 500)) {
        last_f4 = tick;
        g_verbose_log = 1; // verbose for manual F4
        do_raycast();
        g_verbose_log = 0;
    }
    
    // F5 - toggle continuous
    static DWORD last_f5 = 0;
    
    // Continuous raycast (~2 fps, reduced for performance)
    static DWORD last_cont = 0;
    if (g_continuous_raycast && (tick - last_cont > 500)) {
        last_cont = tick;
        g_verbose_log = 0; // quiet in continuous mode
        do_raycast();
    }
    
    





    // Numpad1 - Nearby-unit scan: find_units_intersecting around camera,
    // dump hash + resource_name for every unit (hash<->path mapping)
    static DWORD last_f13 = 0;
    if ((GetAsyncKeyState(VK_NUMPAD1) & 0x8000) && (tick - last_f13 > 1000)) {
        last_f13 = tick;
        scan_nearby_units();
    }








    // 3D lines on the game thread (~30fps). Safe: exec_lua is SEH-isolated,
    // 3D lines on the game thread (~30fps). Kept enabled per user request.
    // draw_3d_lines_game_thread() has its own crash-safety: exec_lua is
    // SEH-isolated and the feature auto-disables after 2 crashes.
    static DWORD last_3d = 0;
    if ((g_has_hit || g_scan_boxes_dirty) && (tick - last_3d > 33)) {
        last_3d = tick;
        draw_3d_lines_game_thread();
    }


    return result;
}



// Install a wrapper around the game's global _G.update function (called
// every frame by the engine). This is the pattern used by working HD2 HUD
// mods: Gui.rect(gui, Vector2 pos, Vector2 size, Color(a, r, g, b)) from the
// game's own Lua thread - the only safe place to draw 2D GUI.
static void install_update_drawer(void) {
    exec_lua(
        "local S = stingray\n"
        "if _G.rc_update_installed then return 'already' end\n"
        "local orig = rawget(_G, 'update')\n"
        "if type(orig) ~= 'function' then return 'noupdate' end\n"
        "_G.rc_update_installed = true\n"
        "_G.rc_panel_ids = {}\n"
        "rawset(_G, 'update', function(...)\n"
        "  local w = S.Application.main_world()\n"
        "  local gui = _G.rc_panel_gui\n"
        "  if not gui and w then\n"
        "    local okg, g = pcall(S.World.create_screen_gui, w)\n"
        "    if okg and g then gui = g; _G.rc_panel_gui = g end\n"
        "  end\n"
        "  if gui then\n"
        "    -- destroy previous frame's rects\n"
        "    for _, id in ipairs(_G.rc_panel_ids) do\n"
        "      pcall(S.Gui.destroy_rect, gui, id)\n"
        "    end\n"
        "    _G.rc_panel_ids = {}\n"
        "    local d = _G.rc_vd or 0\n"
        "    if d > 0.5 and d < 200 then\n"
        "      local okr, rw, rh = pcall(S.Gui.render_resolution, gui)\n"
        "      if okr and rw and rh then\n"
        "        -- bottom-left background bar\n"
        "        local ok1, id1 = pcall(S.Gui.rect, gui, S.Vector2(8, rh - 44), S.Vector2(300, 36), S.Color(200, 12, 12, 12))\n"
        "        if ok1 and id1 then _G.rc_panel_ids[#_G.rc_panel_ids + 1] = id1 end\n"
        "        -- distance bar (green, width = dist*10 clamped)\n"
        "        local bw = math.max(0, math.min(292, d * 10))\n"
        "        local ok2, id2 = pcall(S.Gui.rect, gui, S.Vector2(10, rh - 42), S.Vector2(bw, 32), S.Color(255, 0, 220, 0))\n"
        "        if ok2 and id2 then _G.rc_panel_ids[#_G.rc_panel_ids + 1] = id2 end\n"
        "      end\n"
        "    end\n"
        "    -- panel state for C-side polling (every 120 frames)\n"
        "    _G.rc_panel_frames = (_G.rc_panel_frames or 0) + 1\n"
        "    if _G.rc_panel_frames % 120 == 1 then\n"
        "      _G.rc_panel_state = string.format('fr=%d vd=%.1f rects=%d', _G.rc_panel_frames, d, #_G.rc_panel_ids)\n"
        "    end\n"
        "  end\n"
        "  return orig(...)\n"
        "end)\n"
        "return 'update_drawer_installed'\n"
    );
}

// 3D lines (ray, hit box, scan boxes) drawn on the GAME thread, called from
// hk_lua_pcall. exec_lua isolates crashes with SEH. If LineObject.dispatch
// really needs the render phase it will crash here - auto-disable after 2
// crashes instead of destabilising the game.
static int g_3d_lines_enabled = 1;
static int g_3d_line_crashes = 0;

static void draw_3d_lines_game_thread(void) {
    if (!g_3d_lines_enabled) return;
    if (g_segfault_flag) {
        // A crash happened since the last draw: disable 3D lines after ONE
        // such event (not two). Every retry re-crashes the engine render
        // path and re-arms the global cooldown, which starves shm_write_ui
        // and makes the fx overlay show nothing. Note: we do NOT clear the
        // flag here - the hk_lua_pcall cooldown owns that.
        g_3d_line_crashes++;
        if (g_3d_line_crashes >= 1) {
            g_3d_lines_enabled = 0;
            log_msg("%s", "[RAYCAST] 3D lines disabled (dispatch crashed on game thread)\n");
        }
        return;
    }

    // Pipeline status once per second (confirm lo/boxes/vd state)
    static DWORD last_viz_status = 0;
    DWORD now_tick = GetTickCount();
    if (now_tick - last_viz_status > 1000) {
        last_viz_status = now_tick;
        exec_lua(
            "local b = _G.rc_scan_boxes "
            "local vd = _G.rc_vd or 0 "
            "return 'lo='..tostring(_G.rc_lo ~= nil)..' boxes='..tostring(b and #b or 0)..' vd='..string.format('%.1f', vd)..' hit='..tostring(vd > 0.5 and vd < 200)"
        );
        if (g_last_result[0]) log_msg("[RAYCAST] viz %s\n", g_last_result);
    }

    char set_code[256];
    snprintf(set_code, sizeof(set_code),
        "_G.rc_cx=%f _G.rc_cy=%f _G.rc_cz=%f _G.rc_vx=%f _G.rc_vy=%f _G.rc_vz=%f _G.rc_vd=%f",
        g_cam_x, g_cam_y, g_cam_z, g_hit_x, g_hit_y, g_hit_z, g_hit_dist);
    exec_lua(set_code);

    exec_lua(
        "local S = stingray\n"
        "local V3 = S.Vector3\n"
        "local C = S.Color\n"
        "local w = S.Application.main_world()\n"
        "local lo = _G.rc_lo\n"
        "if not lo then\n"
        "  local ok2, lo2 = pcall(S.World.create_line_object, w)\n"
        "  if ok2 and lo2 then _G.rc_lo = lo2; lo = lo2 end\n"
        "end\n"
        "if not lo then return 'nolo' end\n"
        "local cx, cy, cz = _G.rc_cx, _G.rc_cy, _G.rc_cz\n"
        "local px, py, pz = _G.rc_vx, _G.rc_vy, _G.rc_vz\n"
        "S.LineObject.reset(lo)\n"
        "-- NOTE: scan-box wireframes are drawn by the ReShade fx shader\n"
        "-- (2D projection); drawing all of them as 3D lines every frame\n"
        "-- crashed the engine (768+ lines/frame), so no 3D boxes here.\n"
        "-- ray line + hit box only when a fresh hit exists (rc_vd set by scan)\n"
        "local vd = _G.rc_vd or 0\n"
        "if vd > 0.5 and vd < 200 then\n"
        "-- ray line: camera -> hit point (magenta)\n"
        "S.LineObject.add_line(lo, V3(cx,cy,cz), V3(px,py,pz), C(255,255,0,255))\n"
        "-- hit box wireframe (yellow)\n"
        "local s = 1.0\n"
        "local pts = {\n"
        "  V3(px-s,py-s,pz-s), V3(px+s,py-s,pz-s), V3(px-s,py+s,pz-s), V3(px+s,py+s,pz-s),\n"
        "  V3(px-s,py-s,pz+s), V3(px+s,py-s,pz+s), V3(px-s,py+s,pz+s), V3(px+s,py+s,pz+s)\n"
        "}\n"
        "local edges = {{1,2},{2,4},{4,3},{3,1},{5,6},{6,8},{8,7},{7,5},{1,5},{2,6},{4,8},{3,7}}\n"
        "for _, e in ipairs(edges) do\n"
        "  S.LineObject.add_line(lo, pts[e[1]], pts[e[2]], C(255,255,255,0))\n"
        "end\n"
        "end\n"
        "-- dispatch during render phase\n"
        "S.LineObject.dispatch(lo)\n"
        "-- NOTE: 2D panel is drawn by the _G.update wrapper (game Lua thread)\n"
        "return 'present_draw_ok'\n"
    );
}



// DllMain
// ============================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        if (g_initialized) {
            log_msg("[RAYCAST] Already initialized, skipping\n");
            return TRUE;
        }
        g_initialized = TRUE;
        log_init();
        log_msg("[RAYCAST] DLL attached (clean version)\n");
        
        // Get NtProtectVirtualMemory for bypassing anti-cheat hooks on VirtualProtect
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            f_NtProtectVirtualMemory = (NtProtectVirtualMemory_t)
                GetProcAddress(ntdll, "NtProtectVirtualMemory");
            log_msg("[RAYCAST] NtProtectVirtualMemory at %p\n", f_NtProtectVirtualMemory);
        }
        

        // Shared memory for the ReShade addon (created lazily on first use,
        // but create early so the addon can attach before any scan)
        shm_init();

        // Hand this module to the ReShade addon core (registers later from
        // the game thread to avoid loader-lock hazards)
        hd2_addon_attach(hModule);
        
        // Find lua51.dll
        HMODULE lua_dll = GetModuleHandleA("lua51.dll");
        if (!lua_dll) {
            log_msg("%s", "[RAYCAST] lua51.dll not found\n");
            return TRUE;
        }
        
        void *lua_pcall_addr = GetProcAddress(lua_dll, "lua_pcall");
        f_luaL_loadstring = (luaL_loadstring_t)GetProcAddress(lua_dll, "luaL_loadstring");
        f_lua_tolstring   = (lua_tolstring_t)GetProcAddress(lua_dll, "lua_tolstring");
        f_lua_settop      = (lua_settop_t)GetProcAddress(lua_dll, "lua_settop");
        f_lua_gettop      = (lua_gettop_t)GetProcAddress(lua_dll, "lua_gettop");
        f_lua_type        = (lua_type_t)GetProcAddress(lua_dll, "lua_type");
        f_lua_typename    = (lua_typename_t)GetProcAddress(lua_dll, "lua_typename");
        f_lua_newthread   = (lua_newthread_t)GetProcAddress(lua_dll, "lua_newthread");
        f_lua_touserdata  = (lua_touserdata_t)GetProcAddress(lua_dll, "lua_touserdata");
        f_lua_topointer   = (lua_topointer_t)GetProcAddress(lua_dll, "lua_topointer");
        f_lua_tonumber    = (lua_tonumber_t)GetProcAddress(lua_dll, "lua_tonumber");
        f_lua_getglobal   = (lua_getglobal_t)GetProcAddress(lua_dll, "lua_getglobal");
        f_lua_setglobal   = (lua_setglobal_t)GetProcAddress(lua_dll, "lua_setglobal");
        f_lua_pushnumber  = (lua_pushnumber_t)GetProcAddress(lua_dll, "lua_pushnumber");
        f_lua_getfield    = (lua_getfield_t)GetProcAddress(lua_dll, "lua_getfield");
        f_lua_tocfunction = (lua_tocfunction_t)GetProcAddress(lua_dll, "lua_tocfunction");
        f_lua_getupvalue  = (lua_getupvalue_t)GetProcAddress(lua_dll, "lua_getupvalue");
        f_lua_next        = (lua_next_t)GetProcAddress(lua_dll, "lua_next");
        f_lua_pushnil     = (lua_pushnil_t)GetProcAddress(lua_dll, "lua_pushnil");
        f_lua_rawgeti     = (lua_rawgeti_t)GetProcAddress(lua_dll, "lua_rawgeti");
        f_lua_gc          = (lua_gc_t)GetProcAddress(lua_dll, "lua_gc");
        
        // Print lua_pcall prologue for debugging
        char buf[512];
        int pos = 0;
        pos += snprintf(buf + pos, sizeof(buf) - pos, 
            "[RAYCAST] lua_pcall=%p\n", lua_pcall_addr);
        if (lua_pcall_addr) {
            uint8_t *p = (uint8_t *)lua_pcall_addr;
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  bytes: ");
            for (int i = 0; i < 24; i++) {
                pos += snprintf(buf + pos, sizeof(buf) - pos, "%02x ", p[i]);
            }
            pos += snprintf(buf + pos, sizeof(buf) - pos, "\n");
            int off = 0;
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  instr: ");
            while (off < 24) {
                int ilen = x64_instr_len(p + off);
                if (ilen <= 0 || ilen > 15) break;
                pos += snprintf(buf + pos, sizeof(buf) - pos, "[%d] ", ilen);
                off += ilen;
            }
            pos += snprintf(buf + pos, sizeof(buf) - pos, "\n");
        }
        log_msg("%s", buf);
        
        if (!lua_pcall_addr || !f_luaL_loadstring) {
            log_msg("%s", "[RAYCAST] Missing Lua functions\n");
            return TRUE;
        }
        
        // Install safe inline hook
        void *tramp = NULL;
        install_hook(&tramp, hk_lua_pcall, lua_pcall_addr);
        o_lua_pcall = (lua_pcall_t)tramp;
        
        
        snprintf(buf, sizeof(buf), "[RAYCAST] Hook installed. trampoline=%p\n", tramp);
        log_msg("%s", buf);
        log_msg("%s", "[RAYCAST] Keys: F4=raycast Numpad1=nearby-scan\n");
    } else if (reason == DLL_PROCESS_DETACH) {
        // Unregister from ReShade and release shared memory
        hd2_addon_detach();
    }
    
    return TRUE;
}
