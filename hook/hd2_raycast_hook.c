// hd2_raycast_hook.c
// Inline-hook lua_pcall (x64) in lua51.dll to inject raycast code
//
// Build: cl /LD /O2 /W0 hd2_raycast_hook.c /link /OUT:hd2_raycast_hook.dll user32.lib
//
// Keys:
//   F2     - Probe Lua API + list World/Unit/Sphere functions
//   F4     - Raycast (find_units_intersecting + ray-sphere test)
//   F5     - Toggle continuous raycast (~4fps)
//   F6     - List Unit API
//   F7     - Probe Camera/Gui/Viewport APIs (find raycast/pick)
//   F8     - C-level memory dump: World + Unit C++ struct layout
//   F9     - Scan game.dll for raycast/physics string references
//   F10    - Comprehensive stingray API probe (find hidden raycast/physics)
//   F11    - Toggle continuous visualization (raycast + 3D box + text panel)
//   Insert - Probe Broadphase constructor + query signature
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
/* forward decl (defined with the pin machinery) - used by the SEH handler */
static int g_pin_stage = 0;

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
        /* v10.51: include the pin-tick stage so a crash inside the 120ms
         * pin tick is attributable to pose/xform/teleport/anim. */
        const char *pstage = "?";
        if (g_pin_stage == 1) pstage = "pin-pose";
        else if (g_pin_stage == 2) pstage = "pin-xform";
        else if (g_pin_stage == 3) pstage = "pin-tlp-ret";
        else if (g_pin_stage == 4) pstage = "pin-tlp-vec";
        else if (g_pin_stage == 5) pstage = "pin-set_local_position";
        else if (g_pin_stage == 6) pstage = "pin-set_position";
        else if (g_pin_stage == 7) pstage = "pin-anim";
        // Diagnose WHERE it crashed: print RIP relative to lua51.dll and our dll
        uintptr_t rip = 0;
        PEXCEPTION_POINTERS ep = GetExceptionInformation();
        if (ep && ep->ContextRecord) rip = (uintptr_t)ep->ContextRecord->Rip;
        HMODULE lua = GetModuleHandleA("lua51.dll");
        HMODULE self = GetModuleHandleA("hd2_raycast_hook.dll");
        if (lua && rip >= (uintptr_t)lua && rip < (uintptr_t)lua + 0x200000)
            snprintf(buf, sizeof(buf), "[RAYCAST] SEH 0x%08X rip=lua51+0x%llX (thread isolated) %s\n", GetExceptionCode(), (unsigned long long)(rip - (uintptr_t)lua), pstage);
        else if (self && rip >= (uintptr_t)self && rip < (uintptr_t)self + 0x100000)
            snprintf(buf, sizeof(buf), "[RAYCAST] SEH 0x%08X rip=hook+0x%llX (thread isolated) %s\n", GetExceptionCode(), (unsigned long long)(rip - (uintptr_t)self), pstage);
        else
            snprintf(buf, sizeof(buf), "[RAYCAST] SEH 0x%08X rip=0x%llX (thread isolated) %s\n", GetExceptionCode(), (unsigned long long)rip, pstage);
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

// ============================================================
// Dump lua51.dll export table straight from the loaded module.
// Answers which Lua C-APIs Stingray's custom build actually exports
// (lua_gettop/lua_topointer etc. are macros in stock Lua and may be
// missing from the export table entirely).
// ============================================================
static void dump_lua_exports(void) {
    HMODULE lua = GetModuleHandleA("lua51.dll");
    if (!lua) { log_msg("%s", "[RAYCAST] dump_lua_exports: lua51.dll not loaded\n"); return; }
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)lua;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { log_msg("%s", "[RAYCAST] dump_lua_exports: bad DOS magic\n"); return; }
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)lua + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { log_msg("%s", "[RAYCAST] dump_lua_exports: bad NT signature\n"); return; }
    IMAGE_DATA_DIRECTORY* ed = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed->VirtualAddress || !ed->Size) { log_msg("%s", "[RAYCAST] dump_lua_exports: no export directory\n"); return; }
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)lua + ed->VirtualAddress);
    DWORD nNames = exp->NumberOfNames;
    DWORD* names = (DWORD*)((BYTE*)lua + exp->AddressOfNames);
    WORD*  ords  = (WORD*)((BYTE*)lua + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)lua + exp->AddressOfFunctions);
    if (nNames > 400) nNames = 400; // guard against absurd tables
    log_msg("[RAYCAST] lua51.dll exports: %u names\n", nNames);
    for (DWORD i = 0; i < nNames; i++) {
        const char* nm = (const char*)((BYTE*)lua + names[i]);
        DWORD idx = ords[i];
        DWORD rva = funcs[idx];
        log_msg("[RAYCAST]   %-44s rva=%08X va=0x%llX\n", nm, rva,
            (unsigned long long)(uintptr_t)((BYTE*)lua + rva));
    }
}

// ============================================================
// C-level unit handle -> object resolution, replicated from the
// helldivers2.exe shared "handle resolve" core (every Unit method
// funnels through it). Fully DYNAMIC discovery - no hardcoded
// addresses (game base can move between processes):
//  1) walk Lua to get world_position's real C address
//  2) parse its E8 rel32 near +73 -> handle-resolve core fn
//  3) core fn: mov rsi,[rip+disp] -> global handle table base
//  4) index = handle & 0x3FFFFF, gen = handle >> 22
//     gen table  = [base+0xA0], check gen_table[index] == gen
//     obj table  = [base+0x88], object = obj_table[index]
// ============================================================
static uintptr_t engine_handle_resolve_fn(void) {
    static uintptr_t cached = 0;
    if (cached) return cached;
    if (!g_L || !f_lua_newthread || !f_lua_getfield || !f_lua_tocfunction) return 0;
    lua_State* T = f_lua_newthread(g_L);
    if (!T) return 0;
    uintptr_t wp = 0;
    __try {
        f_lua_getfield(T, LUA_GLOBALSINDEX, "stingray");
        if (f_lua_type(T, -1) == LUA_TTABLE) {
            f_lua_getfield(T, -1, "Unit");
            if (f_lua_type(T, -1) == LUA_TTABLE) {
                f_lua_getfield(T, -1, "world_position");
                if (f_lua_type(T, -1) == LUA_TFUNCTION) {
                    lua_CFunction cfn = f_lua_tocfunction(T, -1);
                    if (cfn) wp = (uintptr_t)cfn;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { wp = 0; }
    f_lua_settop(T, 0);
    f_lua_settop(g_L, -2); // pop thread obj
    if (!wp) { log_msg("%s", "[RAYCAST] resolve: world_position lookup failed\n"); return 0; }
    unsigned char b[96];
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)wp, b, sizeof(b), &got) || got < 80) {
        log_msg("%s", "[RAYCAST] resolve: world_position bytes unreadable\n");
        return 0;
    }
    // find the E8 rel32 call around +73 (the handle-resolve core call)
    for (int j = 60; j < 92 && j + 4 < (int)got; j++) {
        if (b[j] == 0xE8) {
            int32_t disp;
            memcpy(&disp, b + j + 1, 4);
            cached = wp + j + 5 + disp;
            log_msg("[RAYCAST] resolve: world_position=0x%llX E8[%d] -> core=0x%llX\n",
                (unsigned long long)wp, j, (unsigned long long)cached);
            return cached;
        }
    }
    log_msg("%s", "[RAYCAST] resolve: no E8 found in world_position prologue\n");
    return 0;
}

static void* g_handle_table_base(void) {
    static uintptr_t cached = 0;
    if (!cached) {
        uintptr_t fn = engine_handle_resolve_fn(); // dynamic
        if (fn) {
            unsigned char b[32];
            SIZE_T got = 0;
            BOOL ok = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)fn, b, sizeof(b), &got);
            if (!ok || got < 0x14) {
                log_msg("[RAYCAST] htab: core fn 0x%llX unreadable (ok=%d got=%zu)\n",
                    (unsigned long long)fn, ok, got);
            } else if (b[0x0F] == 0x48 && b[0x10] == 0x8B && b[0x11] == 0x35) {
                // mov rsi,[rip+disp] sits at offset 0x0F:
                // 00 mov [rsp+8],rbx  05 mov [rsp+10h],rsi  0A push rdi
                // 0B sub rsp,20h  0F mov rsi,[rip+disp]
                // IMPORTANT: rsi = *(uintptr_t*)(addr) - dereference the global!
                int32_t disp;
                memcpy(&disp, b + 0x12, 4);
                uintptr_t addr = fn + 0x0F + 7 + (uintptr_t)disp;
                uintptr_t val = 0;
                SIZE_T vr = 0;
                if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, &val, sizeof(val), &vr) && vr == sizeof(val)) {
                    cached = val;
                    log_msg("[RAYCAST] htab global @0x%llX = 0x%llX\n",
                        (unsigned long long)addr, (unsigned long long)val);
                } else {
                    log_msg("[RAYCAST] htab global read failed @0x%llX\n", (unsigned long long)addr);
                }
            } else {
                log_msg("[RAYCAST] htab pattern mismatch at 0x%llX: %02X %02X %02X %02X %02X %02X %02X %02X...\n",
                    (unsigned long long)fn, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
            }
        }
        if (!cached) cached = (uintptr_t)-1;
    }
    return cached == (uintptr_t)-1 ? NULL : (void*)cached;
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

/* Parse ONE mesh_verts_<hash>.txt into e. Returns 1 on success. */
static int mesh_table_load_file(uint64_t hash, MeshTableEntry *e) {
    char full[MAX_PATH];
    snprintf(full, sizeof(full), "D:\\hd2_meshtables\\mesh_verts_%llu.txt",
        (unsigned long long)hash);
    FILE *f = fopen(full, "r");
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

static int outline_from_points(float pts[512][2], int n, float out[512][2]) {
    if (n < 3) return 0;
    /* bin into grid */
    unsigned char grid[OUTLINE_GRID][OUTLINE_GRID];
    memset(grid, 0, sizeof(grid));
    for (int i = 0; i < n; i++) {
        int gx = (int)(pts[i][0] * OUTLINE_GRID);
        int gy = (int)(pts[i][1] * OUTLINE_GRID);
        if (gx < 0) gx = 0; if (gx >= OUTLINE_GRID) gx = OUTLINE_GRID - 1;
        if (gy < 0) gy = 0; if (gy >= OUTLINE_GRID) gy = OUTLINE_GRID - 1;
        grid[gx][gy] = 1;
    }
    /* find topmost-leftmost occupied cell as the walk start */
    int sx = -1, sy = -1;
    for (int gy = 0; gy < OUTLINE_GRID && sx < 0; gy++)
        for (int gx = 0; gx < OUTLINE_GRID; gx++)
            if (grid[gx][gy]) { sx = gx; sy = gy; break; }
    if (sx < 0) return 0;

    /* 8-neighbor offsets ordered counter-clockwise from E */
    static const int dx8[8] = { 1, 1, 0, -1, -1, -1, 0, 1 };
    static const int dy8[8] = { 0, 1, 1, 1, 0, -1, -1, -1 };

    int m = 0;
    int cx = sx, cy = sy;
    int dir = 4;              /* start looking N of start */
    int guard = 0;
    while (guard++ < 20000) {
        if (m < 512) {
            out[m][0] = (cx + 0.5f) / OUTLINE_GRID;
            out[m][1] = (cy + 0.5f) / OUTLINE_GRID;
            m++;
        }
        /* find next boundary neighbor in CCW order */
        int found = -1;
        for (int k = 0; k < 8; k++) {
            int nd = (dir + k) & 7;
            int nx = cx + dx8[nd], ny = cy + dy8[nd];
            if (nx < 0 || ny < 0 || nx >= OUTLINE_GRID || ny >= OUTLINE_GRID)
                continue;
            if (!grid[nx][ny]) continue;
            /* must be a boundary cell (has an empty neighbor) */
            int is_b = 0;
            for (int a = -1; a <= 1 && !is_b; a++)
                for (int b = -1; b <= 1 && !is_b; b++) {
                    if (a == 0 && b == 0) continue;
                    int mx = nx + a, my = ny + b;
                    if (mx < 0 || my < 0 || mx >= OUTLINE_GRID || my >= OUTLINE_GRID || !grid[mx][my]) {
                        is_b = 1;
                    }
                }
            if (!is_b) continue;
            found = nd;
            break;
        }
        if (found < 0) break;      /* isolated point */
        cx += dx8[found]; cy += dy8[found];
        dir = (found + 5) & 7;     /* turn right-ish to hug the boundary */
        if (cx == sx && cy == sy) break;  /* closed the loop */
    }
    if (m < 3) return 0;
    return m;
}

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
static DWORD g_unfocus_t0 = 0;
static int g_was_unfocused = 0;

static void mesh_pending_add(uint64_t hash) {
    if (!hash) return;
    if (mesh_table_find(hash)) return;
    for (int i = 0; i < g_mesh_pending_count; i++)
        if (g_mesh_pending[i] == hash) return;
    if (g_mesh_pending_count < MESH_PENDING_MAX)
        g_mesh_pending[g_mesh_pending_count++] = hash;
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

// Called periodically (from the pcall hook). Detects prolonged unfocus and
// triggers the builder; also cleans up when the builder finished.
static void mesh_builder_tick(void) {
    // Is the game window focused?
    int focused = 1;
    HWND fg = GetForegroundWindow();
    if (fg) {
        DWORD pid = 0;
        GetWindowThreadProcessId(fg, &pid);
        if (pid != GetCurrentProcessId()) focused = 0;
    }
    if (!focused && !g_was_unfocused)
        g_unfocus_t0 = GetTickCount();
    if (focused) {
        g_was_unfocused = 0;
        g_unfocus_t0 = 0;
    } else {
        g_was_unfocused = 1;
    }

    if (!focused && g_mesh_pending_count > 0 && !g_mesh_builder_running) {
        DWORD el = GetTickCount() - g_unfocus_t0;
        // DISABLED: each on_demand helper spawns a build_all2.py that holds
        // ~8GB, and while unfocused it re-spawns endlessly (running flag
        // resets after each build) - this caused 99% RAM + a python flood.
        // Pending tables stay queued; build them manually or re-enable later.
        if (0 && el > 60000) {   // unfocused > 1 minute
            mesh_pending_save();
            // spawn python helper: python build_on_demand.py
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                "\"C:\\Python310\\python.exe\" \"D:\\hd2_meshtables\\build_on_demand.py\"");
            STARTUPINFOA si; PROCESS_INFORMATION pi;
            memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
            memset(&pi, 0, sizeof(pi));
            if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                    CREATE_NO_WINDOW, NULL, "D:\\hd2_meshtables", &si, &pi)) {
                g_mesh_builder_running = 1;
                log_msg("[RAYCAST] mesh builder spawned (unfocused, %d pending)\n",
                    g_mesh_pending_count);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            } else {
                log_msg("[RAYCAST] mesh builder spawn FAILED (err=%lu)\n", GetLastError());
            }
        }
    }
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

static void* unit_handle_to_object(uint32_t handle) {
    void* base = g_handle_table_base();
    if (!base) return NULL;
    // EXACT engine algorithm (resolver 0x7FF71EF3DA50 full disasm):
    //   index = handle & 0x3FFFFF
    //   size  = [base+0x98]
    //   if index < size:
    //     gen  = handle >> 22;  gentab = [base+0xA0]
    //     if gentab[index] == gen:
    //       objtab = [base+0x88];  return objtab[index]
    uint32_t index = handle & 0x3FFFFF;
    DWORD size = *(DWORD*)((uint8_t*)base + 0x98);
    if (size && index >= size) return NULL;
    uint8_t  gen   = (uint8_t)(handle >> 22);
    uint8_t* gentab = *(uint8_t**)((uint8_t*)base + 0xA0);
    if (!gentab) return NULL;
    if (gentab[index] != gen) return NULL;
    void** objtab = *(void***)((uint8_t*)base + 0x88);
    if (!objtab) return NULL;
    return objtab[index];
}

// ============================================================
// Full memory dump to a standalone file (mem_dump.txt) so the
// analysis can happen offline without log-flush truncation.
// ============================================================
static FILE *g_memdump = NULL;

static void memdump_open(void) {
    if (g_memdump) return;
    g_memdump = fopen(RC_DIR "mem_dump.txt", "a");
    if (g_memdump) {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(g_memdump, "\n===== MEMDUMP %04d-%02d-%02d %02d:%02d:%02d =====\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        fflush(g_memdump);
    }
}

static void memdump_hex(const char *title, const void *addr, size_t len) {
    if (!g_memdump) return;
    unsigned char *buf = (unsigned char *)malloc(len ? len : 1);
    if (!buf) return;
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), addr, buf, len, &got) || got == 0) {
        fprintf(g_memdump, "[%s] @0x%llX read FAILED\n", title, (unsigned long long)(uintptr_t)addr);
        free(buf); return;
    }
    fprintf(g_memdump, "[%s] @0x%llX (%u bytes):\n", title, (unsigned long long)(uintptr_t)addr, (unsigned)got);
    for (SIZE_T i = 0; i < got; i += 16) {
        fprintf(g_memdump, "  %04X: ", (unsigned)i);
        for (SIZE_T j = 0; j < 16 && i + j < got; j++)
            fprintf(g_memdump, "%02X ", buf[i + j]);
        fprintf(g_memdump, " | ");
        for (SIZE_T j = 0; j < 16 && i + j + 4 <= got; j += 4) {
            float f; memcpy(&f, buf + i + j, 4);
            fprintf(g_memdump, "%.3f ", f);
        }
        fprintf(g_memdump, "\n");
    }
    free(buf);
}

static void memdump_close(void) {
    if (g_memdump) { fflush(g_memdump); fclose(g_memdump); g_memdump = NULL; }
}

static void dump_memory_to_file(void) {
    memdump_open();
    if (!g_memdump) { log_msg("%s", "[RAYCAST] memdump open FAILED\n"); return; }
    log_msg("%s", "[RAYCAST] === memory dump to mem_dump.txt ===\n");

    // 1. handle table base + objtab/gentab
    void* base = g_handle_table_base();
    if (base) {
        memdump_hex("handle_table_base", base, 0x200);
        void** objtab = NULL; SIZE_T go = 0;
        ReadProcessMemory(GetCurrentProcess(), (uint8_t*)base + 0x88, &objtab, 8, &go);
        if (objtab && objtab > (void*)0x10000) memdump_hex("objtab", objtab, 0x200);
        void* gentab = NULL; SIZE_T gg = 0;
        ReadProcessMemory(GetCurrentProcess(), (uint8_t*)base + 0xA0, &gentab, 8, &gg);
        if (gentab && gentab > (void*)0x10000) memdump_hex("gentab", gentab, 0x200);
    }

    // 2. world_position body + every E8 sub-function
    {
        lua_State* T = f_lua_newthread(g_L);
        if (T) {
            __try {
                f_lua_getfield(T, LUA_GLOBALSINDEX, "stingray");
                if (f_lua_type(T, -1) == LUA_TTABLE) {
                    f_lua_getfield(T, -1, "Unit");
                    if (f_lua_type(T, -1) == LUA_TTABLE) {
                        f_lua_getfield(T, -1, "world_position");
                        uintptr_t wp = 0;
                        if (f_lua_type(T, -1) == LUA_TFUNCTION && f_lua_tocfunction)
                            wp = (uintptr_t)f_lua_tocfunction(T, -1);
                        f_lua_settop(T, 0);
                        if (wp > 0x10000) {
                            memdump_hex("world_position_body", (void*)wp, 512);
                            unsigned char wb[512];
                            SIZE_T wg = 0;
                            if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)wp, wb, sizeof(wb), &wg) && wg) {
                                // FF15 (call [rip+disp]) targets = component getters
                                for (int j = 0; j + 5 < (int)wg; j++) {
                                    if (wb[j] == 0xFF && wb[j + 1] == 0x15) {
                                        int32_t disp; memcpy(&disp, wb + j + 2, 4);
                                        uintptr_t slotp = (uintptr_t)(wp + j + 6 + disp);
                                        uintptr_t tgt = 0; SIZE_T tr = 0;
                                        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)slotp, &tgt, 8, &tr) && tr == 8) {
                                            char tn[64]; sprintf_s(tn, sizeof(tn), "wp_FF15_target_+%d", j);
                                            memdump_hex(tn, (void*)tgt, 512);
                                            // recurse one level: dump this target's E8 subs
                                            unsigned char tb[512];
                                            SIZE_T tg = 0;
                                            if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)tgt, tb, sizeof(tb), &tg) && tg) {
                                                for (int m = 0; m + 4 < (int)tg; m++) {
                                                    if (tb[m] == 0xE8) {
                                                        int32_t d2; memcpy(&d2, tb + m + 1, 4);
                                                        uintptr_t s2 = tgt + m + 5 + d2;
                                                        char tn2[80]; sprintf_s(tn2, sizeof(tn2), "wp_FF15_+%d_E8sub_+%d", j, m);
                                                        memdump_hex(tn2, (void*)s2, 512);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    // sub ebx,[rip+disp] (2B 1D) = global base
                                    if (wb[j] == 0x2B && wb[j + 1] == 0x1D) {
                                        int32_t disp; memcpy(&disp, wb + j + 2, 4);
                                        uintptr_t gaddr = (uintptr_t)(wp + j + 6 + disp);
                                        uintptr_t gval = 0; SIZE_T gr = 0;
                                        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)gaddr, &gval, 8, &gr) && gr == 8) {
                                            char tn[64]; sprintf_s(tn, sizeof(tn), "wp_global_base_val_at_%llX", (unsigned long long)gaddr);
                                            memdump_hex(tn, &gval, 8);
                                        }
                                    }
                                }
                                for (int j = 0; j + 4 < (int)wg; j++) {
                                    if (wb[j] == 0xE8) {
                                        int32_t disp; memcpy(&disp, wb + j + 1, 4);
                                        uintptr_t sub = wp + j + 5 + disp;
                                        char tn[64]; sprintf_s(tn, sizeof(tn), "wp_E8_sub_+%d", j);
                                        memdump_hex(tn, (void*)sub, 512);
                                    }
                                }
                            }
                        }
                    }
                    f_lua_settop(T, 0);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                log_msg("[RAYCAST] memdump wp SEH 0x%08X\n", GetExceptionCode());
            }
            f_lua_settop(g_L, -2);
        }
    }

    // 3. first 8 unit objects + their pointer-field targets
    exec_lua(
        "local S=stingray local w=S.Application.main_world() "
        "local ok,u=pcall(S.World.units,w) "
        "_G.rc_ents2 = (ok and type(u)=='table') and u or {} "
        "return #_G.rc_ents2"
    );
    {
        lua_State* T2 = f_lua_newthread(g_L);
        if (T2) {
            __try {
                f_lua_getfield(T2, LUA_GLOBALSINDEX, "rc_ents2");
                if (f_lua_type(T2, -1) == LUA_TTABLE) {
                    for (int i = 1; i <= 8; i++) {
                        f_lua_rawgeti(T2, -1, i);
                        int t = f_lua_type(T2, -1);
                        if (t == LUA_TLIGHTUSERDATA || t == LUA_TUSERDATA) {
                            void* ud = f_lua_touserdata(T2, -1);
                            uint32_t h = (t == LUA_TLIGHTUSERDATA) ? (uint32_t)(uintptr_t)ud
                                       : (uint32_t)(ud ? *(double*)ud : 0);
                            void* obj = unit_handle_to_object(h);
                            if (obj) {
                                char tn[64]; sprintf_s(tn, sizeof(tn), "unit[%d]_obj_handle_%u", i, h);
                                memdump_hex(tn, obj, 512);
                                unsigned char ob[512];
                                SIZE_T og = 0;
                                if (ReadProcessMemory(GetCurrentProcess(), obj, ob, sizeof(ob), &og) && og) {
                                    for (int q = 0; q < 16; q++) {
                                        uintptr_t p = 0; memcpy(&p, ob + q * 8, 8);
                                        if (p > 0x10000 && p < 0x7FFFFFFFFFFF) {
                                            char tn2[64]; sprintf_s(tn2, sizeof(tn2), "unit[%d]_obj+0x%02X", i, q * 8);
                                            memdump_hex(tn2, (void*)p, 256);
                                        }
                                    }
                                }
                            }
                        }
                        f_lua_settop(T2, -2);
                    }
                }
                f_lua_settop(T2, 0);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                log_msg("[RAYCAST] memdump units SEH 0x%08X\n", GetExceptionCode());
            }
            f_lua_settop(g_L, -2);
        }
    }

    memdump_close();
    log_msg("%s", "[RAYCAST] memdump done -> mem_dump.txt\n");
}

static void test_handle_resolve(void) {
    log_msg("%s", "[RAYCAST] === F8: C-level handle resolve ===\n");
    void* base = g_handle_table_base();
    log_msg("[RAYCAST] htab base = 0x%llX\n", (unsigned long long)(uintptr_t)base);
    if (!base) return;
    static void* g_f8_arr = NULL;
    g_f8_arr = NULL; // reset each run
    static uint32_t g_f8_last_h = 0;
    if (!f_lua_newthread || !f_lua_getfield || !f_lua_rawgeti || !f_lua_touserdata) {
        log_msg("%s", "[RAYCAST] F8: lua APIs unavailable\n");
        return;
    }
    // stash the unit list in a global, then walk it in C (Lua units are USERDATA)
    exec_lua(
        "local S=stingray "
        "local w=S.Application.main_world() "
        "local ok, u1 = pcall(S.World.units, w) "
        "_G.rc_ents2 = (ok and type(u1)=='table') and u1 or {} "
        "return #_G.rc_ents2"
    );
    log_msg("[RAYCAST] units in list: %s\n", g_last_result);
    // KEY: world_position's 2nd arg is the scene-graph NODE index (disasm:
    // f2 = lua_tointeger(L,2), off = node-1). node=0 -> off=-1 -> garbage.
    // Verify node=1/2 return real coords.
    exec_lua(
        "local S=stingray "
        "local w=S.Application.main_world() "
        "local ok,u=pcall(S.World.units,w) "
        "if ok and type(u)=='table' and u[1] then "
        "  local unit=u[1] "
        "  local r={} "
        "  for n=1,4 do "
        "    local okw,wp=pcall(S.Unit.world_position,unit,n) "
        "    r[#r+1]=n..':'..(okw and wp and wp.x and string.format('(%.1f,%.1f,%.1f)',wp.x,wp.y,wp.z) or tostring(wp)) "
        "  end "
        "  return table.concat(r,' ') "
        "end "
        "return 'no units'"
    );
    log_msg("[RAYCAST] wp node test: %s\n", g_last_result);
    // Lua-level engine-fn probes (world_position etc.) were REMOVED: they
    // crash inside the engine (SEH caught) and leak its internal lock, which
    // deadlocks the game right after. F8 is PURE C READS only from here on.
    lua_State* T = f_lua_newthread(g_L);
    if (!T) return;
    __try {
        f_lua_getfield(T, LUA_GLOBALSINDEX, "rc_ents2");
        if (f_lua_type(T, -1) == LUA_TTABLE) {
            for (int i = 1; i <= 16; i++) {
                f_lua_rawgeti(T, -1, i);
                int t = f_lua_type(T, -1);
                if (t == LUA_TUSERDATA || t == LUA_TLIGHTUSERDATA) { // full or light userdata
                    void* ud = f_lua_touserdata(T, -1);
                    uint32_t h = 0;
                    double d = 0.0;
                    if (t == LUA_TLIGHTUSERDATA) { // lightuserdata: the value IS the handle
                        h = (uint32_t)(uintptr_t)ud;
                        d = (double)h;
                    } else {      // full userdata: data[0] = handle as double
                        d = ud ? *(double*)ud : 0.0;
                        h = (uint32_t)d;
                    }
                    void* obj = unit_handle_to_object(h);
                    log_msg("[RAYCAST] [%d] type=%d(%s) ud=0x%llX dbl=%.0f handle=%u(0x%X) -> obj=0x%llX\n",
                        i, t, f_lua_typename ? f_lua_typename(T, t) : "?",
                        (unsigned long long)(uintptr_t)ud, d, h, h,
                        (unsigned long long)(uintptr_t)obj);
                    if (obj) {
                        void* arr = *(void**)((uint8_t*)obj + 0x28);
                        if (!g_f8_arr) g_f8_arr = arr;
                        log_msg("[RAYCAST]   [obj+0x28]=0x%llX\n", (unsigned long long)(uintptr_t)arr);
                        if (arr) {
                            uint8_t* slot = (uint8_t*)arr + 0x30 + (uintptr_t)h * 64;
                            unsigned char sb[128];
                            SIZE_T sg = 0;
                            if (ReadProcessMemory(GetCurrentProcess(), slot, sb, sizeof(sb), &sg) && sg) {
                                char shex[512]; size_t so = 0;
                                for (SIZE_T k = 0; k < sg; k++)
                                    so += (size_t)sprintf_s(shex + so, sizeof(shex) - so, "%02X ", sb[k]);
                                log_msg("[RAYCAST]   slot@0x%llX: %s\n", (unsigned long long)(uintptr_t)slot, shex);
                                float* f = (float*)sb;
                                log_msg("[RAYCAST]   floats: %.2f %.2f %.2f | %.2f %.2f %.2f | %.2f %.2f %.2f | %.2f %.2f %.2f\n",
                                    f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11]);
                            }
                        }
                        unsigned char ob[256];
                        SIZE_T og = 0;
                        if (ReadProcessMemory(GetCurrentProcess(), obj, ob, sizeof(ob), &og) && og) {
                            char hex[1024]; size_t o = 0;
                            for (SIZE_T k = 0; k < og; k++)
                                o += (size_t)sprintf_s(hex + o, sizeof(hex) - o, "%02X ", ob[k]);
                            log_msg("[RAYCAST]   obj head: %s\n", hex);
                            // every 16-byte offset as 4 floats
                            for (int off = 0; off + 16 <= (int)og; off += 16) {
                                float* f = (float*)(ob + off);
                                log_msg("[RAYCAST]     +0x%02X f: %.2f %.2f %.2f %.2f\n",
                                    off, f[0], f[1], f[2], f[3]);
                            }
                            // pointer sub-structures removed: 256 RPMs per F8
                            // froze the game at obj+0x20 on some units (likely
                            // GameGuard interference); obj head+floats suffice.
                            // KEY: scene graph node layout (doc): [local | world | parent].
                            // Each pose = 3x3 rot + 3 trans (12 floats). So local
                            // trans = f[9..11], world trans = f[21..23]. Read 128B
                            // to cover both. Player (unit[1]) world ~= camera.
                            if (i <= 3) {
                                log_msg("[RAYCAST]     cam=(%.2f,%.2f,%.2f)\n", g_cam_x, g_cam_y, g_cam_z);
                                for (int q = 0; q < 16; q++) {
                                    uintptr_t p = 0;
                                    memcpy(&p, ob + q * 8, 8);
                                    if (p > 0x10000 && p < 0x7FFFFFFFFFFF) {
                                        unsigned char tb[128];
                                        SIZE_T tg = 0;
                                        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)p, tb, sizeof(tb), &tg) && tg >= 96) {
                                            float* f = (float*)tb;
                                            log_msg("[RAYCAST]     T[obj+0x%02X]=0x%llX LOCAL(%.2f,%.2f,%.2f) WORLD(%.2f,%.2f,%.2f)\n",
                                                q * 8, (unsigned long long)p,
                                                f[9], f[10], f[11], f[21], f[22], f[23]);
                                        }
                                    }
                                }
                            }
                            // component-array verification (world_position
                            // disasm): [obj+0x10] = component array, element
                            // k = component type k+1. component2 = type 2's
                            // [obj+0] double->int. off = component2 - 1.
                            if (i <= 3) {
                                uintptr_t comp_arr = 0;
                                memcpy(&comp_arr, ob + 0x10, 8);
                                log_msg("[RAYCAST]     comp_arr=[obj+0x10]=0x%llX\n", (unsigned long long)comp_arr);
                                if (comp_arr > 0x10000 && comp_arr < 0x7FFFFFFFFFFF) {
                                    for (int cidx = 0; cidx < 4; cidx++) {
                                        // element ADDRESS = comp_arr + cidx*8; read the
                                        // element's bytes directly (NOT dereference the
                                        // element as a pointer - the getter returns the
                                        // address and f2 reads [addr+0] as double).
                                        unsigned char elem[16];
                                        SIZE_T ge = 0;
                                        if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(comp_arr + (uintptr_t)cidx * 8), elem, sizeof(elem), &ge) || ge < 12) continue;
                                        double dv; memcpy(&dv, elem, 8);
                                        uint32_t ty; memcpy(&ty, elem + 4, 4);
                                        uint64_t raw; memcpy(&raw, elem, 8);
                                        log_msg("[RAYCAST]     comp[%d] raw=0x%llX dbl=%.1f int=%d type=0x%08X\n",
                                            cidx, (unsigned long long)raw, dv, (int)dv, ty);
                                    }
                                }
                            }
                        }
                    } else {
                        // diagnostics: why did handle->object fail?
                        uint8_t* gentab = *(uint8_t**)((uint8_t*)base + 0xA0);
                        void** objtab = *(void***)((uint8_t*)base + 0x88);
                        DWORD size = *(DWORD*)((uint8_t*)base + 0x98);
                        uint32_t index = h & 0x3FFFFF;
                        log_msg("[RAYCAST]   FAIL: size=%u gentab=0x%llX objtab=0x%llX index=%u gentab[idx]=%d\n",
                            size,
                            (unsigned long long)(uintptr_t)gentab,
                            (unsigned long long)(uintptr_t)objtab,
                            index,
                            (gentab && index < 0x400000) ? (int)gentab[index] : -1);
                        if (objtab && index < 0x400000 && objtab[index])
                            log_msg("[RAYCAST]   objtab[%u]=0x%llX (gen check failed?)\n",
                                index, (unsigned long long)(uintptr_t)objtab[index]);
                        // NOTE: calling lua51.dll+0x5320 directly was REMOVED:
                        // it crashed (SEH caught) but leaked an engine lock and
                        // deadlocked the game (user: game froze after F8).
                    }
                } else {
                    log_msg("[RAYCAST] [%d] type=%d (not userdata)\n", i, t);
                }
                f_lua_settop(T, -2); // pop the value
            }
            // GROUND TRUTH = the LAST F4-HIT entity: the user visually
            // confirmed the ray line endpoint (cam + fwd * rc_hit_d), so we
            // verify coordinates against THAT point, never against Unit.box
            // (user: static boxes are wrong).
            exec_lua("_G.rc_hitu2 = _G.rc_hit_unit or _G.rc_ents2[763] return tostring(_G.rc_hitu2 ~= nil)");
            exec_lua("return string.format('%.4f', _G.rc_hit_d or 0)");
            double hit_d = atof(g_last_result);
            double hx = g_cam_x + g_fwd_x * hit_d;
            double hy = g_cam_y + g_fwd_y * hit_d;
            double hz = g_cam_z + g_fwd_z * hit_d;
            f_lua_getfield(T, LUA_GLOBALSINDEX, "rc_hitu2");
            {
                int t = f_lua_type(T, -1);
                if (t == LUA_TLIGHTUSERDATA || t == LUA_TUSERDATA) {
                    void* ud = f_lua_touserdata(T, -1);
                    uint32_t h = (t == LUA_TLIGHTUSERDATA)
                        ? (uint32_t)(uintptr_t)ud
                        : (uint32_t)(ud ? *(double*)ud : 0);
                    void* obj = unit_handle_to_object(h);
                    g_f8_last_h = h;
                    log_msg("[RAYCAST] [HIT] handle=%u(0x%X) -> obj=0x%llX hit=(%.2f,%.2f,%.2f) dist=%.2f\n",
                        h, h, (unsigned long long)(uintptr_t)obj, hx, hy, hz, hit_d);
                    if (obj) {
                        void* arr = *(void**)((uint8_t*)obj + 0x28);
                        log_msg("[RAYCAST]   [763 obj+0x28]=0x%llX\n", (unsigned long long)(uintptr_t)arr);
                        if (arr) {
                            uint8_t* slot = (uint8_t*)arr + 0x30 + (uintptr_t)h * 64;
                            unsigned char sb[256];
                            SIZE_T sg = 0;
                            if (ReadProcessMemory(GetCurrentProcess(), slot, sb, sizeof(sb), &sg) && sg) {
                                char shex[1024]; size_t so = 0;
                                for (SIZE_T k = 0; k < sg; k++)
                                    so += (size_t)sprintf_s(shex + so, sizeof(shex) - so, "%02X ", sb[k]);
                                log_msg("[RAYCAST]   [763 slot] %s\n", shex);
                                for (int off = 0; off + 16 <= (int)sg; off += 16) {
                                    float* f = (float*)(sb + off);
                                    log_msg("[RAYCAST]     +0x%02X f: %.2f %.2f %.2f %.2f\n",
                                        off, f[0], f[1], f[2], f[3]);
                                }
                            }
                        }
                        unsigned char ob[256];
                        SIZE_T og = 0;
                        if (ReadProcessMemory(GetCurrentProcess(), obj, ob, sizeof(ob), &og) && og) {
                            char hex[1024]; size_t o = 0;
                            for (SIZE_T k = 0; k < og; k++)
                                o += (size_t)sprintf_s(hex + o, sizeof(hex) - o, "%02X ", ob[k]);
                            log_msg("[RAYCAST]   [763 obj] %s\n", hex);
                            for (int off = 0; off + 16 <= (int)og; off += 16) {
                                float* f = (float*)(ob + off);
                                log_msg("[RAYCAST]     +0x%02X f: %.2f %.2f %.2f %.2f\n",
                                    off, f[0], f[1], f[2], f[3]);
                            }
                        }
                    } else {
                        // diagnostics: WHY did handle->object fail?
                        uint8_t* gentab = *(uint8_t**)((uint8_t*)base + 0xA0);
                        void** objtab = *(void***)((uint8_t*)base + 0x88);
                        DWORD size = *(DWORD*)((uint8_t*)base + 0x98);
                        log_msg("[RAYCAST]   [763 FAIL] size=%u gentab=0x%llX objtab=0x%llX\n",
                            size,
                            (unsigned long long)(uintptr_t)gentab,
                            (unsigned long long)(uintptr_t)objtab);
                        // FULL-SCAN proved objtab has NO entry with obj+8==h:
                        // static objects (763) are NOT in the object table.
                        // Their data lives in the shared slot array directly:
                        // slot = arr + 0x30 + handle*64 (no obj needed).
                        log_msg("[RAYCAST]   [763 FAIL] size=%u gentab=0x%llX objtab=0x%llX (static: not in objtab)\n",
                            size,
                            (unsigned long long)(uintptr_t)gentab,
                            (unsigned long long)(uintptr_t)objtab);
                        // SWEEP: every plausible table offset x layout x index
                        // encoding, verify each hit via obj+8 == handle.
                        {
                            uintptr_t hb = (uintptr_t)g_handle_table_base();
                            static const DWORD toffs[] = { 0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0 };
                            for (int ti = 0; ti < (int)(sizeof(toffs) / sizeof(toffs[0])); ti++) {
                                // layout A: direct array ptr at base+off, size at base+off+0x10
                                uintptr_t arrA = 0; SIZE_T gA = 0;
                                if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(hb + toffs[ti]), &arrA, 8, &gA) && gA == 8 && arrA > 0x10000 && arrA < 0x7FFFFFFFFFFF) {
                                    DWORD szA = 0; SIZE_T gsA = 0;
                                    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(hb + toffs[ti] + 0x10), &szA, 4, &gsA);
                                    if (gsA == 4 && szA && szA < 0x100000) {
                                        for (int im = 0; im < 4; im++) {
                                            uint32_t idx = (im == 0) ? (h & 0x3FFFFF) : (im == 1) ? (h >> 2) : (im == 2) ? (h & 0x3FF) : h;
                                            if (idx >= szA) continue;
                                            void* objA = NULL; SIZE_T goA = 0;
                                            if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(arrA + (uintptr_t)idx * 8), &objA, 8, &goA) || goA != 8) continue;
                                            if (objA <= (void*)0x10000 || objA >= (void*)0x7FFFFFFFFFFF) continue;
                                            uint32_t ohA = 0; SIZE_T ghA = 0;
                                            if (ReadProcessMemory(GetCurrentProcess(), (uint8_t*)objA + 8, &ohA, 4, &ghA) && ghA == 4) {
                                                log_msg("[RAYCAST]   sweepA off=0x%02X idx=%-7u obj=0x%llX obj+8=%u %s\n",
                                                    toffs[ti], idx, (unsigned long long)(uintptr_t)objA, ohA,
                                                    ohA == h ? "<- MATCH" : "");
                                                if (ohA != h) {
                                                    // verify against known box coords via body triples
                                                    unsigned char obT[256];
                                                    SIZE_T ogT = 0;
                                                    if (ReadProcessMemory(GetCurrentProcess(), objA, obT, sizeof(obT), &ogT) && ogT) {
                                                        for (int off = 0; off + 12 <= (int)ogT; off += 4) {
                                                            float* f = (float*)(obT + off);
                                                            float ax = fabsf(f[0]), ay = fabsf(f[1]), az = fabsf(f[2]);
                                                            if ((ax > 0.5f && ax < 5000.0f) && (ay > 0.5f && ay < 5000.0f) && (az > 0.5f && az < 5000.0f))
                                                                log_msg("[RAYCAST]   sweepA off=0x%02X idx=%-7u obj+0x%02X triple: %.2f %.2f %.2f\n",
                                                                    toffs[ti], idx, off, f[0], f[1], f[2]);
                                                        }
                                                    }
                                                }
                                                if (ohA == h) {
                                                    void* arrM = *(void**)((uint8_t*)objA + 0x28);
                                                    log_msg("[RAYCAST]     MATCH obj+0x28=0x%llX\n", (unsigned long long)(uintptr_t)arrM);
                                                    if (arrM) {
                                                        uint8_t* slot = (uint8_t*)arrM + 0x30 + (uintptr_t)h * 64;
                                                        unsigned char sbM[128];
                                                        SIZE_T sgM = 0;
                                                        if (ReadProcessMemory(GetCurrentProcess(), slot, sbM, sizeof(sbM), &sgM) && sgM) {
                                                            float* f = (float*)sbM;
                                                            log_msg("[RAYCAST]     MATCH slot floats: %.2f %.2f %.2f | %.2f %.2f %.2f | %.2f %.2f %.2f\n",
                                                                f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]);
                                                        }
                                                    }
                                                    unsigned char obM[256];
                                                    SIZE_T ogM = 0;
                                                    if (ReadProcessMemory(GetCurrentProcess(), objA, obM, sizeof(obM), &ogM) && ogM) {
                                                        for (int off = 0; off + 12 <= (int)ogM; off += 4) {
                                                            float* f = (float*)(obM + off);
                                                            float ax = fabsf(f[0]), ay = fabsf(f[1]), az = fabsf(f[2]);
                                                            if ((ax > 0.5f && ax < 5000.0f) && (ay > 0.5f && ay < 5000.0f) && (az > 0.5f && az < 5000.0f))
                                                                log_msg("[RAYCAST]     MATCH obj+0x%02X triple: %.2f %.2f %.2f\n",
                                                                    off, f[0], f[1], f[2]);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                // layout B: table ptr at base+off, arr at tbl+8, size at tbl+0x18
                                uintptr_t tblB = 0; SIZE_T gB = 0;
                                if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(hb + toffs[ti]), &tblB, 8, &gB) && gB == 8 && tblB > 0x10000 && tblB < 0x7FFFFFFFFFFF) {
                                    uintptr_t arrB = 0; SIZE_T gaB = 0;
                                    if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(tblB + 8), &arrB, 8, &gaB) && gaB == 8 && arrB > 0x10000 && arrB < 0x7FFFFFFFFFFF) {
                                        DWORD szB = 0; SIZE_T gsB = 0;
                                        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(tblB + 0x18), &szB, 4, &gsB) && gsB == 4 && szB && szB < 0x100000) {
                                            for (int im = 0; im < 4; im++) {
                                                uint32_t idx = (im == 0) ? (h & 0x3FFFFF) : (im == 1) ? (h >> 2) : (im == 2) ? (h & 0x3FF) : h;
                                                if (idx >= szB) continue;
                                                void* objB = NULL; SIZE_T goB = 0;
                                                if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(arrB + (uintptr_t)idx * 8), &objB, 8, &goB) || goB != 8) continue;
                                                if (objB <= (void*)0x10000 || objB >= (void*)0x7FFFFFFFFFFF) continue;
                                                uint32_t ohB = 0; SIZE_T ghB = 0;
                                                if (ReadProcessMemory(GetCurrentProcess(), (uint8_t*)objB + 8, &ohB, 4, &ghB) && ghB == 4) {
                                                    log_msg("[RAYCAST]   sweepB off=0x%02X idx=%-7u obj=0x%llX obj+8=%u %s\n",
                                                        toffs[ti], idx, (unsigned long long)(uintptr_t)objB, ohB,
                                                        ohB == h ? "<- MATCH" : "");
                                                    if (ohB != h) {
                                                        unsigned char obT[256];
                                                        SIZE_T ogT = 0;
                                                        if (ReadProcessMemory(GetCurrentProcess(), objB, obT, sizeof(obT), &ogT) && ogT) {
                                                            for (int off = 0; off + 12 <= (int)ogT; off += 4) {
                                                                float* f = (float*)(obT + off);
                                                                float ax = fabsf(f[0]), ay = fabsf(f[1]), az = fabsf(f[2]);
                                                                if ((ax > 0.5f && ax < 5000.0f) && (ay > 0.5f && ay < 5000.0f) && (az > 0.5f && az < 5000.0f))
                                                                    log_msg("[RAYCAST]   sweepB off=0x%02X idx=%-7u obj+0x%02X triple: %.2f %.2f %.2f\n",
                                                                        toffs[ti], idx, off, f[0], f[1], f[2]);
                                                            }
                                                        }
                                                    }
                                                    if (ohB == h) {
                                                        void* arrM = *(void**)((uint8_t*)objB + 0x28);
                                                        log_msg("[RAYCAST]     MATCH obj+0x28=0x%llX\n", (unsigned long long)(uintptr_t)arrM);
                                                        if (arrM) {
                                                            uint8_t* slot = (uint8_t*)arrM + 0x30 + (uintptr_t)h * 64;
                                                            unsigned char sbM[128];
                                                            SIZE_T sgM = 0;
                                                            if (ReadProcessMemory(GetCurrentProcess(), slot, sbM, sizeof(sbM), &sgM) && sgM) {
                                                                float* f = (float*)sbM;
                                                                log_msg("[RAYCAST]     MATCH slot floats: %.2f %.2f %.2f | %.2f %.2f %.2f | %.2f %.2f %.2f\n",
                                                                    f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]);
                                                            }
                                                        }
                                                        unsigned char obM[256];
                                                        SIZE_T ogM = 0;
                                                        if (ReadProcessMemory(GetCurrentProcess(), objB, obM, sizeof(obM), &ogM) && ogM) {
                                                            for (int off = 0; off + 12 <= (int)ogM; off += 4) {
                                                                float* f = (float*)(obM + off);
                                                                float ax = fabsf(f[0]), ay = fabsf(f[1]), az = fabsf(f[2]);
                                                                if ((ax > 0.5f && ax < 5000.0f) && (ay > 0.5f && ay < 5000.0f) && (az > 0.5f && az < 5000.0f))
                                                                    log_msg("[RAYCAST]     MATCH obj+0x%02X triple: %.2f %.2f %.2f\n",
                                                                        off, f[0], f[1], f[2]);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (g_f8_arr) {
                            uint8_t* slot = (uint8_t*)g_f8_arr + 0x30 + (uintptr_t)h * 64;
                            // wide window: this slot +/- 4 slots (512 bytes)
                            uint8_t* win = slot - 0x100;
                            unsigned char sb[512];
                            SIZE_T sg = 0;
                            if (ReadProcessMemory(GetCurrentProcess(), win, sb, sizeof(sb), &sg) && sg) {
                                char shex[2048]; size_t so = 0;
                                for (SIZE_T k = 0; k < sg; k++)
                                    so += (size_t)sprintf_s(shex + so, sizeof(shex) - so, "%02X ", sb[k]);
                                log_msg("[RAYCAST]   [763 win@0x%llX h*64] %s\n",
                                    (unsigned long long)(uintptr_t)win, shex);
                                // every 16-byte offset as floats
                                for (int off = 0; off + 16 <= (int)sg; off += 16) {
                                    float* f = (float*)(sb + off);
                                    log_msg("[RAYCAST]     %+03X f: %.2f %.2f %.2f %.2f\n",
                                        off - 0x100, f[0], f[1], f[2], f[3]);
                                }
                                // coordinate-like triple scan (0.5..5000 abs)
                                for (int off = 0; off + 12 <= (int)sg; off += 4) {
                                    float* f = (float*)(sb + off);
                                    float ax = fabsf(f[0]), ay = fabsf(f[1]), az = fabsf(f[2]);
                                    if ((ax > 0.5f && ax < 5000.0f) && (ay > 0.5f && ay < 5000.0f) && (az > 0.5f && az < 5000.0f))
                                        log_msg("[RAYCAST]       win%+03X triple: %.2f %.2f %.2f\n",
                                            off - 0x100, f[0], f[1], f[2]);
                                }
                            } else {
                                log_msg("[RAYCAST]   [763 win] read FAILED @0x%llX\n",
                                    (unsigned long long)(uintptr_t)win);
                            }
                        }
                        // reference: known box from Lua pcall (safe, F4 uses it)
                        exec_lua(
                            "local u = _G.rc_ents2[763] "
                            "if not u then return 'oob' end "
                            "local okb, b1, b2 = pcall(stingray.Unit.box, u) "
                            "if not okb then return 'boxfail' end "
                            "if b1 and b2 and b1.x then "
                            "  if b2.x >= b1.x then "
                            "    return string.format('box minmax c=(%.2f,%.2f,%.2f) half=(%.2f,%.2f,%.2f)', (b1.x+b2.x)/2,(b1.y+b2.y)/2,(b1.z+b2.z)/2,(b2.x-b1.x)/2,(b2.y-b1.y)/2,(b2.z-b1.z)/2) "
                            "  else "
                            "    return string.format('box center c=(%.2f,%.2f,%.2f) half=(%.2f,%.2f,%.2f)', b1.x,b1.y,b1.z,b2.x/2,b2.y/2,b2.z/2) "
                            "  end "
                            "else return 'badbox' end"
                        );
                        log_msg("[RAYCAST]   [763 box ref] %s\n", g_last_result);
                        // CRITICAL: [763 win] above shows UTF-16 name/string
                        // data - obj+0x28's array is a NAME table, not
                        // positions. world_position disasm uses [World+0x28]
                        // (World object, not Unit obj). Grab World from Lua:
                        exec_lua("_G.rc_world = stingray.Application.main_world() return type(_G.rc_world)");
                        log_msg("[RAYCAST]   world lua type: %s\n", g_last_result);
                        {
                            lua_State* T3 = f_lua_newthread(g_L);
                            if (T3) {
                                __try {
                                    f_lua_getfield(T3, LUA_GLOBALSINDEX, "rc_world");
                                    int wt = f_lua_type(T3, -1);
                                    uintptr_t wv = 0;
                                    if (wt == LUA_TLIGHTUSERDATA)
                                        wv = (uintptr_t)f_lua_touserdata(T3, -1);
                                    else if (wt == LUA_TUSERDATA) {
                                        void* ud = f_lua_touserdata(T3, -1);
                                        if (ud) wv = *(uintptr_t*)ud;
                                    } else if (wt == LUA_TNUMBER)
                                        wv = (uintptr_t)f_lua_tonumber(T3, -1);
                                    log_msg("[RAYCAST]   world value=0x%llX type=%d\n",
                                        (unsigned long long)wv, wt);
                                    f_lua_settop(T3, 0);
                                    if (wv > 0x10000) {
                                        uintptr_t arrp = 0;
                                        SIZE_T gr2 = 0;
                                        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(wv + 0x28), &arrp, 8, &gr2) && gr2 == 8) {
                                            log_msg("[RAYCAST]   world+0x28 = 0x%llX\n", (unsigned long long)arrp);
                                            if (arrp > 0x10000) {
                                                uint8_t* slot = (uint8_t*)arrp + 0x30 + (uintptr_t)h * 64;
                                                unsigned char sb2[128];
                                                SIZE_T sg2 = 0;
                                                if (ReadProcessMemory(GetCurrentProcess(), slot, sb2, sizeof(sb2), &sg2) && sg2) {
                                                    char shex2[512]; size_t so2 = 0;
                                                    for (SIZE_T k = 0; k < sg2; k++)
                                                        so2 += (size_t)sprintf_s(shex2 + so2, sizeof(shex2) - so2, "%02X ", sb2[k]);
                                                    log_msg("[RAYCAST]   world-slot@0x%llX: %s\n",
                                                        (unsigned long long)(uintptr_t)slot, shex2);
                                                    float* f = (float*)sb2;
                                                    log_msg("[RAYCAST]   world-slot floats: %.2f %.2f %.2f | %.2f %.2f %.2f | %.2f %.2f %.2f\n",
                                                        f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]);
                                                }
                                            }
                                        }
                                    }
                                } __except (EXCEPTION_EXECUTE_HANDLER) {
                                    log_msg("[RAYCAST]   world probe SEH 0x%08X\n", GetExceptionCode());
                                }
                                f_lua_settop(g_L, -2); // pop thread obj
                            }
                        }
                    }
                } else {
                    log_msg("[RAYCAST] [763] type=%d (not userdata)\n", t);
                }
            }
            f_lua_settop(T, -2); // pop 763 value
            // dump the engine's OWN handle resolver: world_position's E8
            // sub-function (0x7FF71EF3DA50-style). Its machine code reveals
            // the REAL handle->obj index encoding (arithmetic guesses failed:
            // >>2 / &0x3FF gave obj whose +8 field != handle).
            {
                lua_State* T2 = f_lua_newthread(g_L);
                if (T2) {
                    __try {
                        f_lua_getfield(T2, LUA_GLOBALSINDEX, "stingray");
                        if (f_lua_type(T2, -1) == LUA_TTABLE) {
                            f_lua_getfield(T2, -1, "Unit");
                            if (f_lua_type(T2, -1) == LUA_TTABLE) {
                                f_lua_getfield(T2, -1, "world_position");
                                uintptr_t wp = 0;
                                if (f_lua_type(T2, -1) == LUA_TFUNCTION && f_lua_tocfunction)
                                    wp = (uintptr_t)f_lua_tocfunction(T2, -1);
                                f_lua_settop(T2, 0);
                                if (wp > 0x10000) {
                                    unsigned char wb[256];
                                    SIZE_T wg = 0;
                                    if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)wp, wb, sizeof(wb), &wg) && wg) {
                                                // dump the FULL world_position body so we can
                                                // disassemble how it reads world transform from
                                                // the object (the E8 sub is only the handle part).
                                                {
                                                    char whex[1024]; size_t wo = 0;
                                                    for (SIZE_T k = 0; k < wg; k++)
                                                        wo += (size_t)sprintf_s(whex + wo, sizeof(whex) - wo, "%02X ", wb[k]);
                                                    log_msg("[RAYCAST] world_position body @0x%llX: %s\n",
                                                        (unsigned long long)wp, whex);
                                                }
                                                for (int j = 0; j + 4 < (int)wg; j++) {
                                                    if (wb[j] == 0xE8) {
                                                        int32_t disp;
                                                        memcpy(&disp, wb + j + 1, 4);
                                                        uintptr_t sub = (uintptr_t)(wp + j + 5 + disp);
                                                        log_msg("[RAYCAST] resolver E8[%d] sub=0x%llX\n", j, (unsigned long long)sub);
                                                        unsigned char sb[256];
                                                        SIZE_T sg = 0;
                                                        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)sub, sb, sizeof(sb), &sg) && sg) {
                                                            char hex[1024]; size_t o = 0;
                                                            for (SIZE_T k = 0; k < sg; k++)
                                                                o += (size_t)sprintf_s(hex + o, sizeof(hex) - o, "%02X ", sb[k]);
                                                            log_msg("[RAYCAST] resolver bytes: %s\n", hex);
                                                            // resolver's OWN global(s): scan EVERY mov rsi,[rip+disp]
                                                            // (48 8B 35) - the prologue stores regs first, so the mov
                                                            // sits at +0x0D, not offset 0 (previous version missed it).
                                                            for (int q = 0; q + 6 < (int)sg; q++) {
                                                                if (sb[q] == 0x48 && sb[q + 1] == 0x8B && sb[q + 2] == 0x35) {
                                                                    int32_t disp3;
                                                                    memcpy(&disp3, sb + q + 3, 4);
                                                                    uintptr_t rg = (uintptr_t)(sub + q + 7 + disp3);
                                                                    uintptr_t gval = 0;
                                                                    SIZE_T gv = 0;
                                                                    if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)rg, &gval, 8, &gv) && gv == 8 && gval > 0x10000 && gval < 0x7FFFFFFFFFFF) {
                                                                        log_msg("[RAYCAST]   resolver mov rsi @+0x%02X global 0x%llX = 0x%llX\n",
                                                                            q, (unsigned long long)rg, (unsigned long long)gval);
                                                                        uintptr_t tbl2 = 0;
                                                                        SIZE_T gt2 = 0;
                                                                        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(gval + 0xD0), &tbl2, 8, &gt2) && gt2 == 8 && tbl2) {
                                                                            log_msg("[RAYCAST]   resolver table [g+0xD0] = 0x%llX\n", (unsigned long long)tbl2);
                                                                            uintptr_t arr2 = 0;
                                                                            SIZE_T ga2 = 0;
                                                                            DWORD sz2 = 0;
                                                                            SIZE_T gs2 = 0;
                                                                            if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(tbl2 + 8), &arr2, 8, &ga2) && ga2 == 8)
                                                                                ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(tbl2 + 0x18), &sz2, 4, &gs2);
                                                                            log_msg("[RAYCAST]   resolver arr=0x%llX size=%u\n",
                                                                                (unsigned long long)arr2, sz2);
                                                                            uint32_t idx2 = g_f8_last_h & 0x3FFFFF;
                                                                            if (arr2 && sz2 && idx2 < sz2) {
                                                                                void* obj2 = NULL;
                                                                                SIZE_T go2 = 0;
                                                                                if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(arr2 + (uintptr_t)idx2 * 8), &obj2, 8, &go2) && go2 == 8 && obj2 > (void*)0x10000 && obj2 < (void*)0x7FFFFFFFFFFF) {
                                                                                    uint32_t oh2 = 0;
                                                                                    SIZE_T gh2 = 0;
                                                                                    if (ReadProcessMemory(GetCurrentProcess(), (uint8_t*)obj2 + 8, &oh2, 4, &gh2) && gh2 == 4)
                                                                                        log_msg("[RAYCAST]   resolver obj=0x%llX obj+8=%u %s\n",
                                                                                            (unsigned long long)(uintptr_t)obj2, oh2,
                                                                                            oh2 == g_f8_last_h ? "<- MATCH" : "");
                                                                                    if (oh2 == g_f8_last_h) {
                                                                                        void* arrM2 = *(void**)((uint8_t*)obj2 + 0x28);
                                                                                        log_msg("[RAYCAST]   RMATCH obj+0x28=0x%llX\n", (unsigned long long)(uintptr_t)arrM2);
                                                                                        if (arrM2) {
                                                                                            uint8_t* slot = (uint8_t*)arrM2 + 0x30 + (uintptr_t)g_f8_last_h * 64;
                                                                                            unsigned char sbR[128];
                                                                                            SIZE_T sgR = 0;
                                                                                            if (ReadProcessMemory(GetCurrentProcess(), slot, sbR, sizeof(sbR), &sgR) && sgR) {
                                                                                                float* f = (float*)sbR;
                                                                                                log_msg("[RAYCAST]   RMATCH slot floats: %.2f %.2f %.2f | %.2f %.2f %.2f | %.2f %.2f %.2f\n",
                                                                                                    f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]);
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                } else {
                                                                                    log_msg("[RAYCAST]   resolver arr[%u] = NULL/OOR\n", idx2);
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            // FF 15 indirect call targets inside the resolver
                                                            for (int m = 0; m + 5 < (int)sg; m++) {
                                                                if (sb[m] == 0xFF && sb[m + 1] == 0x15) {
                                                                    int32_t disp2;
                                                                    memcpy(&disp2, sb + m + 2, 4);
                                                                    uintptr_t slotp = (uintptr_t)(sub + m + 6 + disp2);
                                                                    uintptr_t tgt = 0;
                                                                    SIZE_T tr2 = 0;
                                                                    if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)slotp, &tgt, 8, &tr2) && tr2 == 8) {
                                                                        log_msg("[RAYCAST]   resolver FF15[%d] -> fn=0x%llX\n", m, (unsigned long long)tgt);
                                                                        if (tgt > 0x10000) {
                                                                            unsigned char tb[256];
                                                                            SIZE_T tg2 = 0;
                                                                            if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)tgt, tb, sizeof(tb), &tg2) && tg2) {
                                                                                char thex[1024]; size_t to2 = 0;
                                                                                for (SIZE_T k2 = 0; k2 < tg2; k2++)
                                                                                    to2 += (size_t)sprintf_s(thex + to2, sizeof(thex) - to2, "%02X ", tb[k2]);
                                                                                log_msg("[RAYCAST]   resolver FF15 tgt bytes: %s\n", thex);
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                    }
                                }
                            }
                            f_lua_settop(T2, 0);
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        log_msg("[RAYCAST] resolver disasm SEH 0x%08X\n", GetExceptionCode());
                    }
                    f_lua_settop(g_L, -2); // pop thread obj
                }
            }
        } else {
            log_msg("%s", "[RAYCAST] rc_ents2 not a table\n");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_msg("[RAYCAST] F8 SEH 0x%08X\n", GetExceptionCode());
    }
    f_lua_settop(T, 0);
    f_lua_settop(g_L, -2); // pop thread obj
}

// ============================================================
// Broadphase probe (Insert key) - find the game's own broadphase
// ============================================================
static void probe_broadphase(void) {
    log_msg("[RAYCAST] === Broadphase raycast test v2 ===\n");
    
    // Use stingray.Vector3, not global Vector3
    // Test 1: Create broadphase and add one item
    exec_lua(
        "local S = stingray "
        "local V3 = S.Vector3 "
        "if not S or not S.Broadphase then return 'no Broadphase' end "
        "if not V3 then return 'no Vector3' end "
        "local bp = S.Broadphase('probe_bp') "
        "_G.test_bp = bp "
        "bp:add('test_item', V3(0,0,0), 1.0) "
        "local all = bp:all() "
        "return 'BP created, all() count='..#all "
    );
    
    // Test 2: query with a box (AABB min, max)
    exec_lua(
        "local S = stingray "
        "local V3 = S.Vector3 "
        "local bp = _G.test_bp "
        "if not bp then return 'no bp' end "
        "local ok, res = pcall(function() "
        "  return bp:query(V3(-10,-10,-10), V3(10,10,10)) "
        "end) "
        "if not ok then return 'box_query err: '..tostring(res) end "
        "if type(res) == 'table' then return 'box_query OK: '..#res..' items' end "
        "return 'box_query OK: '..type(res) "
    );
    
    // Test 3: query with 'ray' type + direction
    exec_lua(
        "local S = stingray "
        "local V3 = S.Vector3 "
        "local bp = _G.test_bp "
        "if not bp then return 'no bp' end "
        "local ok, res = pcall(function() "
        "  return bp:query('ray', V3(-10,0,0), V3(1,0,0)) "
        "end) "
        "if not ok then return 'ray_query err: '..tostring(res) end "
        "if type(res) == 'table' then return 'ray_query OK: '..#res..' items' end "
        "return 'ray_query OK: '..type(res) "
    );
    
    // Test 4: query with 'ray' + max_length
    exec_lua(
        "local S = stingray "
        "local V3 = S.Vector3 "
        "local bp = _G.test_bp "
        "if not bp then return 'no bp' end "
        "local ok, res = pcall(function() "
        "  return bp:query('ray', V3(-10,0,0), V3(1,0,0), 20) "
        "end) "
        "if not ok then return 'ray20 err: '..tostring(res) end "
        "if type(res) == 'table' then return 'ray20 OK: '..#res..' items' end "
        "return 'ray20 OK: '..type(res) "
    );
    
    // Test 5: query_item_data_pairs
    exec_lua(
        "local bp = _G.test_bp "
        "if not bp then return 'no bp' end "
        "local ok, res = pcall(function() "
        "  return bp:query_item_data_pairs() "
        "end) "
        "if not ok then return 'qidp err: '..tostring(res) end "
        "return 'qidp OK: '..type(res) "
    );
    
    // Test 6: move an item
    exec_lua(
        "local S = stingray "
        "local V3 = S.Vector3 "
        "local bp = _G.test_bp "
        "if not bp then return 'no bp' end "
        "local ok, err = pcall(function() "
        "  bp:move('test_item', V3(5,0,0)) "
        "end) "
        "if not ok then return 'move err: '..tostring(err) end "
        "return 'move OK' "
    );
    
    // Test 7: remove + clean up (wrapped in pcall for safety)
    exec_lua(
        "local bp = _G.test_bp "
        "if not bp then return 'no bp' end "
        "local ok, err = pcall(function() "
        "  bp:remove('test_item') "
        "end) "
        "_G.test_bp = nil "
        "if not ok then return 'remove err: '..tostring(err) end "
        "return 'cleaned up OK' "
    );
    
    log_msg("[RAYCAST] === Broadphase test done ===\n");
}

// ============================================================
// Memory dump (C-level invasive inspection)
// ============================================================
static int is_readable(const void *ptr, size_t size) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    DWORD prot = mbi.Protect & 0xFF;
    if (prot == PAGE_NOACCESS || prot == PAGE_GUARD) return 0;
    return 1;
}

static void dump_mem(const char *label, const void *ptr, int size) {
    if (!ptr) {
        log_msg("[RAYCAST] [DUMP] %s: NULL\n", label);
        return;
    }
    if (!is_readable(ptr, size)) {
        log_msg("[RAYCAST] [DUMP] %s: %p (unreadable)\n", label, ptr);
        return;
    }

    log_msg("[RAYCAST] [DUMP] %s: ptr=%p (%d bytes)\n", label, ptr, size);

    for (int off = 0; off < size; off += 16) {
        char line[256];
        int pos = 0;
        pos += snprintf(line + pos, sizeof(line) - pos, "[RAYCAST] [DUMP]   +0x%03x: ", off);

        for (int i = 0; i < 16 && off + i < size; i++) {
            pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", ((uint8_t *)ptr)[off + i]);
        }
        for (int i = 16 - (size - off < 16 ? size - off : 16); i > 0; i--) {
            pos += snprintf(line + pos, sizeof(line) - pos, "   ");
        }

        pos += snprintf(line + pos, sizeof(line) - pos, " |");
        for (int i = 0; i < 16 && off + i < size; i++) {
            uint8_t b = ((uint8_t *)ptr)[off + i];
            pos += snprintf(line + pos, sizeof(line) - pos, "%c", (b >= 32 && b < 127) ? b : '.');
        }
        pos += snprintf(line + pos, sizeof(line) - pos, "|\n");
        log_msg("%s", line);
    }
}

static void *get_lua_result_userdata(lua_State *T) {
    if (!T || !f_lua_touserdata) return NULL;
    int top = f_lua_gettop(T);
    if (top < 1) return NULL;
    int t = f_lua_type(T, 1);
    if (t != LUA_TUSERDATA && t != LUA_TTABLE) return NULL;
    return f_lua_touserdata(T, 1);
}

// ============================================================
// C-level memory dump probe (F8)
// Dumps World and Unit C++ struct memory to find physics/broadphase offsets
// ============================================================
static void dump_world_and_unit(void) {
    if (!f_lua_touserdata) {
        log_msg("%s", "[RAYCAST] [DUMP] lua_touserdata not available\n");
        return;
    }

    if (!g_L || !f_luaL_loadstring || !o_lua_pcall || !f_lua_newthread) return;
    if (g_segfault_flag) {
        log_msg("%s", "[RAYCAST] [DUMP] Skipping (segfault cooldown)\n");
        return;
    }

    // === Phase 1: World C++ struct (512 bytes) + follow key pointers ===
    log_msg("%s", "[RAYCAST] [DUMP] === World C++ struct (512 bytes) ===\n");

    int top = f_lua_gettop(g_L);
    lua_State *T = f_lua_newthread(g_L);
    if (!T) { f_lua_settop(g_L, top); return; }

    const char *world_code =
        "local S = stingray "
        "local w = S.Application.main_world() "
        "return w";

    if (f_luaL_loadstring(T, world_code) != 0) {
        const char *err = f_lua_tolstring(T, -1, NULL);
        log_msg("[RAYCAST] [DUMP] World load err: %s\n", err ? err : "?");
        f_lua_settop(g_L, top);
        return;
    }

    __try {
        o_lua_pcall(T, 0, 1, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_msg("[RAYCAST] [DUMP] World SEH 0x%08X\n", GetExceptionCode());
        InterlockedExchange(&g_segfault_flag, 1);
        InterlockedExchange((volatile LONG *)&g_segfault_tick, GetTickCount());
        f_lua_settop(g_L, top);
        return;
    }

    void *world_ud = f_lua_touserdata(T, 1);
    log_msg("[RAYCAST] [DUMP] World userdata at %p\n", world_ud);

    void *world_cpp = NULL;
    if (world_ud && is_readable(world_ud, 32)) {
        dump_mem("World userdata", world_ud, 32);
        world_cpp = *(void **)world_ud;
    }

    f_lua_settop(g_L, top);

    if (world_cpp && is_readable(world_cpp, 512)) {
        dump_mem("World C++ object", world_cpp, 512);

        // Follow key pointers and dump their memory
        int follow_offsets[] = {0x008, 0x018, 0x020, 0x030, 0x038, 0x0b8, 0x0c0, 0x0c8, 0x0d0, 0x0e8};
        for (int i = 0; i < 10; i++) {
            int off = follow_offsets[i];
            void *ptr = *(void **)((uint8_t *)world_cpp + off);
            if (ptr && is_readable(ptr, 128)) {
                char label[64];
                snprintf(label, sizeof(label), "World+0x%03x -> %p", off, ptr);
                dump_mem(label, ptr, 128);
            }
        }
    }

    // === Phase 2: Test find_units_intersecting + local_position(u, 0) ===
    log_msg("%s", "[RAYCAST] [DUMP] === find_units_intersecting + pre-filter test ===\n");

    exec_lua(
        "local S = stingray\n"
        "local w = S.Application.main_world()\n"
        "local M = S.Matrix4x4\n"
        "local pose = S.World.debug_camera_pose(w)\n"
        "local cam = M.translation(pose)\n"
        "-- Sphere is nil, try different arg formats\n"
        "local units = nil\n"
        "local fui = 'none'\n"
        "local ok, res = pcall(S.World.find_units_intersecting, w, {center=cam, radius=50})\n"
        "if ok and type(res) == 'table' then units = res; fui = 'table' end\n"
        "if not units then\n"
        "  ok, res = pcall(S.World.find_units_intersecting, w, cam, 50)\n"
        "  if ok and type(res) == 'table' then units = res; fui = 'v3+r' end\n"
        "end\n"
        "if not units then\n"
        "  ok, res = pcall(S.World.find_units_intersecting, w, cam.x, cam.y, cam.z, 50)\n"
        "  if ok and type(res) == 'table' then units = res; fui = '4num' end\n"
        "end\n"
        "if not units then\n"
        "  units = S.World.units(w)\n"
        "  fui = 'World.units fallback'\n"
        "end\n"
        "local count = #units\n"
        "local alive_cnt = 0\n"
        "local hasnode_cnt = 0\n"
        "local pos_ok_cnt = 0\n"
        "local hits = {}\n"
        "for i = 1, math.min(count, 20) do\n"
        "  local u = units[i]\n"
        "  if u and type(u) == 'userdata' then\n"
        "    local ok_a, a = pcall(S.Unit.alive, u)\n"
        "    if ok_a and a then\n"
        "      alive_cnt = alive_cnt + 1\n"
        "      local ok_hn, hn = pcall(S.Unit.has_node, u, 0)\n"
        "      if ok_hn and hn then\n"
        "        hasnode_cnt = hasnode_cnt + 1\n"
        "        local ok_lp, pos = pcall(S.Unit.local_position, u, 0)\n"
        "        if ok_lp and pos and pos.x then\n"
        "          pos_ok_cnt = pos_ok_cnt + 1\n"
        "          local rn = '?'\n"
        "          local ok_rn, vrn = pcall(S.Unit.resource_name, u)\n"
        "          if ok_rn and vrn then rn = tostring(vrn) end\n"
        "          table.insert(hits, string.format('[%d] rn=%s pos=(%.1f,%.1f,%.1f)',\n"
        "            i, rn, pos.x, pos.y, pos.z))\n"
        "        end\n"
        "      end\n"
        "    end\n"
        "  end\n"
        "end\n"
        "return string.format('fui=%s cnt=%d alive=%d hn=%d pos=%d %s',\n"
        "  fui, count, alive_cnt, hasnode_cnt, pos_ok_cnt, table.concat(hits, ' '))\n"
    );

    // === Phase 4: Camera info ===
    exec_lua(
        "local S = stingray "
        "local w = S.Application.main_world() "
        "local pose = S.World.debug_camera_pose(w) "
        "local M = S.Matrix4x4 "
        "local pos = M.translation(pose) "
        "local fwd = M.forward(pose) "
        "return string.format('cam pos=(%.2f,%.2f,%.2f) fwd=(%.3f,%.3f,%.3f) units=%d', "
        "pos.x, pos.y, pos.z, fwd.x, fwd.y, fwd.z, S.World.num_units(w))"
    );

    log_msg("%s", "[RAYCAST] [DUMP] === Dump complete ===\n");
}

// ============================================================
// Float scanner: find position-like float triples in raw memory
// ============================================================
static void scan_floats(const char *label, void *ptr, int size,
                        float ref_x, float ref_y, float ref_z) {
    float *f = (float *)ptr;
    int count = size / 4;
    int printed = 0;

    for (int i = 0; i < count - 2; i++) {
        float a = f[i], b = f[i+1], c = f[i+2];
        // Skip all-zero
        if (a == 0.0f && b == 0.0f && c == 0.0f) continue;
        // Reasonable coordinate range
        if (a < -10000.0f || a > 10000.0f) continue;
        if (b < -10000.0f || b > 10000.0f) continue;
        if (c < -10000.0f || c > 10000.0f) continue;
        // Skip if looks like integers (0, 1, 2, -1 etc with no fractional part)
        if ((a == 1.0f || a == 0.0f || a == -1.0f || a == 2.0f) &&
            (b == 1.0f || b == 0.0f || b == -1.0f || b == 2.0f) &&
            (c == 1.0f || c == 0.0f || c == -1.0f || c == 2.0f)) continue;

        // Check distance to camera
        float dx = a - ref_x, dy = b - ref_y, dz = c - ref_z;
        float dist_sq = dx*dx + dy*dy + dz*dz;
        const char *dist_tag = "";
        if (dist_sq < 10000.0f) dist_tag = " [NEAR CAM]";
        else if (dist_sq < 1000000.0f) dist_tag = " [MID]";

        log_msg("[RAYCAST] [DUMP] %s +0x%03x: (%.2f, %.2f, %.2f)%s\n",
            label, i * 4, a, b, c, dist_tag);
        if (dist_sq >= 10000.0f) printed++;
        if (printed >= 10) break;
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
    /* v4: component explorer. Written by the C hook every ~2s (or on demand
     * via comp_refresh); consumed by the addon ImGui menu. Layout facts
     * (offline RE of the runtime dump, game.dll image):
     *   inst_mgr = *(u64*)(base + 0x276d430)   (component instance manager)
     *     +0x6c = instance count, +0x110 = object ptr array (8B/entry)
     *     component object: +0x08 = type id, +0x0c = unit id, +0x14 bit0 = valid
     *   type_mgr = *(u64*)(base + 0x276d488)   (component type manager)
     *     +0x0c/+0x10 = type count, +0x48 = type object array (0x40/entry)
     *     type object: +0x00 = type id; a qword field pointing into the
     *     .rdata string region (base+0x1f90000..base+0x1fb0000) is the
     *     type-name string (auto-discovered at runtime). */
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
    /* v4b: live engine component-log ring (captured via OutputDebugStringW
     * hook; engine logs look like "[Seater] set_entering ..." etc.) */
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

/* ============================================================
 * Component explorer (v5). Reads the REAL component instance pool.
 * Live RE (2026-08-28, in-mission PID 32200) - 127 managers scanned:
 *   slot game.dll+0x276cad0 -> manager (hash-map object):
 *     +0x10 = component count (was +0x08 in v4 guess)
 *     +0x20 = id map (comp id -> index, cap 0x800, stride 2)
 *     +0x38 = component object pointer array (8B/entry)
 *   component object (0x18 bytes each):
 *     +0x00 = 8B hash/id pair
 *     +0x08 = component instance id (== id map key, 0x144..)
 *     +0x0c = type field (e.g. 0x00400223)
 *     +0x14 = valid flag (1)
 * ============================================================ */
#define RC_RVA_INST_MGR 0x276cad0u  /* POINTER to the component instance pool */
#define RC_STR_LO 0x1f90000u        /* .rdata component string region */
#define RC_STR_HI 0x1fb0000u

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

/* ============================================================
 * OutputDebugStringW hook - capture the engine's "[Seater] ..." logs.
 * The engine prints set_entering/goto_node/set_role through this API
 * (DebugView shows them). Hooking it gives:
 *   - the LIVE parameter stream (seater/seat_collection/interactable/instant)
 *     -> ring buffer for the addon menu
 *   - the RETURN ADDRESS of the logging code -> points into the REAL Seater
 *     implementation, so we can locate set_entering's true entry.
 * ============================================================ */
typedef void (WINAPI *fn_odsw)(LPCWSTR);
static fn_odsw g_orig_odsw = NULL;
static uint8_t g_odsw_orig[16];
static int g_odsw_hooked = 0;

static void WINAPI hk_odsw(LPCWSTR str)
{
    uintptr_t ra = 0;
    /* Engine component logs look like "[Seater] set_entering ...", i.e.
     * start with '[' and contain "] ". CRITICAL: exclude our OWN prefixes
     * ([ENGINE-LOG], [RAYCAST]) - calling log_msg() from this hook would
     * re-enter OutputDebugStringW and recurse infinitely (stack overflow ->
     * crash). We write to the log FILE directly instead, which does not
     * touch OutputDebugStringW at all. */
    if (str && str[0] == L'[' && wcsstr(str, L"] ")
        && !wcsstr(str, L"[ENGINE-LOG]") && !wcsstr(str, L"[RAYCAST]")) {
        char buf[1024];
        WideCharToMultiByte(CP_UTF8, 0, str, -1, buf, sizeof(buf), NULL, NULL);
        ra = (uintptr_t)_ReturnAddress();
        /* write to file directly (no OutputDebugStringW -> no recursion) */
        EnterCriticalSection(&g_log_cs);
        if (g_log_file) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            fprintf(g_log_file, "[%02d:%02d:%02d.%03d] [ENGINE-LOG] ra=0x%llx %s\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                (unsigned long long)ra, buf);
            fflush(g_log_file);
        }
        LeaveCriticalSection(&g_log_cs);
        if (g_shm) {
            static uint32_t ev_idx = 0;
            struct rc_shm_data *s = g_shm;
            uint32_t slot = ev_idx % 6;
            s->comp_evt[slot][0] = 0;
            snprintf(s->comp_evt[slot], sizeof(s->comp_evt[slot]), "ra=%llx %s",
                (unsigned long long)ra, buf);
            ev_idx++;
            s->comp_evt_count = ev_idx;
        }
    }
    if (g_orig_odsw) g_orig_odsw(str);
}

/* ============================================================
 * Component type-name hook (v5c).
 * Target: game.dll+0xd411b0 = 0x7ffb4af011b0 (component pool realloc
 * report). Every component type registers its pool capacity through
 * this function; the signature is:
 *     void __fastcall (void *obj, const char *name, int new_cap)
 * where rdx = the REAL component type name (e.g. "SeaterComponent",
 * "HealthComponent", ...). We capture it into a name table that the
 * component explorer publishes to the addon menu.
 *
 * PATCH: uses a 15-byte ABSOLUTE jump (mov rax,imm64; jmp rax + NOPs)
 * because an E9 rel32 hook is limited to +-2GB - game.dll and this
 * hook DLL commonly load >2GB apart and the rel32 overflows, jumping
 * into garbage (crash in ntdll, 0xc0000026). The covered window is
 * exactly 15 bytes = mov[rsp+8],rbx(5) + mov[rsp+0x10],rsi(5) +
 * push rdi(1) + sub rsp,0x40(4) - no RIP-relative instruction inside.
 * ============================================================ */
#define RC_RVA_TYPE_NAME_HK 0xd411b0u
#define RC_TN_PATCH_LEN 15
typedef void (__fastcall *fn_type_name)(void *obj, const char *name, int new_cap);
static fn_type_name g_orig_type_name = NULL;
static uint8_t g_tn_orig[16];
static int g_tn_hooked = 0;

#define RC_TN_MAX 128
static uint32_t g_tn_count = 0;
static struct { uint32_t type_id; char name[48]; } g_tn_table[RC_TN_MAX];

static void __fastcall hk_type_name(void *obj, const char *name, int new_cap)
{
    char tmp[48];
    int have = 0;
    /* obj unused; capture name (rdx). SEH-guard every read: a malformed
     * rdx must never take the game down. */
    __try {
        if (name && g_tn_count < RC_TN_MAX) {
            int i = 0;
            while (i < 47 && name[i]) { tmp[i] = name[i]; i++; }
            tmp[i] = 0;
            if (i > 0) have = 1;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        have = 0;
    }
    if (have) {
        uint32_t i;
        for (i = 0; i < g_tn_count; i++)
            if (strcmp(g_tn_table[i].name, tmp) == 0) break;
        if (i == g_tn_count) {
            memcpy(g_tn_table[g_tn_count].name, tmp, 48);
            g_tn_table[g_tn_count].type_id = g_tn_count;
            g_tn_count++;
            log_msg("[RAYCAST] comp type name[%u]: %s (cap=%d)\n",
                g_tn_count - 1, tmp, new_cap);
        }
    }
    if (g_orig_type_name) g_orig_type_name(obj, name, new_cap);
}

static void install_type_name_hook(void)
{
    if (g_tn_hooked) return;
    HMODULE gdll = GetModuleHandleA("game.dll");
    if (!gdll) return;
    uint8_t *target = (uint8_t *)(uintptr_t)((uintptr_t)gdll + RC_RVA_TYPE_NAME_HK);
    /* Verify the covered 15 bytes are exactly the expected prologue:
     * mov [rsp+8],rbx | mov [rsp+0x10],rsi | push rdi | sub rsp,0x40 */
    static const uint8_t expect[15] = {
        0x48,0x89,0x5C,0x24,0x08, 0x48,0x89,0x74,0x24,0x10,
        0x57, 0x48,0x83,0xEC,0x40
    };
    if (memcmp(target, expect, 15) != 0) {
        log_msg("[RAYCAST] type-name hook: unexpected prologue\n");
        return;
    }
    uint8_t *tramp = (uint8_t *)VirtualAlloc(NULL, 48, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return;
    /* trampoline: original 15 bytes + mov rax,<target+15> + jmp rax */
    memcpy(g_tn_orig, target, 15);
    memcpy(tramp, g_tn_orig, 15);
    tramp[15] = 0x48; tramp[16] = 0xB8;                    /* mov rax, imm64 */
    *(uint64_t *)(tramp + 17) = (uint64_t)(target + 15);
    tramp[25] = 0xFF; tramp[26] = 0xE0;                    /* jmp rax */
    DWORD old;
    VirtualProtect(target, RC_TN_PATCH_LEN, PAGE_EXECUTE_READWRITE, &old);
    /* absolute jump: mov rax,imm64(10) + jmp rax(2) + 3x nop = 15 bytes */
    target[0] = 0x48; target[1] = 0xB8;
    *(uint64_t *)(target + 2) = (uint64_t)(uintptr_t)hk_type_name;
    target[10] = 0xFF; target[11] = 0xE0;
    target[12] = 0x90; target[13] = 0x90; target[14] = 0x90;
    VirtualProtect(target, RC_TN_PATCH_LEN, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, RC_TN_PATCH_LEN);
    g_orig_type_name = (fn_type_name)tramp;
    g_tn_hooked = 1;
    log_msg("[RAYCAST] type-name hook installed (abs jump, target=%p tramp=%p)\n", target, tramp);
}

static void install_odsw_hook(void)
{
    if (g_odsw_hooked) return;
    HMODULE k = GetModuleHandleA("kernel32.dll");
    uint8_t *target = (uint8_t *)GetProcAddress(k, "OutputDebugStringW");
    if (!target) return;
    /* A 5-byte E9 patch must cover whole instructions; also reject relative
     * branch/lea immediates inside the covered window (they'd break in the
     * trampoline). */
    int off = 0;
    while (off < 5) {
        int l = x64_instr_len(target + off);
        if (l <= 0 || off + l > 7) return; /* too long or unaligned -> abort */
        uint8_t op = target[off];
        if (op == 0xE8 || op == 0xE9 || op == 0xEB || (op == 0x0F && (target[off+1] & 0x80))) return;
        if ((op & 0xF0) == 0x70) return; /* Jcc short */
        if (op == 0xFF && (target[off+1] & 0x38) == 0x20) return; /* jmp r/m */
        off += l;
    }
    uint8_t *tramp = (uint8_t *)VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return;
    memcpy(g_odsw_orig, target, 5);
    memcpy(tramp, g_odsw_orig, 5);
    tramp[5] = 0x48; tramp[6] = 0xB8;                    /* mov rax, imm64 */
    *(uint64_t *)(tramp + 7) = (uint64_t)(target + 5);
    tramp[15] = 0xFF; tramp[16] = 0xE0;                  /* jmp rax */
    DWORD old;
    VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old);
    int32_t rel = (int32_t)((intptr_t)hk_odsw - (intptr_t)(target + 5));
    target[0] = 0xE9;
    memcpy(target + 1, &rel, 4);
    VirtualProtect(target, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, 5);
    g_orig_odsw = (fn_odsw)tramp;
    g_odsw_hooked = 1;
    log_msg("[RAYCAST] OutputDebugStringW hook installed (tramp=%p)\n", tramp);
}

/* build version banner - printed once at load so we can ALWAYS tell which
 * DLL the injector actually loaded */
#define RC_BUILD_VER "v10.54"
static void rc_print_version_banner(void) {
    static volatile LONG done = 0;
    if (InterlockedExchange(&done, 1) == 0) {
        log_msg("[RAYCAST] hd2_raycast_hook %s built %s %s loaded (base=%p)\n",
            RC_BUILD_VER, __DATE__, __TIME__, (void *)GetModuleHandleA("game.dll"));
    }
}

static void comp_explorer_tick(void) {
    rc_print_version_banner();
    if (!g_shm) shm_init();
    if (!g_shm) return;
    struct rc_shm_data *s = g_shm;

    HMODULE gdll = GetModuleHandleA("game.dll");
    if (!gdll) return;
    uint64_t base = (uint64_t)(uintptr_t)gdll;

    /* ---- command area: execute pending writes first ----
     * cmd_seq is bumped by the addon; the hook processes exactly the
     * commands whose cmd_seq differs from cmd_done. */
    {
        uint32_t seq = s->cmd_seq;
        if (seq != s->cmd_done && s->cmd_type != 0) {
            uint32_t t = s->cmd_type;
            uint64_t a = s->cmd_addr;
            if (t == 1 || t == 2) {
                __try {
                    if (t == 1) *(volatile uint32_t *)a = s->cmd_val32;
                    else        *(volatile float   *)a = s->cmd_valf;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    log_msg("[RAYCAST] comp cmd write @0x%llx FAILED (SEH)\n",
                        (unsigned long long)a);
                }
                log_msg("[RAYCAST] comp cmd write u%u @0x%llx = %u / %f\n",
                    t, (unsigned long long)a, s->cmd_val32, s->cmd_valf);
            }
            s->cmd_done = seq;
            s->cmd_type = 0;
        }
    }

    /* ---- refresh throttle: ~2s, or immediately when asked ---- */
    static DWORD last_refresh = 0;
    DWORD now = GetTickCount();
    int forced = (s->comp_refresh != 0);
    if (!forced && (now - last_refresh) < 2000) return;
    last_refresh = now;
    s->comp_refresh = 0;

    uint32_t icount = 0;
    uint64_t cont = 0;
    uint64_t objs = 0;
    /* v5: 0x276cad0 points to the component instance pool manager;
     * +0x10 = component count, +0x38 = component object pointer array */
    rc_safe_read64(base + RC_RVA_INST_MGR, &cont);
    if (cont) {
        rc_safe_read32(cont + 0x10, &icount);
        rc_safe_read64(cont + 0x38, &objs);
    }
    if (!cont || !icount || icount > 0x20000 || !objs) {
        s->comp_unit_count = 0;
        s->comp_item_count = 0;
        s->comp_type_count = 0;
        s->comp_seq++;
        /* Diagnostic: container pointer is 0 until a mission world exists. */
        static DWORD last_mgr_log = 0;
        if ((now - last_mgr_log) > 10000) {
            last_mgr_log = now;
            log_msg("[RAYCAST] comp explorer: cont_ptr=0x%llx count=%u objs=0x%llx (empty - not in mission?)\n",
                (unsigned long long)cont, icount, (unsigned long long)objs);
        }
        return;
    }

    /* ---- type name cache ----
     * Real component-type names are captured at runtime by the type-name
     * hook (game.dll+0xd411b0, rdx = name on pool realloc). They land in
     * g_tn_table[] keyed by discovery order; component objects carry a
     * type field at +0x0c that we try to match by substring (e.g. the
     * type id 0x00400223 encodes a unit/type pair - see seater analysis).
     * Fallback: "Comp_<id>" (component instance id). */
    struct { uint32_t id; char name[48]; } tcache[256];
    int tcache_n = 0;
    for (uint32_t i = 0; i < g_tn_count && i < 256; i++) {
        tcache[tcache_n].id = g_tn_table[i].type_id;
        memcpy(tcache[tcache_n].name, g_tn_table[i].name, 48);
        tcache_n++;
    }

    /* ---- walk the object pointer array ----
     * component object (0x18B): +0x08 = comp id (== id map key, e.g. 0x144),
     * +0x0c = type field (e.g. 0x00400223), +0x14 = valid flag. */
    static struct rc_comp_item items[RC_COMP_MAX_ITEMS];
    static uint32_t units[RC_COMP_MAX_UNITS];
    static float unit_pos[RC_COMP_MAX_UNITS][3];
    uint32_t item_n = 0;
    int unit_n = 0;
    uint32_t diag_n = 0;
    for (uint32_t i = 0; i < icount && item_n < RC_COMP_MAX_ITEMS; i++) {
        uint64_t o = 0;
        if (!rc_safe_read64(objs + (uint64_t)i * 8, &o) || !o) continue;
        uint8_t v8 = 0;
        rc_safe_read8(o + 0x14, &v8);
        uint32_t cid = 0, typ = 0;
        rc_safe_read32(o + 8, &cid);
        rc_safe_read32(o + 0x0c, &typ);
        /* Diag: first entries with raw object fields - PRINT ONCE only
         * (the every-2s dump floods the log and drowns SEATER8 lines).
         * FIX: set done on the FIRST tick regardless of component count
         * (on the ship there are <20 components, so diag_n never hit 20). */
        static int diag_done = 0;
        if (!diag_done) {
            if (diag_n < 20) {
                uint64_t vt = 0;
                rc_safe_read64(o, &vt);
                log_msg("[RAYCAST] comp[%u] obj=%llx vt=%llx +8=%u +0xc=%u +0x14=%u\n",
                    diag_n, (unsigned long long)o, (unsigned long long)vt, cid, typ, v8);
            }
            diag_n++;
            diag_done = 1;
        }
        if (!(v8 & 1)) continue;
        if (!cid) continue;
        /* group by component id (0x144..) as the menu's "unit" handle */
        uint32_t uid = cid;
        int ui = -1;
        for (int j = 0; j < unit_n; j++)
            if (units[j] == uid) { ui = j; break; }
        if (ui < 0) {
            if (unit_n >= RC_COMP_MAX_UNITS) continue;
            units[unit_n] = uid;
            /* world pos via unit system: *(u64*)(base+0x276ca20+0x18)=obj,
             * obj+0x88 = fn ptr, call (uid, 0) -> float[3] */
            unit_pos[unit_n][0] = 0.0f;
            unit_pos[unit_n][1] = 0.0f;
            unit_pos[unit_n][2] = 0.0f;
            {
                uint64_t uobj = 0, fn = 0;
                if (rc_safe_read64(base + 0x276ca20 + 0x18, &uobj) && uobj &&
                    rc_safe_read64(uobj + 0x88, &fn) && fn) {
                    __try {
                        float *p = (float *)((float *(*)(uint32_t, int))(uintptr_t)fn)(uid, 0);
                        if (p) {
                            unit_pos[unit_n][0] = p[0];
                            unit_pos[unit_n][1] = p[1];
                            unit_pos[unit_n][2] = p[2];
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                    }
                }
            }
            ui = unit_n;
            unit_n++;
        }
        /* per-unit component cap */
        int per = 0;
        for (uint32_t k = 0; k < item_n; k++)
            if (items[k].unit == uid) per++;
        if (per >= RC_COMP_MAX_PER_UNIT) continue;
        struct rc_comp_item *it = &items[item_n++];
        it->unit = uid;
        it->type_id = typ;
        it->valid = v8 & 1;
        it->flags = 0;
        it->obj = o;
        it->type_name[0] = 0;
        for (int j = 0; j < tcache_n; j++)
            if (tcache[j].id == typ) { memcpy(it->type_name, tcache[j].name, 48); break; }
        if (!it->type_name[0])
            snprintf(it->type_name, sizeof(it->type_name), "Comp_%u", cid);
    }
    /* sort units ascending (keep pos in sync) */
    for (int i = 1; i < unit_n; i++) {
        uint32_t k = units[i];
        float kp[3] = { unit_pos[i][0], unit_pos[i][1], unit_pos[i][2] };
        int j = i - 1;
        while (j >= 0 && units[j] > k) {
            units[j + 1] = units[j];
            unit_pos[j + 1][0] = unit_pos[j][0];
            unit_pos[j + 1][1] = unit_pos[j][1];
            unit_pos[j + 1][2] = unit_pos[j][2];
            j--;
        }
        units[j + 1] = k;
        unit_pos[j + 1][0] = kp[0];
        unit_pos[j + 1][1] = kp[1];
        unit_pos[j + 1][2] = kp[2];
    }

    /* ---- commit to shared memory ---- */
    s->seq++;
    uint32_t tn = (uint32_t)tcache_n < RC_COMP_MAX_TYPES ? (uint32_t)tcache_n : RC_COMP_MAX_TYPES;
    s->comp_type_count = tn;
    for (uint32_t i = 0; i < tn; i++) {
        s->comp_types[i].type_id = tcache[i].id;
        memcpy(s->comp_types[i].name, tcache[i].name, 48);
    }
    s->comp_unit_count = (uint32_t)unit_n;
    for (int i = 0; i < unit_n; i++) {
        s->comp_units[i] = units[i];
        s->comp_unit_pos[i][0] = unit_pos[i][0];
        s->comp_unit_pos[i][1] = unit_pos[i][1];
        s->comp_unit_pos[i][2] = unit_pos[i][2];
    }
    s->comp_item_count = item_n;
    if (item_n) memcpy(s->comp_items, items, item_n * sizeof(struct rc_comp_item));
    s->comp_seq++;
    s->seq++;
    /* summary line throttled to every 30s (was every 2s - log flood) */
    static DWORD comp_last_sum = 0;
    DWORD comp_now = GetTickCount();
    if (comp_now - comp_last_sum > 30000) {
        comp_last_sum = comp_now;
        log_msg("[RAYCAST] comp explorer: units=%d items=%u types=%u\n",
            unit_n, item_n, tn);
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
            mesh_pending_add(s->hit_hash64);
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
                /* project every vertex once */
                float spx[MESH_VERTS_MAX], spy[MESH_VERTS_MAX];
                unsigned char spv[MESH_VERTS_MAX];
                for (uint32_t vi = 0; vi < mt->nverts; vi++) {
                    spv[vi] = 0;
                    /* local -> world: world = pos + R * local.
                     * rc_mesh_rot = {right.xyz, up.xyz, fwd.xyz} as COLUMNS.
                     * IMPORTANT: the mesh tables store vertices in the SDK /
                     * Blender Z-up frame (raw VertexPositions are Z-up: a
                     * standing character's height runs along local Z, verified
                     * against unit 5556372446766824087). The engine's
                     * world_pose is Y-up (Unit.box maps Y -> world up), so the
                     * mesh projection must map local Z -> world UP:
                     *   X -> right, Y -> forward, Z -> up. */
                    float lx = mt->verts[vi][0], ly = mt->verts[vi][1], lz = mt->verts[vi][2];
                    float wx = pos[0] + rot[0]*lx + rot[6]*ly + rot[3]*lz;
                    float wy = pos[1] + rot[1]*lx + rot[7]*ly + rot[4]*lz;
                    float wz = pos[2] + rot[2]*lx + rot[8]*ly + rot[5]*lz;
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
                if (0) {
                static DWORD mesh_out_t0 = 0;
                DWORD motick = GetTickCount();
                if (motick - mesh_out_t0 > 2000) {
                    mesh_out_t0 = motick;
                    log_msg("[RAYCAST] meshdiag: %u edges drawn from %u verts/%u edges (hash=%llu)\n",
                        out / 2, mt->nverts, mt->nedges, (unsigned long long)s->hit_hash64);
                }
                }
            }
        }
    }
    s->seq++;
}

// Ray-sphere intersection: returns 1 if hit, 0 if miss
static int ray_sphere(float cx, float cy, float cz,
                      float dx, float dy, float dz,
                      float px, float py, float pz,
                      float r) {
    float lx = px - cx, ly = py - cy, lz = pz - cz;
    float tca = lx * dx + ly * dy + lz * dz;
    if (tca < 0) return 0;
    float d2 = lx * lx + ly * ly + lz * lz - tca * tca;
    if (d2 > r * r) return 0;
    return 1;
}

static void dump_unit_at(int idx) {
    if (!f_lua_touserdata || !g_L || !f_luaL_loadstring || !o_lua_pcall || !f_lua_newthread) return;
    if (g_segfault_flag) return;

    int top = f_lua_gettop(g_L);
    lua_State *T = f_lua_newthread(g_L);
    if (!T) { f_lua_settop(g_L, top); return; }

    char code[512];
    snprintf(code, sizeof(code),
        "local S = stingray "
        "local w = S.Application.main_world() "
        "local ok, ents = pcall(S.World.entities, w) "
        "if not ok or type(ents) ~= 'table' then return nil end "
        "local u = ents[%d] "
        "if not u then return nil end "
        "local ok_rn, rn = pcall(S.Unit.resource_name, u) "
        "return u, ok_rn and tostring(rn) or '?'",
        idx);

    if (f_luaL_loadstring(T, code) != 0) {
        const char *err = f_lua_tolstring(T, -1, NULL);
        log_msg("[RAYCAST] [DUMP] Unit %d load err: %s\n", idx, err ? err : "?");
        f_lua_settop(g_L, top);
        return;
    }

    __try {
        o_lua_pcall(T, 0, 2, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_msg("[RAYCAST] [DUMP] Unit %d SEH 0x%08X\n", idx, GetExceptionCode());
        InterlockedExchange(&g_segfault_flag, 1);
        InterlockedExchange((volatile LONG *)&g_segfault_tick, GetTickCount());
        f_lua_settop(g_L, top);
        return;
    }

    const char *rn_str = f_lua_tolstring(T, 2, NULL);
    void *unit_ud = f_lua_touserdata(T, 1);

    log_msg("[RAYCAST] [DUMP] --- Unit %d: rn=%s ---\n", idx, rn_str ? rn_str : "?");

    if (unit_ud && is_readable(unit_ud, 32)) {
        dump_mem("Unit userdata", unit_ud, 32);
        void *unit_cpp = *(void **)unit_ud;
        if (unit_cpp && is_readable(unit_cpp, 256)) {
            char ulabel[64];
            snprintf(ulabel, sizeof(ulabel), "Unit %d C++", idx);
            dump_mem(ulabel, unit_cpp, 256);

            // Scan for position-like floats
            scan_floats(ulabel, unit_cpp, 256, g_cam_x, g_cam_y, g_cam_z);

            // Follow first 8 pointers (8-byte aligned) and dump 128 bytes each
            for (int i = 0; i < 8; i++) {
                void *ptr = *(void **)((uint8_t *)unit_cpp + i * 8);
                if (ptr && is_readable(ptr, 128)) {
                    char label[80];
                    snprintf(label, sizeof(label), "Unit%d+0x%03x -> %p", idx, i * 8, ptr);
                    dump_mem(label, ptr, 128);
                    scan_floats(label, ptr, 128, g_cam_x, g_cam_y, g_cam_z);
                }
            }
        }
    } else {
        log_msg("[RAYCAST] [DUMP] Unit %d: userdata unreadable or nil\n", idx);
    }

    f_lua_settop(g_L, top);
}

// ============================================================
// Game.dll string scanner (F9) - find raycast/physics string refs
// ============================================================
static void scan_game_dll_strings(void) {
    log_msg("%s", "[RAYCAST] === F9: Scanning game.dll for vehicle/seat/boarding strings ===\n");
    
    HMODULE game_dll = GetModuleHandleA("game.dll");
    if (!game_dll) {
        log_msg("%s", "[RAYCAST] game.dll not found\n");
        return;
    }
    
    uint8_t *base = (uint8_t *)game_dll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    
    // Boarding / vehicle / seat logic strings. game.dll is packed on disk
    // (.winlice/.vm_sec), but at runtime the unpacked image is in memory -
    // this scan runs against the live module so the strings are readable.
    const char *keywords[] = {
        "enter_vehicle", "enter_seat", "exit_vehicle", "exit_seat",
        "vehicle", "seat", "boarding", "board", "mount", "gunner",
        "passenger", "driver", "occup", "ride", "frv", "drive",
        "interact", "anim_enter", "anim_exit", "seat_"
    };
    int num_keywords = sizeof(keywords) / sizeof(keywords[0]);
    int total_found = 0;
    
    for (WORD si = 0; si < nt->FileHeader.NumberOfSections; si++) {
        char sec_name[9] = {0};
        memcpy(sec_name, sec[si].Name, 8);
        
        // Only scan readable sections (both code and data)
        DWORD prot = sec[si].Characteristics;
        if (!(prot & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA)))
            continue;
        
        uint8_t *sec_start = base + sec[si].VirtualAddress;
        SIZE_T sec_size = sec[si].Misc.VirtualSize;
        
        if (!is_readable(sec_start, 64)) continue;
        
        for (int k = 0; k < num_keywords; k++) {
            const char *kw = keywords[k];
            int kw_len = (int)strlen(kw);
            
            for (SIZE_T off = 0; off + kw_len < sec_size; off++) {
                if (_memicmp(sec_start + off, kw, kw_len) != 0)
                    continue;
                
                // Read context (null-terminated string around the match)
                char context[256] = {0};
                int ctx_start = (off >= 64) ? (int)(off - 64) : 0;
                int ctx_end = (int)(off + 128);
                if (ctx_end > (int)sec_size) ctx_end = (int)sec_size;
                
                // Find string start (walk back to non-printable or string start)
                int str_start = (int)off;
                while (str_start > ctx_start) {
                    uint8_t prev = sec_start[str_start - 1];
                    if (prev < 32 || prev > 126) break;
                    str_start--;
                }
                // Find string end
                int str_end = (int)off;
                while (str_end < ctx_end && sec_start[str_end] >= 32 && sec_start[str_end] <= 126)
                    str_end++;
                
                int slen = str_end - str_start;
                if (slen > 0 && slen < 200) {
                    memcpy(context, sec_start + str_start, slen);
                    context[slen] = 0;
                    
                    SIZE_T rva = (SIZE_T)(sec_start + str_start - base);
                    log_msg("[RAYCAST] STR '%s' at game.dll+0x%zx (sec=%s): \"%s\"\n",
                        kw, rva, sec_name, context);
                    total_found++;
                    if (total_found >= 500) goto xref_scan;
                }
            }
        }
    }
    
xref_scan:
    log_msg("[RAYCAST] String scan complete: %d matches\n", total_found);
    
    // ---- lea rip-relative xref scan: find code that references any of the
    // found strings. Patterns: 48 8D / 4C 8D / 48 8B / 4C 8B + ModRM
    // (mod=00, reg=any, rm=101) + disp32 -> target = insn_end + disp.
    log_msg("%s", "[RAYCAST] Scanning code for lea rip xrefs to found strings...\n");
    int xrefs = 0;
    for (WORD si = 0; si < nt->FileHeader.NumberOfSections && xrefs < 300; si++) {
        DWORD prot = sec[si].Characteristics;
        if (!(prot & IMAGE_SCN_CNT_CODE)) continue;
        if (!(prot & IMAGE_SCN_MEM_READ)) continue;
        
        uint8_t *cs = base + sec[si].VirtualAddress;
        SIZE_T cs_size = sec[si].Misc.VirtualSize;
        if (!is_readable(cs, 64)) continue;
        
        for (SIZE_T i = 0; i + 7 < cs_size; i++) {
            // LEA r64, [rip+disp32]: 48 8D | 4C 8D, ModRM rm=101 (0x05/0x0D/0x15/0x1D/0x25/0x2D/0x35/0x3D), disp32
            if (cs[i] != 0x48 && cs[i] != 0x4C) continue;
            if (cs[i+1] != 0x8D) continue;
            uint8_t modrm = cs[i+2];
            if ((modrm & 0xC7) != 0x05) continue; // mod=00, rm=101
            int32_t disp;
            memcpy(&disp, cs + i + 3, 4);
            SIZE_T insn_end = i + 7;
            SIZE_T target_rva = (SIZE_T)(cs + insn_end - base) + (SIZE_T)disp;
            // sanity: target inside module
            if (target_rva > nt->OptionalHeader.SizeOfImage) continue;
            // does target point at printable text?
            if (!is_readable(base + target_rva, 8)) continue;
            int printable = 1;
            for (int c = 0; c < 8; c++) {
                uint8_t b = *(base + target_rva + c);
                if (b != 0 && (b < 32 || b > 126)) { printable = 0; break; }
            }
            if (!printable) continue;
            // does the string there contain any keyword?
            char buf[192]; memcpy(buf, base + target_rva, 191); buf[191] = 0;
            int hit = 0;
            for (int k = 0; k < num_keywords; k++) {
                if (_memicmp(buf, keywords[k], (int)strlen(keywords[k])) == 0 ||
                    strstr(buf, keywords[k]) != NULL) { hit = 1; break; }
            }
            if (!hit) continue;
            // walk back to find the function prologue start (8B EC / CC padding)
            SIZE_T fn_start = insn_end;
            SIZE_T lo = (i >= 0x400) ? (i - 0x400) : 0;
            for (SIZE_T j = i; j > lo; j--) {
                uint8_t b0 = cs[j-1];
                uint8_t b1 = cs[j];
                if ((b0 == 0xCC && b1 == 0xCC) || b1 == 0x55) { fn_start = j; break; }
            }
            log_msg("[RAYCAST] XREF lea@game.dll+0x%zx fn~+0x%zx -> str@+0x%zx \"%.96s\"\n",
                (size_t)(cs + insn_end - base), (size_t)(cs + fn_start - base),
                (size_t)target_rva, buf);
            xrefs++;
        }
    }
    log_msg("[RAYCAST] Xref scan complete: %d xrefs\n", xrefs);
}

// Dump the unpacked game.dll image from memory (the on-disk file is packed
// with WinLicense/VMProtect; only the runtime image has readable strings and
// code). Writes D:\hd2_meshtables\game_mem_dump.bin for offline analysis.
static void dump_game_module(void) {
    log_msg("%s", "[RAYCAST] === Numpad7: dumping unpacked game.dll image ===\n");
    HMODULE game_dll = GetModuleHandleA("game.dll");
    if (!game_dll) { log_msg("%s", "[RAYCAST] game.dll not found\n"); return; }
    uint8_t *base = (uint8_t *)game_dll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { log_msg("%s", "[RAYCAST] bad dos header\n"); return; }
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { log_msg("%s", "[RAYCAST] bad nt header\n"); return; }
    SIZE_T size = nt->OptionalHeader.SizeOfImage;
    if (size < 0x1000 || size > 0x20000000) { log_msg("[RAYCAST] bad size 0x%zx\n", size); return; }

    const char *path = "D:\\hd2_meshtables\\game_mem_dump.bin";
    FILE *f = fopen(path, "wb");
    if (!f) { log_msg("[RAYCAST] cannot open %s\n", path); return; }

    // Page-by-page copy so an unreadable page (VMProtect guard) does not
    // abort the whole dump - fill failed pages with 0xCC.
    SIZE_T total = 0, failed = 0;
    uint8_t *page = (uint8_t *)malloc(0x1000);
    if (!page) { fclose(f); log_msg("%s", "[RAYCAST] alloc failed\n"); return; }
    for (SIZE_T off = 0; off < size; off += 0x1000) {
        SIZE_T chunk = (off + 0x1000 <= size) ? 0x1000 : (size - off);
        SIZE_T got = 0;
        if (ReadProcessMemory(GetCurrentProcess(), base + off, page, chunk, &got) && got == chunk) {
            fwrite(page, 1, chunk, f);
        } else {
            memset(page, 0xCC, chunk);
            fwrite(page, 1, chunk, f);
            failed++;
        }
        total += chunk;
    }
    free(page);
    fclose(f);
    log_msg("[RAYCAST] dumped %zu bytes (%zu unreadable pages) -> %s\n", total, failed, path);
}
// ============================================================
// NPC auto-ride (F11): pin the F4-targeted NPC into a FRV passenger seat.
// Lua defines _G.rc_ride_arm / _G.rc_ride_exit / _G.rc_ride_tick; the C side
// toggles arm/exit and ticks the ride every ~120ms from the key loop.
// Seat anchor is FRV-local (z-up), transformed to world via world_pose.
// ============================================================
static void npc_ride_define(void) {
    exec_lua(
        "if _G.rc_ride_def then return 'def' end "
        "_G.rc_ride_def = true "
        "local S = stingray "
        "_G.rc_ride = nil "
        "_G.rc_ride_fails = 0 "
        "local function try_anim(u, names) "
        "  for i = 1, #names do "
        "    local ok, e = pcall(S.Unit.play_simple_animation, u, names[i]) "
        "    if ok and not e then return names[i] end "
        "  end "
        "  return nil "
        "end "
        "_G.rc_ride_tick = function() "
        "  local r = _G.rc_ride "
        "  if not r then return 'off' end "
        "  r.t = (r.t or 0) + 1 "
        "  _G.rc_ride_fails = 0 "
        "  local okp, pose = pcall(S.Unit.world_pose, r.frv) "
        "  if not okp or not pose then "
        "    _G.rc_ride_fails = _G.rc_ride_fails + 1 "
        "    if _G.rc_ride_fails > 60 then _G.rc_ride = nil end "
        "    return 'nopose' "
        "  end "
        "  local okv, v = pcall(S.Matrix4x4.transform, pose, S.Vector3(r.seat[1], r.seat[2], r.seat[3])) "
        "  if okv and v and v.x then "
        "    pcall(S.Unit.teleport_local_position, r.npc, v) "
        "  end "
        "  if r.state == 'entering' and r.t == 3 then "
        "    try_anim(r.npc, {'content/fac_helldivers/vehicles/frv/animation/enter_back_left', "
        "                     'content/fac_helldivers/vehicles/frv/animation/enter_back_right', "
        "                     'content/fac_helldivers/vehicles/frv/animation/enter_front_right'}) "
        "    r.state = 'riding' "
        "  end "
        "  return r.state "
        "end "
        "_G.rc_ride_arm = function() "
        "  local w = S.Application.main_world() "
        "  if not w then return 'no world' end "
        "  local target = _G.rc_hit_unit "
        "  if not target then return 'no target (F4 first)' end "
        "  local units = S.World.units(w) "
        "  if not units then return 'no units' end "
        "  local okp, pose = pcall(S.World.debug_camera_pose, w) "
        "  local cx, cy, cz = 0, 0, 0 "
        "  if okp and pose then local m = S.Matrix4x4.translation(pose) cx, cy, cz = m.x, m.y, m.z end "
        "  local frv = nil "
        "  local nearhex = '' "
        "  for i = 1, #units do "
        "    local u = units[i] "
        "    local okr, rn = pcall(S.Unit.resource_name, u) "
        "    local s = okr and tostring(rn) or '' "
        "    local h = s:match('#ID%[%x+%]') "
        "    local hex = h and h:sub(5, -2) or '' "
        "    if hex == 'cc21c7ffd3ebefb9' or hex == 'e0a48d0be9a7453f' then "
        "      local okw, wp = pcall(S.Unit.world_position, u, 1) "
        "      if okw and wp then "
        "        local d = (wp.x-cx)^2 + (wp.y-cy)^2 + (wp.z-cz)^2 "
        "        if d < 10000 then frv = u break end "
        "      end "
        "    end "
        "    if nearhex == '' and hex ~= '' then nearhex = hex end "
        "  end "
        "  if not frv then return 'no FRV near player (first=' .. nearhex .. ')' end "
        "  _G.rc_ride = { frv = frv, npc = target, seat = {1.18, -1.6, 0.935}, "
        "    state = 'entering', t = 0 } "
        "  return 'ride armed' "
        "end "
        "_G.rc_ride_exit = function() "
        "  local r = _G.rc_ride "
        "  if not r then return 'off' end "
        "  local okp, pose = pcall(S.Unit.world_pose, r.frv) "
        "  if okp and pose then "
        "    local m = S.Matrix4x4.translation(pose) "
        "    pcall(S.Unit.teleport_local_position, r.npc, S.Vector3(m.x + 2.0, m.y, m.z + 0.5)) "
        "  end "
        "  try_anim(r.npc, {'content/fac_helldivers/vehicles/frv/animation/exit_back_left', "
        "                   'content/fac_helldivers/vehicles/frv/animation/exit_back_right', "
        "                   'content/fac_helldivers/vehicles/frv/animation/exit_front_right'}) "
        "  _G.rc_ride = nil "
        "  return 'ride off' "
        "end "
        "return 'ride def'"
    );
}

// F11 press: arm (F4-target -> seat) or exit (current rider).
static int g_ride_active = 0;

// ============================================================
// Auto-gunner (Numpad9 register + automatic): when a FRV spawns (called in),
// spawn a SEAF soldier onto the vehicle machine-gun mount and pin it there
// forever. SEAF template unit is registered by F4-targeting a SEAF first
// (its resource hash is unknown to us - the pack/unit names are hidden).
// Machine gun mount = unit hash 085c1edb038ec24e (M-102 车载重机枪, spawned
// next to the FRV), used as the pin anchor.
// ============================================================
static void npc_gunner_define(void) {
    exec_lua(
        "if _G.rc_gunner_def then return 'def' end "
        "_G.rc_gunner_def = true "
        "local S = stingray "
        "_G.rc_gunner_seen = {} "
        "_G.rc_gunner = nil "
        "_G.rc_gunner_tick = function() "
        "  local w = S.Application.main_world() "
        "  if not w then return end "
        "  local units = S.World.units(w) "
        "  if not units then return end "
        "  local seen = _G.rc_gunner_seen "
        "  for i = 1, #units do "
        "    local u = units[i] "
        "    local okr, rn = pcall(S.Unit.resource_name, u) "
        "    local s = okr and tostring(rn) or '' "
        "    local h = s:match('#ID%[%x+%]') "
        "    local hex = h and h:sub(5, -2) or '' "
        "    if hex == 'cc21c7ffd3ebefb9' or hex == 'e0a48d0be9a7453f' then "
        "      local uid = tostring(u) "
        "      if not seen[uid] then "
        "        seen[uid] = true "
        "        local tpl = _G.rc_seaf_template "
        "        if tpl then "
        "          local mg = nil "
        "          for j = 1, #units do "
        "            local u2 = units[j] "
        "            local okr2, rn2 = pcall(S.Unit.resource_name, u2) "
        "            local s2 = okr2 and tostring(rn2) or '' "
        "            local h2 = s2:match('#ID%[%x+%]') "
        "            if h2 and h2:sub(5, -2) == '085c1edb038ec24e' then mg = u2 break end "
        "          end "
        "          local ok, npc = pcall(S.World.spawn_unit, w, tpl) "
        "          if ok and npc then "
        "            _G.rc_gunner = { frv = u, npc = npc, mg = mg, t = 0 } "
        "            return 'gunner spawned' "
        "          end "
        "        end "
        "      end "
        "    end "
        "  end "
        "  return 'ok' "
        "end "
        "_G.rc_gunner_pin = function() "
        "  local g = _G.rc_gunner "
        "  if not g then return end "
        "  g.t = (g.t or 0) + 1 "
        "  local anchor = g.mg "
        "  if not anchor then "
        "    local okp2, pose2 = pcall(S.Unit.world_pose, g.frv) "
        "    if okp2 and pose2 then "
        "      local okv2, v2 = pcall(S.Matrix4x4.transform, pose2, S.Vector3(-1.0, 1.2, 0.6)) "
        "      if okv2 and v2 and v2.x then pcall(S.Unit.teleport_local_position, g.npc, v2) end "
        "    end "
        "    return "
        "  end "
        "  local okw, wp = pcall(S.Unit.world_position, anchor, 1) "
        "  if okw and wp then "
        "    pcall(S.Unit.teleport_local_position, g.npc, S.Vector3(wp.x, wp.y + 0.6, wp.z)) "
        "  end "
        "  if g.t == 3 then "
        "    for _, an in ipairs({'content/fac_helldivers/vehicles/frv/animation/idle_back_right', "
        "                         'content/fac_helldivers/vehicles/frv/animation/idle_front_right', "
        "                         'content/fac_helldivers/vehicles/frv/animation/idle'}) do "
        "      local ok, e = pcall(S.Unit.play_simple_animation, g.npc, an) "
        "      if ok and not e then break end "
        "    end "
        "  end "
        "end "
        "return 'gunner def'"
    );
}

// Numpad9: register the F4-targeted unit as the SEAF template for auto-gunner.
static void npc_gunner_register(void) {
    npc_gunner_define();
    exec_lua(
        "local S = stingray "
        "local u = _G.rc_hit_unit "
        "if not u then return 'no target (F4 first)' end "
        "local okr, rn = pcall(S.Unit.resource_name, u) "
        "local s = okr and tostring(rn) or '' "
        "local h = s:match('#ID%[%x+%]') "
        "if not h then return 'no hash rn=[' .. s .. ']' end "
        "local hex = h:sub(5, -2) "
        "_G.rc_seaf_template = hex "
        "return 'SEAF template = 0x' .. hex"
    );
    log_msg("[RAYCAST] gunner: %s\n", g_last_result[0] ? g_last_result : "?");
}

static void npc_ride_toggle(void) {
    npc_ride_define();
    // If a ride is active, exit; otherwise arm. Read state first.
    exec_lua("return tostring(_G.rc_ride ~= nil)");
    int active = (g_last_result[0] == 't');
    if (active) {
        exec_lua("return _G.rc_ride_exit()");
        log_msg("[RAYCAST] ride: %s\n", g_last_result[0] ? g_last_result : "?");
        g_ride_active = 0;
    } else {
        exec_lua("return _G.rc_ride_arm()");
        log_msg("[RAYCAST] ride: %s\n", g_last_result[0] ? g_last_result : "?");
        // armed only when rc_ride is now non-nil
        exec_lua("return tostring(_G.rc_ride ~= nil)");
        g_ride_active = (g_last_result[0] == 't');
    }
}

// ============================================================
// Engine Seater hook (Numpad5 install): inline-hook game.dll's
// set_entering (RVA 0x633ec0, decompiled FUN_7ffaae873ec0) to observe the
// REAL board call when a player enters a vehicle: register args (rcx =
// Seater component object, rdx = seat idx, r8/r9) so we can replicate it
// for NPCs. Trampoline preserves the original 12 bytes.
// ============================================================
typedef void (__fastcall *fn_set_entering)(void *seater, unsigned int seat, unsigned int sc, unsigned int ei, unsigned int inst);
static fn_set_entering g_orig_set_entering = NULL;
static uint8_t g_seater_orig[32];
static int g_seater_hooked = 0;

static void __fastcall hk_set_entering(void *seater, unsigned int seat, unsigned int sc,
                                       unsigned int ei, unsigned int inst)
{
    // NOTE: rcx (seater) is a COMPONENT ID / handle (e.g. 426 per engine log),
    // NOT a raw object pointer - dereferencing it crashed (0xC0000005).
    log_msg("[SEATER] set_entering seater=%llu seat=%u sc=%u ei=%u inst=%u\n",
        (unsigned long long)(uintptr_t)seater, seat, sc, ei, inst);
    if (g_orig_set_entering)
        g_orig_set_entering(seater, seat, sc, ei, inst);
}

/* ============================================================
 * Seater set_entering observation v7 (HARDWARE BREAKPOINT, no code patch).
 * game.dll is WinLicense+VMProtect packed with an anti-tamper integrity
 * check: ANY inline patch (E9 or abs-jump, CRT or zero-CRT) is detected
 * within seconds and the game dies with 0xC0000026 (5 crashes confirmed).
 *
 * v7 therefore patches NOTHING. It arms a CPU hardware breakpoint on
 * the real set_entering entry (game.dll+0x637660) by writing DR0/DR7 of
 * every game thread (per-thread debug registers, zero code bytes
 * touched). When the game thread executes 0x637660 the CPU raises a
 * single-step debug exception; our VEH reads rcx (Y = Seater instance),
 * edx (seat index) and r8d (new state) from the exception context,
 * clears DR6.B0 and returns CONTINUE so the instruction runs normally.
 * The breakpoint stays armed: every player enter/leave is captured.
 * ============================================================ */
#define RC_RVA_SET_ENTERING 0x637660u
typedef void (__fastcall *fn_seater_v7)(void *y, unsigned int seat, unsigned int state);
static uint64_t g_se7_target = 0;              /* VA of set_entering */
static volatile LONG g_se7_armed = 0;
static volatile LONG g_se7_veh_ok = 0;

/* ring buffer (256 entries) - VEH writes, main polls */
#define RC_SE7_RING 256
static volatile uint64_t g_se7_y[RC_SE7_RING];
static volatile uint32_t g_se7_seat[RC_SE7_RING];
static volatile uint32_t g_se7_st[RC_SE7_RING];
static volatile uint64_t g_se7_ra[RC_SE7_RING];
static volatile uint32_t g_se7_wp = 0;
static volatile uint32_t g_se7_hits = 0;
static volatile uint32_t g_se7_last_print = 0;

static LONG NTAPI se7_veh(PEXCEPTION_POINTERS ep)
{
    if (g_se7_armed && ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        PCONTEXT ctx = ep->ContextRecord;
        if (ctx->Rip == g_se7_target && (uint64_t)ctx->Dr0 == g_se7_target) {
            uint32_t w = (uint32_t)g_se7_wp;
            uint32_t s = w & (RC_SE7_RING - 1);
            g_se7_y[s]    = ctx->Rcx;
            g_se7_seat[s] = (uint32_t)ctx->Rdx;
            g_se7_st[s]   = (uint32_t)ctx->R8;
            g_se7_ra[s]   = ctx->Rip;
            g_se7_wp      = w + 1;
            g_se7_hits    = (uint32_t)g_se7_hits + 1;
            /* clear DR6.B0..B3 so the same instruction does not loop;
               keep DR7.L0 armed for the next call */
            ctx->Dr6 &= ~0xFul;
            /* CRITICAL: set the Resume Flag (RF, bit 8) so the CPU executes
               the breakpoint instruction ONCE. Without it the debug
               exception re-fires on the same instruction forever and the
               game freezes (observed: freeze on manning an emplacement). */
            ctx->EFlags |= 0x100ul;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void se7_arm(void)
{
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!th) continue;
            CONTEXT c; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(th, &c)) {
                c.Dr0 = g_se7_target;
                /* keep other breakpoints, set DR0: L0=1 (exec) */
                c.Dr7 = (c.Dr7 & ~0xF0003ul) | 0x1ul;
                SetThreadContext(th, &c);
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static void se7_disarm(void)
{
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!th) continue;
            CONTEXT c; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(th, &c)) {
                c.Dr0 = 0;
                c.Dr7 &= ~0xF0003ul;   /* clear DR0 enable bits */
                SetThreadContext(th, &c);
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static void se7_poll_log(void)
{
    uint32_t h = (uint32_t)g_se7_hits;
    if (h != g_se7_last_print && h > 0) {
        uint32_t from = g_se7_last_print < h ? g_se7_last_print : 0;
        uint32_t n = h - from;
        if (n > 16) n = 16;
        for (uint32_t k = 0; k < n; k++) {
            uint32_t s = ((uint32_t)g_se7_wp - n + k) & (RC_SE7_RING - 1);
            log_msg("[SEATER7] set_entering y=%llx seat=%u state=%u\n",
                (unsigned long long)g_se7_y[s], g_se7_seat[s], g_se7_st[s]);
        }
        g_se7_last_print = h;
    }
}

static void install_seater_hook_v7(void)
{
    HMODULE gdll = GetModuleHandleA("game.dll");
    if (!gdll) return;
    uint64_t tgt = (uint64_t)(uintptr_t)gdll + RC_RVA_SET_ENTERING;
    /* Sanity: the entry bytes must match the capstone-verified prologue
     * (read-only check, no patch). */
    const uint8_t expect[6] = { 0x4C,0x8B,0xDC, 0x41,0x54, 0x41 };
    if (memcmp((const void *)tgt, expect, 6) != 0) {
        log_msg("[SEATER7] prologue mismatch at %p - aborting arm\n", (void *)tgt);
        return;
    }
    g_se7_target = tgt;
    if (!g_se7_veh_ok) {
        if (AddVectoredExceptionHandler(1, se7_veh))
            g_se7_veh_ok = 1;
        else {
            log_msg("[SEATER7] AddVectoredExceptionHandler failed\n");
            return;
        }
    }
    se7_arm();
    g_se7_armed = 1;
    g_se7_wp = 0; g_se7_hits = 0; g_se7_last_print = 0;
    log_msg("[SEATER7] HW breakpoint armed on set_entering @ %p (no code patched)\n", (void *)tgt);
}

static void uninstall_seater_hook_v7(void)
{
    if (!g_se7_armed) return;
    g_se7_armed = 0;
    se7_disarm();
    log_msg("[SEATER7] HW breakpoint disarmed\n");
}

static void install_seater_hook(void) {
    // CRASH HISTORY: 0x634120 mid-instruction patch (x2), type-name E9 and
    // abs-jump hooks (x2), zero-CRT set_entering abs-jump (x1) - all inline
    // patches get caught by the WinLicense/VMProtect integrity check.
    // v7 uses a hardware breakpoint instead: ZERO code bytes modified.
    if (g_se7_armed) uninstall_seater_hook_v7();
    else install_seater_hook_v7();
}

/* ============================================================
 * v8: FRV Seater instance (Y) discovery + DIRECT set_entering call.
 * No code is patched - we only READ memory to locate Y, then CALL the
 * engine function (game.dll+0x637660) like any other function. The
 * anti-tamper check detects modified bytes, not function calls.
 *
 * Chain: uobj = [game.dll+0x276ca20+0x18]
 *        arr  = [uobj+0x0e0]
 *        X    = arr[i] where [X+0x48] is a heap ptr AND X+0x80 string
 *               contains "bundle"/"ico00" (vehicle resource path)
 *        Y    = [X+0x48]  (Seater instance, slot array at Y+0x48)
 * ============================================================ */
#define RC_RVA_SET_ENTERING8 0x637660u
typedef void (__fastcall *fn_seater_v8)(void *y, unsigned int seat, unsigned int state);
static uint64_t g_frv_y = 0;

static int v8_has_marker(uint64_t a) {
    /* read 0x48 bytes at a, look for "bundle" or "ico00" */
    unsigned char buf[0x48];
    for (int i = 0; i < 9; i++) {
        uint64_t v = 0;
        if (!rc_safe_read64(a + i*8, &v)) return 0;
        ((uint64_t *)buf)[i] = v;
    }
    for (int i = 0; i + 6 < (int)sizeof(buf); i++) {
        if (memcmp(buf + i, "bundle", 6) == 0) return 1;
        if (i + 5 < (int)sizeof(buf) && memcmp(buf + i, "ico00", 5) == 0) return 1;
    }
    return 0;
}

static int find_frv_y(void) {
    HMODULE gdll = GetModuleHandleA("game.dll");
    if (!gdll) return 0;
    uint64_t gb = (uint64_t)(uintptr_t)gdll;
    uint64_t uobj = 0;
    if (!rc_safe_read64(gb + 0x276ca20 + 0x18, &uobj) || uobj < 0x100000000ULL) return 0;
    uint64_t arr = 0;
    if (!rc_safe_read64(uobj + 0x0e0, &arr) || arr < 0x100000000ULL) return 0;
    int best = -1;
    uint64_t best_y = 0;
    for (int i = 0; i < 256; i++) {
        uint64_t E = 0;
        if (!rc_safe_read64(arr + i*8, &E) || E < 0x100000000ULL) continue;
        uint64_t p48 = 0;
        if (!rc_safe_read64(E + 0x48, &p48) || p48 < 0x100000000ULL) continue;
        if (!v8_has_marker(E + 0x80)) continue;
        /* candidate X found - log it */
        log_msg("[RAYCAST] SEATER8 cand[%d] X=%llx Y=%llx\n", i, E, p48);
        /* validate: [Y+0x48] must be a heap ptr (seat slot array) AND
         * [Y+0x50] must point back at X (double check - X+0x48 is a
         * dynamic field, the first deref can be a different object) */
        uint64_t slots = 0;
        if (!rc_safe_read64(p48 + 0x48, &slots) || slots < 0x100000000ULL) {
            log_msg("[RAYCAST] SEATER8   (reject: no slot array)\n");
            continue;
        }
        uint64_t back = 0;
        if (!rc_safe_read64(p48 + 0x50, &back) || back != E) {
            log_msg("[RAYCAST] SEATER8   (reject: back-pointer mismatch)\n");
            continue;
        }
        g_frv_y = p48;
        return 1;
    }
    if (best >= 0) { g_frv_y = best_y; return 1; }
    return 0;
}

/* v10.5: on-screen feedback (rendered by addon). f7_find_frv below uses it,
 * so forward-declare before that function. */
static void rc_set_feedback(const char *fmt, ...);

static void f7_find_frv(void) {
    if (find_frv_y()) {
        log_msg("[RAYCAST] SEATER8 FRV Y = %llx\n", (unsigned long long)g_frv_y);
        rc_set_feedback("已锁定 FRV（实例 %llx）", (unsigned long long)g_frv_y);
        uint64_t slots = 0;
        if (rc_safe_read64(g_frv_y + 0x48, &slots) && slots >= 0x100000000ULL) {
            for (int i = 0; i < 8; i++) {
                uint64_t qs[4] = {0,0,0,0};
                int ok = 1;
                for (int j = 0; j < 4; j++)
                    if (!rc_safe_read64(slots + i*0x40 + j*8, &qs[j])) { ok = 0; break; }
                if (!ok) break;
                log_msg("  slot[%d] %016llx %016llx %016llx %016llx\n",
                    i, qs[0], qs[1], qs[2], qs[3]);
            }
        }
    } else {
        log_msg("[RAYCAST] SEATER8 FRV Y not found (is a vehicle deployed?)\n");
        rc_set_feedback("没找到 FRV：确认载具已部署再按");
    }
}

/* v10.33: dump the player seater context ([game+0x276ca28] structure), the
 * command-context global region, and the seater instance array. Bound to
 * Numpad0 alongside f7_find_frv. This reveals how the player's unit is bound
 * to the seat (the last piece needed for NPC boarding). */
static void dump_player_ctx(void) {
    HMODULE gdll = GetModuleHandleA("game.dll");
    if (!gdll) { log_msg("[RAYCAST] CTX dump FAIL: no game.dll\n"); return; }
    uint64_t gb = (uint64_t)(uintptr_t)gdll;
    uint64_t ctx = 0;
    if (rc_safe_read64(gb + 0x276ca28, &ctx))
        log_msg("[RAYCAST] CTX [0x276ca28] = 0x%llx\n", (unsigned long long)ctx);
    if (ctx >= 0x100000000ULL) {
        log_msg("[RAYCAST] CTX struct @0x%llx:\n", (unsigned long long)ctx);
        uint32_t d[16];
        int ok = 1;
        for (int j = 0; j < 16; j++)
            if (!rc_safe_read32(ctx + j*4, &d[j])) { ok = 0; break; }
        if (ok) {
            log_msg("[RAYCAST] CTX +00: %08x %08x %08x %08x\n", d[0], d[1], d[2], d[3]);
            log_msg("[RAYCAST] CTX +10: %08x %08x %08x %08x\n", d[4], d[5], d[6], d[7]);
            log_msg("[RAYCAST] CTX +20: %08x %08x %08x %08x\n", d[8], d[9], d[10], d[11]);
            log_msg("[RAYCAST] CTX +30: %08x %08x %08x %08x\n", d[12], d[13], d[14], d[15]);
        }
        /* v10.34: follow the two qword pointers in the ctx struct (+0x08 and
         * +0x28) - one of them is likely the player unit / seat binding.
         * v10.36: dump 16 qwords (128B object header) of each pointed object
         * and follow EVERY pointer found inside (not just q[0]). */
        uint64_t ptrs[2] = {0, 0};
        rc_safe_read64(ctx + 0x08, &ptrs[0]);
        rc_safe_read64(ctx + 0x28, &ptrs[1]);
        for (int pi = 0; pi < 2; pi++) {
            uint64_t p = ptrs[pi];
            if (p >= 0x100000000ULL) {
                uint64_t q[16];
                int ok2 = 1;
                for (int j = 0; j < 16; j++)
                    if (!rc_safe_read64(p + j*8, &q[j])) { ok2 = 0; break; }
                if (ok2)
                    for (int j = 0; j < 16; j += 4)
                        log_msg("[RAYCAST] CTX->ptr+0x%02X @0x%llx +%02X: %016llx %016llx %016llx %016llx\n",
                            pi ? 0x28 : 0x08, (unsigned long long)p, j*8,
                            q[j], q[j+1], q[j+2], q[j+3]);
                if (ok2) {
                    /* follow every pointer found inside the object header */
                    for (int j = 0; j < 16; j++) {
                        uint64_t q0 = q[j];
                        if (q0 >= 0x100000000ULL && q0 != p && q0 != ctx) {
                            uint64_t r[4];
                            int ok3 = 1;
                            for (int k = 0; k < 4; k++)
                                if (!rc_safe_read64(q0 + k*8, &r[k])) { ok3 = 0; break; }
                            if (ok3)
                                log_msg("[RAYCAST]   ->[+0x%02X] @0x%llx: %016llx %016llx %016llx %016llx\n",
                                    j*8, (unsigned long long)q0, r[0], r[1], r[2], r[3]);
                        }
                    }
                }
            }
        }
    } else {
        log_msg("[RAYCAST] CTX [0x276ca28] = 0 - player not boarded?\n");
    }
    uint64_t g0 = 0, g1 = 0, g2 = 0, g3 = 0;
    rc_safe_read64(gb + 0x276ca30, &g0);
    rc_safe_read64(gb + 0x276ca38, &g1);
    rc_safe_read64(gb + 0x276ca40, &g2);
    rc_safe_read64(gb + 0x276ca48, &g3);
    log_msg("[RAYCAST] CTX region 0x276ca30: %llx %llx %llx %llx\n",
        (unsigned long long)g0, (unsigned long long)g1, (unsigned long long)g2, (unsigned long long)g3);
    /* v10.34: raw dump of [0x276ca80]-pointed area (the previous count offset
     * +0x55d8 produced garbage - re-derive the array layout from raw bytes). */
    uint64_t arr = 0;
    if (rc_safe_read64(gb + 0x276ca80, &arr) && arr >= 0x100000000ULL) {
        log_msg("[RAYCAST] CTX seater-region [0x276ca80]=0x%llx raw dump:\n", (unsigned long long)arr);
        uint32_t raw[64];
        int okr = 1;
        for (int j = 0; j < 64; j++)
            if (!rc_safe_read32(arr + j*4, &raw[j])) { okr = 0; break; }
        if (okr) {
            for (int j = 0; j < 64; j += 4)
                log_msg("[RAYCAST]   +%03X: %08x %08x %08x %08x\n", j*4, raw[j], raw[j+1], raw[j+2], raw[j+3]);
        }
    } else {
        log_msg("[RAYCAST] CTX seater-region [0x276ca80] = 0\n");
    }
    /* v10.37: dump the seater manager ([0x276ca88]) slot array directly -
     * the real unit<->seat binding lives here (empty slots when no rider,
     * occupied when boarded), unlike the CTX chain which is a resident
     * player-session context (verified unchanged off-board). This does NOT
     * depend on the broken find_frv_y legacy path. */
    uint64_t smgr = 0;
    if (rc_safe_read64(gb + 0x276ca88, &smgr) && smgr >= 0x100000000ULL) {
        log_msg("[RAYCAST] SEATER8 mgr [0x276ca88]=0x%llx\n", (unsigned long long)smgr);
        uint64_t htab = 0, hcnt = 0;
        rc_safe_read64(smgr + 0x20, &htab);
        rc_safe_read64(smgr + 0x28, &hcnt);
        log_msg("[RAYCAST] SEATER8 mgr hash@+0x20=%llx count@+0x28=%llx\n",
            (unsigned long long)htab, (unsigned long long)hcnt);
        uint64_t slots = 0;
        if (rc_safe_read64(smgr + 0x48, &slots) && slots >= 0x100000000ULL) {
            log_msg("[RAYCAST] SEATER8 mgr slots@+0x48=0x%llx\n", (unsigned long long)slots);
            for (int si = 0; si < 4; si++) {
                uint32_t q[16] = {0};
                int ok = 1;
                for (int j = 0; j < 16; j++)
                    if (!rc_safe_read32(slots + (uint64_t)si * 0x40 + j*4, &q[j])) { ok = 0; break; }
                if (ok)
                    log_msg("[RAYCAST] SEATER8 slot[%d]=[0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x]\n",
                        si, q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7], q[8], q[9], q[10], q[11], q[12], q[13], q[14], q[15]);
            }
        } else {
            log_msg("[RAYCAST] SEATER8 mgr: no slot array at +0x48\n");
        }
        /* v10.38: scan the hash table at mgr+0x20 for the seater_id->slot
         * mapping (command_queue_exit uses it: entry[+4]=slot index). The
         * boarded slot's seater_idx (0x1a in the capture) should appear as
         * an entry key.
         * v10.39: full-table scan (0x200 entries, open-addressing so entries
         * are sparse) + dump the table header + the mgr head to learn the
         * real layout (first-64 linear scan was all-empty). */
        if (htab >= 0x100000000ULL && hcnt <= 0x2000) {
            uint32_t th[16] = {0};
            int okt = 1;
            for (int j = 0; j < 16; j++)
                if (!rc_safe_read32(htab + j*4, &th[j])) { okt = 0; break; }
            if (okt)
                log_msg("[RAYCAST] SEATER8 hash@+0x20 header: %08x %08x %08x %08x | %08x %08x %08x %08x | %08x %08x %08x %08x | %08x %08x %08x %08x\n",
                    th[0], th[1], th[2], th[3], th[4], th[5], th[6], th[7],
                    th[8], th[9], th[10], th[11], th[12], th[13], th[14], th[15]);
            /* full-table scan: 0x200 entries x 8 bytes (key=lo32, slot=hi32) */
            log_msg("[RAYCAST] SEATER8 hash full scan (0x200 entries):\n");
            int shown = 0;
            for (int i = 0; i < 512; i++) {
                uint64_t e = 0;
                if (!rc_safe_read64(htab + (uint64_t)i * 8, &e)) break;
                if (e == 0 || e == 0xFFFFFFFFFFFFFFFFull) continue;
                log_msg("[RAYCAST]   entry[%03d]=0x%016llx (key=0x%x slot=0x%x)\n",
                    i, (unsigned long long)e,
                    (unsigned)(e & 0xFFFFFFFFu), (unsigned)((e >> 32) & 0xFFFFFFFFu));
                shown++;
            }
            log_msg("[RAYCAST] SEATER8 hash scan done: %d non-empty\n", shown);
            /* mgr head (first 16 qwords) to locate the seater object array */
            uint64_t mq[16] = {0};
            int okm = 1;
            for (int j = 0; j < 16; j++)
                if (!rc_safe_read64(smgr + j*8, &mq[j])) { okm = 0; break; }
            if (okm) {
                log_msg("[RAYCAST] SEATER8 mgr head:\n");
                for (int j = 0; j < 16; j += 4)
                    log_msg("[RAYCAST]   +%02X: %016llx %016llx %016llx %016llx\n",
                        j*8, mq[j], mq[j+1], mq[j+2], mq[j+3]);
            }
            /* v10.40: follow mgr+0x38 (seater object array, used by
             * find_frv_seater_id) - dump the first 8 objects and read each
             * object's +8 field (the id find_frv_seater_id returns) to find
             * which one carries 0x1cc (the hash key of the boarded slot).
             * v10.41: dump 32 objects (hash has 26 entries - the array IS
             * the global seater registration table; every registered unit
             * has one object here). */
            uint64_t objs = mq[7]; /* mgr+0x38 */
            if (objs >= 0x100000000ULL) {
                log_msg("[RAYCAST] SEATER8 obj-arr@mgr+0x38=%llx (32 objs):\n", (unsigned long long)objs);
                for (int oi = 0; oi < 32; oi++) {
                    uint64_t o = 0;
                    if (!rc_safe_read64(objs + (uint64_t)oi * 8, &o) || o < 0x100000000ULL) continue;
                    uint64_t q1 = 0;
                    if (!rc_safe_read64(o + 8, &q1)) continue;
                    uint32_t id = q1 & 0xFFFFFFFF;
                    log_msg("[RAYCAST]   obj[%02d]=%llx +8=0x%llx (id=0x%x hi=0x%x)\n",
                        oi, (unsigned long long)o, (unsigned long long)q1, id, (unsigned)(q1 >> 32));
                }
            }
        }
    } else {
        log_msg("[RAYCAST] SEATER8 mgr [0x276ca88] = 0\n");
    }
}

static void CALLBACK apc_seater_call(ULONG_PTR param) {
    /* Runs ON the game thread (APC context). The engine function is
     * called exactly like the game calls it: same thread, same stack
     * discipline - no cross-thread data race. */
    uint64_t *a = (uint64_t *)param;
    fn_seater_v8 fn = (fn_seater_v8)(uintptr_t)a[1];
    __try {
        fn((void *)(uintptr_t)a[0], (unsigned int)a[2], (unsigned int)a[3]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_msg("[RAYCAST] SEATER8 apc set_entering exception (caught)\n");
    }
}

/* ============================================================
 * v10: FULL board command via game.dll+0x634120 (capstone-verified
 * set_entering command entry):
 *   void __fastcall cmd(void *seater_mgr, uint seat_idx,
 *                       uint seat_collection_id, uint entrance_interactable,
 *                       uint instant)
 * The engine's own "set_entering seater:%u, seat_collection:%u,
 * entrance_interactable:%u, instant:%u" log is printed from here, then
 * the seat slot is written and seat_collection is processed. Running it
 * on the game thread (APC) replicates the real board flow.
 * ============================================================ */
#define RC_RVA_SE_CMD 0x634120u
typedef void (__fastcall *fn_se_cmd)(void *mgr, unsigned int seat, unsigned int sc_id,
                                     unsigned int entrance, unsigned int instant);

/* dynamic FRV seat_collection id: scan the sc manager's object array for
 * the FIRST valid entry (id != 0). The hi16 marker (0x0080/0x0040/...) is
 * NOT stable across sessions; the first entry is the vehicle's because
 * the seater manager holds the FRV at index 0. */
static int find_frv_sc_id(uint64_t *out_id)
{
    HMODULE gdll = GetModuleHandleA("game.dll");
    if (!gdll) return 0;
    uint64_t gb = (uint64_t)(uintptr_t)gdll;
    uint64_t sc = 0;
    if (!rc_safe_read64(gb + 0x276ca98, &sc) || sc < 0x100000000ULL) return 0;
    uint64_t objs = 0;
    if (!rc_safe_read64(sc + 0x38, &objs) || objs < 0x100000000ULL) return 0;
    for (int i = 0; i < 32; i++) {
        uint64_t o = 0;
        if (!rc_safe_read64(objs + (uint64_t)i * 8, &o) || o < 0x100000000ULL) continue;
        uint64_t q1 = 0;
        if (!rc_safe_read64(o + 8, &q1)) continue;
        uint32_t id = q1 & 0xFFFFFFFF;
        if (id != 0 && id != 0xFFFFFFFF) {
            *out_id = id;
            return 1;
        }
    }
    return 0;
}

/* v10.16: print the faulting address when an APC engine call crashes,
 * so we can pin down WHERE 0x634120/0x633e50 blow up internally. v10.17
 * adds the owning module base/name - the crash addr 0x7ff6b3fed62e was
 * outside game.dll's range, so we need to know which module it is in. */
static void apc_exc_log(const char *tag, PEXCEPTION_POINTERS ep)
{
    if (ep && ep->ExceptionRecord) {
        void *addr = ep->ExceptionRecord->ExceptionAddress;
        HMODULE mod = NULL;
        char modname[64] = "?";
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)addr, &mod) && mod) {
            GetModuleBaseNameA(GetCurrentProcess(), mod, modname, sizeof(modname));
            log_msg("[RAYCAST] SEATER8 %s exception at 0x%llx code=0x%x mod=%s base=%llx rva=0x%llx\n",
                tag, (unsigned long long)(uintptr_t)addr,
                (unsigned)ep->ExceptionRecord->ExceptionCode, modname,
                (unsigned long long)(uintptr_t)mod,
                (unsigned long long)((uintptr_t)addr - (uintptr_t)mod));
        } else {
            log_msg("[RAYCAST] SEATER8 %s exception at 0x%llx code=0x%x (no module)\n",
                tag, (unsigned long long)(uintptr_t)addr,
                (unsigned)ep->ExceptionRecord->ExceptionCode);
        }
    }
}

static void CALLBACK apc_se_cmd(ULONG_PTR param)
{
    uint64_t *a = (uint64_t *)param;
    fn_se_cmd fn = (fn_se_cmd)(uintptr_t)a[1];
    log_msg("[RAYCAST] SEATER8 APC se-cmd EXECUTED on tid=%lu\n",
        (unsigned long)GetCurrentThreadId());
    __try {
        fn((void *)(uintptr_t)a[0], (unsigned int)a[2], (unsigned int)a[3],
           (unsigned int)a[4], (unsigned int)a[5]);
        log_msg("[RAYCAST] SEATER8 APC se-cmd RETURNED (engine accepted)\n");
    } __except (apc_exc_log("se-cmd", GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
        log_msg("[RAYCAST] SEATER8 apc se-cmd exception (caught)\n");
    }
}

/* ============================================================
 * v10.13: goto_node_with_action - game.dll+0x633e50
 *   void __fastcall goto_na(void *mgr, uint slot_index, uint action,
 *                           uint node, uint instant)
 * Normal board sequence (engine logs, [0]):
 *   set_entering -> execute_action -> goto_node_with_action(node=-1)
 *   -> (animation) -> set_role. We were only calling set_entering, so the
 *   unit was seated but never animated to the node - stuck, no animation.
 * ============================================================ */
#define RC_RVA_GOTO_NA 0x633e50u
typedef void (__fastcall *fn_goto_na)(void *mgr, unsigned int slot_index,
    unsigned int action, unsigned int node, unsigned int instant);

static void CALLBACK apc_goto_na(ULONG_PTR param)
{
    uint64_t *a = (uint64_t *)param;
    fn_goto_na fn = (fn_goto_na)(uintptr_t)a[1];
    log_msg("[RAYCAST] SEATER8 APC goto_na EXECUTED on tid=%lu\n",
        (unsigned long)GetCurrentThreadId());
    __try {
        fn((void *)(uintptr_t)a[0], (unsigned int)a[2], (unsigned int)a[3],
           (unsigned int)a[4], (unsigned int)a[5]);
        log_msg("[RAYCAST] SEATER8 APC goto_na RETURNED\n");
    } __except (apc_exc_log("goto_na", GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
        log_msg("[RAYCAST] SEATER8 apc goto_na exception (caught)\n");
    }
}

/* ============================================================
 * v10.19: full board sequence in one APC. Disasm of the engine's own
 * caller (0x633358) shows it calls 0x630810 (state-prep, returns slot)
 * FIRST, then 0x634120 with instant=1, then goto_node_with_action.
 * Calling 0x634120 alone (v10.3+) crashed at helldivers2.exe+0x9d62e
 * because the seater was never activated - 0x619400's lookup failed.
 * ============================================================ */
#define RC_RVA_ACT810 0x630810u
typedef int (__fastcall *fn_act810)(void *mgr, unsigned int sc_id,
    unsigned int r8_unused, unsigned int entrance);

static void CALLBACK apc_board_full(ULONG_PTR param)
{
    uint64_t *a = (uint64_t *)param; /* mgrB, se_cmd, goto_na, act810, sc_id, entrance, action, mgrA */
    fn_act810 f1 = (fn_act810)(uintptr_t)a[3];
    fn_se_cmd f2 = (fn_se_cmd)(uintptr_t)a[1];
    fn_goto_na f3 = (fn_goto_na)(uintptr_t)a[2];
    log_msg("[RAYCAST] SEATER8 APC board-full EXECUTED on tid=%lu\n",
        (unsigned long)GetCurrentThreadId());
    __try {
        int r1 = f1((void *)(uintptr_t)a[7], (unsigned int)a[4], 0, (unsigned int)a[5]);
        log_msg("[RAYCAST] SEATER8 act810(0x630810,mgrA) returned %d\n", r1);
        f2((void *)(uintptr_t)a[0], 0, (unsigned int)a[4], (unsigned int)a[5], 1);
        log_msg("[RAYCAST] SEATER8 set_entering done (instant=1)\n");
        f3((void *)(uintptr_t)a[0], 0, 0xFFFFFFFFu, (unsigned int)a[6], 0);
        log_msg("[RAYCAST] SEATER8 goto_na done (node=-1 action=%u)\n", (unsigned int)a[6]);
        log_msg("%s", "[RAYCAST] SEATER8 board-full RETURNED (engine accepted)\n");
    } __except (apc_exc_log("board-full", GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
        log_msg("[RAYCAST] SEATER8 apc board-full exception (caught)\n");
    }
}

/* v10.42: NPC board APC - set_entering with a SELECTED seat index (obj-arr
 * index of the target unit). Reverse-engineering (fn_00634120.asm) proved
 * set_entering's 2nd param = obj-arr index (mgr+0x38[seat]) = slot index:
 *   shl r15,6 ; add r15,[rcx+0x48]   -> slot[seat]
 *   mov rax,[rdx+0x38] ; mov rcx,[rax+rcx] ; mov ebx,[rcx+8] -> obj-arr[seat].id
 * The player-board path hardcodes seat=0 (obj-arr[0]=player); passing a
 * SEAF unit's index lets THAT unit board. */
static void CALLBACK apc_npc_board(ULONG_PTR param)
{
    uint64_t *a = (uint64_t *)param; /* mgrB, se_cmd, goto_na, act810, sc_id, seat, entrance, action, mgrA */
    fn_act810 f1 = (fn_act810)(uintptr_t)a[3];
    fn_se_cmd f2 = (fn_se_cmd)(uintptr_t)a[1];
    fn_goto_na f3 = (fn_goto_na)(uintptr_t)a[2];
    log_msg("[RAYCAST] SEATER8 APC npc-board EXECUTED on tid=%lu seat=%u\n",
        (unsigned long)GetCurrentThreadId(), (unsigned int)a[5]);
    __try {
        int r1 = f1((void *)(uintptr_t)a[8], (unsigned int)a[4], 0, (unsigned int)a[6]);
        log_msg("[RAYCAST] SEATER8 npc act810 returned %d\n", r1);
        f2((void *)(uintptr_t)a[0], (unsigned int)a[5], (unsigned int)a[4], (unsigned int)a[6], 1);
        log_msg("[RAYCAST] SEATER8 npc set_entering done (seat=%u instant=1)\n", (unsigned int)a[5]);
        f3((void *)(uintptr_t)a[0], (unsigned int)a[5], 0xFFFFFFFFu, (unsigned int)a[7], 0);
        log_msg("[RAYCAST] SEATER8 npc goto_na done (seat=%u node=-1 action=%u)\n",
            (unsigned int)a[5], (unsigned int)a[7]);
        log_msg("%s", "[RAYCAST] SEATER8 npc-board RETURNED (engine accepted)\n");
    } __except (apc_exc_log("npc-board", GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
        log_msg("[RAYCAST] SEATER8 apc npc-board exception (caught)\n");
    }
}

/* ============================================================
 * v10.3: EXIT command - game.dll+0x636e50 (command_queue_exit)
 *   void __fastcall exit_cmd(void *seater_mgr, uint seater_id, uint instant)
 * edx = the SEATER COMPONENT ID (322 in the last session), looked up in
 * the manager's id map. Instant flag is r8b (low byte of r8).
 * ============================================================ */
#define RC_RVA_EXIT_CMD 0x636e50u
typedef void (__fastcall *fn_exit_cmd)(void *mgr, unsigned int seater_id, unsigned int instant);

/* FRV seater id = first valid entry in the seater manager object array */
static int find_frv_seater_id(uint64_t *out_id)
{
    HMODULE gdll = GetModuleHandleA("game.dll");
    if (!gdll) return 0;
    uint64_t gb = (uint64_t)(uintptr_t)gdll;
    uint64_t mgr = 0;
    if (!rc_safe_read64(gb + 0x276ca88, &mgr) || mgr < 0x100000000ULL) return 0;
    uint64_t objs = 0;
    if (!rc_safe_read64(mgr + 0x38, &objs) || objs < 0x100000000ULL) return 0;
    uint64_t o = 0;
    if (!rc_safe_read64(objs, &o) || o < 0x100000000ULL) return 0;
    uint64_t q1 = 0;
    if (!rc_safe_read64(o + 8, &q1)) return 0;
    uint32_t id = q1 & 0xFFFFFFFF;
    if (id == 0 || id == 0xFFFFFFFF) return 0;
    *out_id = id;
    return 1;
}

static void CALLBACK apc_exit_cmd(ULONG_PTR param)
{
    uint64_t *a = (uint64_t *)param;
    fn_exit_cmd fn = (fn_exit_cmd)(uintptr_t)a[1];
    log_msg("[RAYCAST] SEATER8 APC exit-cmd EXECUTED on tid=%lu\n",
        (unsigned long)GetCurrentThreadId());
    __try {
        fn((void *)(uintptr_t)a[0], (unsigned int)a[2], (unsigned int)a[3]);
        log_msg("[RAYCAST] SEATER8 APC exit-cmd RETURNED (engine accepted)\n");
    } __except (apc_exc_log("exit-cmd", GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
        log_msg("[RAYCAST] SEATER8 apc exit-cmd exception (caught)\n");
    }
}

/* v10.4b: find the game's window thread (input/update loop). The engine's
 * seater commands must run on this thread; a random worker thread never
 * enters alertable wait, so the APC would just sit in the queue forever. */
static BOOL CALLBACK find_wnd_thread_cb(HWND h, LPARAM lp)
{
    DWORD pid = GetCurrentProcessId();
    DWORD wpid = 0;
    GetWindowThreadProcessId(h, &wpid);
    if (wpid == pid) {
        *((DWORD *)lp) = GetWindowThreadProcessId(h, NULL);
        return FALSE; /* stop */
    }
    return TRUE;
}
static DWORD find_window_thread(void)
{
    DWORD tid = 0;
    EnumWindows(find_wnd_thread_cb, (LPARAM)&tid);
    return tid;
}

/* ============================================================
 * v10.10: engine-thread discovery by APC probe.
 * The game's window thread never enters an alertable wait, so APCs queued
 * to it (v10.6-v10.9) sat forever - "queued" but never EXECUTED. Instead
 * we probe EVERY thread once: alertable threads run our marker callback
 * within ~250ms, non-alertable ones ignore it. The first responder is the
 * engine thread we route seater commands to (the v10.3 build that worked
 * had accidentally picked exactly such a thread via enumeration order).
 * ============================================================ */
static volatile LONG g_probe_tids[64];
static volatile LONG g_probe_count = 0;
static DWORD g_engine_tid = 0;
static int g_engine_probed = 0;

static void CALLBACK apc_probe(ULONG_PTR param)
{
    (void)param;
    LONG tid = (LONG)GetCurrentThreadId();
    if (g_probe_count < 64) {
        LONG idx = InterlockedIncrement(&g_probe_count) - 1;
        if (idx < 64) g_probe_tids[idx] = tid;
    }
}

/* Probe once, cache the first alertable thread. Returns 0 if none. */
static DWORD find_engine_thread(void)
{
    if (g_engine_probed) return g_engine_tid;
    g_engine_probed = 1;
    InterlockedExchange(&g_probe_count, 0);
    DWORD my_tid = GetCurrentThreadId();
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    int queued = 0;
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te; te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid || te.th32ThreadID == my_tid) continue;
                HANDLE th = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (!th) continue;
                if (QueueUserAPC((PAPCFUNC)apc_probe, th, 0)) queued++;
                CloseHandle(th);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    Sleep(250); /* give alertable threads a chance to run the probe */
    if (g_probe_count > 0) {
        g_engine_tid = (DWORD)g_probe_tids[0];
        log_msg("[RAYCAST] SEATER8 engine-thread probe: %ld alertable, picked tid=%lu\n",
            (long)g_probe_count, (unsigned long)g_engine_tid);
    } else {
        log_msg("[RAYCAST] SEATER8 engine-thread probe: NO alertable thread (%d queued)\n",
            queued);
    }
    return g_engine_tid;
}

static int queue_apc(PAPCFUNC fn, uint64_t *arg, int n)
{
    (void)n;
    DWORD my_tid = GetCurrentThreadId();
    DWORD pid = GetCurrentProcessId();
    int queued = 0;

    /* preferred: the probed alertable engine thread */
    DWORD eng_tid = find_engine_thread();
    if (eng_tid && eng_tid != my_tid) {
        HANDLE th = OpenThread(THREAD_SET_CONTEXT, FALSE, eng_tid);
        if (th) {
            if (QueueUserAPC(fn, th, (ULONG_PTR)arg)) {
                queued++;
                log_msg("[RAYCAST] SEATER8 APC queued to engine tid=%lu\n",
                    (unsigned long)eng_tid);
            }
            CloseHandle(th);
        }
    }

    /* fallback 1: the game window thread (likely non-alertable, best effort) */
    if (!queued) {
        DWORD win_tid = find_window_thread();
        if (win_tid && win_tid != my_tid) {
            HANDLE th = OpenThread(THREAD_SET_CONTEXT, FALSE, win_tid);
            if (th) {
                if (QueueUserAPC(fn, th, (ULONG_PTR)arg)) {
                    queued++;
                    log_msg("[RAYCAST] SEATER8 APC queued to window thread tid=%lu\n",
                        (unsigned long)win_tid);
                }
                CloseHandle(th);
            }
        }
    }

    /* fallback 2: first thread that actually accepts the APC (never all) */
    if (!queued) {
        /* fallback: first thread that actually accepts the APC (never all) */
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te; te.dwSize = sizeof(te);
            if (Thread32First(snap, &te)) {
                do {
                    if (te.th32OwnerProcessID != pid || te.th32ThreadID == my_tid) continue;
                    HANDLE th = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                    if (!th) continue;
                    if (QueueUserAPC(fn, th, (ULONG_PTR)arg)) {
                        queued++;
                        log_msg("[RAYCAST] SEATER8 APC queued to fallback tid=%lu\n",
                            (unsigned long)te.th32ThreadID);
                        CloseHandle(th);
                        break;
                    }
                    CloseHandle(th);
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }
    }
    return queued;
}

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

static void f8_exit_command(void)
{
    HMODULE gdll = GetModuleHandleA("game.dll");
    if (!gdll) { log_msg("[RAYCAST] SEATER8 exit FAIL: no game.dll\n"); return; }
    uint64_t gb = (uint64_t)(uintptr_t)gdll;
    uint64_t mgr = 0;
    if (!rc_safe_read64(gb + 0x276ca88, &mgr) || mgr < 0x100000000ULL) {
        rc_set_feedback("下车失败：找不到座位管理器");
        log_msg("[RAYCAST] SEATER8 exit FAIL: no seater mgr\n");
        return;
    }
    uint64_t seater_id = 0;
    if (!find_frv_seater_id(&seater_id)) {
        rc_set_feedback("下车失败：没找到已锁定的载具（确认已部署）");
        log_msg("[RAYCAST] SEATER8 exit FAIL: no seater id\n");
        return;
    }
    /* v10.14: diagnose why command_queue_exit (0x636e50) silently returns -
     * it looks the seater id up in the hash table at mgr+0x20 (disasm:
     * [rcx+0x20] is the table pointer, [rcx+0x28] the count). Dump the
     * first 32 entries and the slot 0 state so we can see if 321 is there. */
    {
        uint64_t tab = 0;
        if (rc_safe_read64(mgr + 0x20, &tab) && tab >= 0x100000000ULL) {
            log_msg("[RAYCAST] SEATER8 exit-diag: hash@mgr+0x20=%llx\n",
                (unsigned long long)tab);
            for (int i = 0; i < 32; i++) {
                uint64_t e = 0;
                if (!rc_safe_read64(tab + (uint64_t)i * 8, &e)) break;
                if (e != 0 && e != 0xFFFFFFFFFFFFFFFFull && (e & 0xFFFFFFFFu) == seater_id) {
                    log_msg("[RAYCAST] SEATER8 exit-diag: FOUND seater %llu at entry %d (hi=0x%x)\n",
                        (unsigned long long)(e & 0xFFFFFFFFu), i, (unsigned)(e >> 32));
                }
            }
        } else {
            log_msg("[RAYCAST] SEATER8 exit-diag: no hash table at mgr+0x20 (mgr=%llx)\n",
                (unsigned long long)mgr);
        }
        /* slot 0 state - v10.31: full 0x40-byte slot (16 uint32). The unit
         * reference (player while boarded) lives in the back half, which the
         * old 9-field dump never showed. */
        uint64_t slots = 0;
        if (rc_safe_read64(mgr + 0x48, &slots) && slots >= 0x100000000ULL) {
            uint32_t q[16] = {0};
            int ok = 1;
            for (int j = 0; j < 16; j++)
                if (!rc_safe_read32(slots + (uint64_t)0 * 0x40 + j * 4, &q[j])) { ok = 0; break; }
            if (ok)
                log_msg("[RAYCAST] SEATER8 exit-diag: slot0=[0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x]\n",
                    q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7], q[8], q[9], q[10], q[11], q[12], q[13], q[14], q[15]);
            /* second slot (offset 0x40), first 8 fields - seat slots are
             * contiguous; the player occupies one of them. */
            {
                uint32_t s1[8] = {0};
                int ok1 = 1;
                for (int j = 0; j < 8; j++)
                    if (!rc_safe_read32(slots + 1 * 0x40 + j * 4, &s1[j])) { ok1 = 0; break; }
                if (ok1)
                    log_msg("[RAYCAST] SEATER8 exit-diag: slot1=[0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x]\n",
                        s1[0], s1[1], s1[2], s1[3], s1[4], s1[5], s1[6], s1[7]);
            }
        }
    }
    /* v10.35: exit APC restored (v10.32-34 had a dump-only temporary return
     * so the boarded slot state stayed intact for layout capture; collection
     * finished - full command_queue_exit path is live again). */
    static uint64_t apc_arg[4]; /* mgr, fn, seater_id, instant */
    apc_arg[0] = mgr;
    apc_arg[1] = gb + RC_RVA_EXIT_CMD;
    apc_arg[2] = seater_id;
    apc_arg[3] = 0;
    if (!queue_apc((PAPCFUNC)apc_exit_cmd, apc_arg, 4)) {
        rc_set_feedback("下车失败：命令没送进游戏线程");
        log_msg("[RAYCAST] SEATER8 exit-cmd APC queue FAILED\n");
        return;
    }
    rc_set_feedback("已锁定 FRV，发送下车指令");
    log_msg("[RAYCAST] SEATER8 exit-cmd queued: seater_id=%llu instant=0\n",
        (unsigned long long)seater_id);
}

static void f8_set_entering(unsigned int seat, unsigned int state) {
    HMODULE gdll = GetModuleHandleA("game.dll");
    if (!gdll) { log_msg("[RAYCAST] SEATER8 board FAIL: no game.dll\n"); return; }
    uint64_t gb = (uint64_t)(uintptr_t)gdll;

    uint64_t mgr = 0;
    if (!rc_safe_read64(gb + 0x276ca88, &mgr) || mgr < 0x100000000ULL) {
        rc_set_feedback("上车失败：找不到座位管理器");
        log_msg("[RAYCAST] SEATER8 board FAIL: no seater mgr\n");
        return;
    }
    uint64_t sc_id = 0;
    if (!find_frv_sc_id(&sc_id)) {
        rc_set_feedback("上车失败：没找到已锁定的载具（确认已部署）");
        log_msg("[RAYCAST] SEATER8 board FAIL: no seat_collection id\n");
        return;
    }

    /* seat name for humans: 3=driver, 2=gunner, 0/1=passenger */
    const char *seat_name;
    switch (state) {
        case 3:  seat_name = "驾驶位"; break;
        case 2:  seat_name = "炮手位"; break;
        case 0:  seat_name = "乘客位(中)"; break;
        case 1:  seat_name = "乘客位(后)"; break;
        default: seat_name = "未知座位"; break;
    }

    /* v10.22: 0x630810 operates on the SEAT_COLLECTION manager (it looks up
     * sc_id in the hash table), while 0x634120/0x633e50 take the SEATER
     * manager. The engine globals 0x276aa88/0x276aa98 were -1 in the dump
     * (uninitialized outside missions) and crashed at 0x630838 - use the
     * two known-good managers instead and log their runtime values. */
    uint64_t mgrA = 0, mgrB = 0;
    if (!rc_safe_read64(gb + 0x276ca98, &mgrA) || mgrA < 0x100000000ULL) {
        rc_set_feedback("上车失败：找不到座位管理器A");
        log_msg("[RAYCAST] SEATER8 board FAIL: no sc mgr @0x276ca98\n");
        return;
    }
    if (!rc_safe_read64(gb + 0x276ca88, &mgrB) || mgrB < 0x100000000ULL) {
        rc_set_feedback("上车失败：找不到座位管理器B");
        log_msg("[RAYCAST] SEATER8 board FAIL: no seater mgr @0x276ca88\n");
        return;
    }
    log_msg("[RAYCAST] SEATER8 mgrA(sc)=%llx mgrB(seater)=%llx\n",
        (unsigned long long)mgrA, (unsigned long long)mgrB);

    /* v10.19: full board in ONE APC: 0x630810 (state-prep) -> 0x634120
     * (set_entering, instant=1 like the engine) -> 0x633e50
     * (goto_node_with_action, node=-1, action). Mirrors the engine's own
     * caller (0x633358). */
    static uint64_t apc_arg[8];
    apc_arg[0] = mgrB;
    apc_arg[1] = gb + RC_RVA_SE_CMD;
    apc_arg[2] = gb + RC_RVA_GOTO_NA;
    apc_arg[3] = gb + RC_RVA_ACT810;
    apc_arg[4] = sc_id;
    apc_arg[5] = state;        /* entrance */
    apc_arg[6] = state;        /* action (entrance-based guess) */
    apc_arg[7] = mgrA;
    if (!queue_apc((PAPCFUNC)apc_board_full, apc_arg, 8)) {
        rc_set_feedback("上车失败：命令没送进游戏线程");
        log_msg("[RAYCAST] SEATER8 board-full APC queue FAILED\n");
        return;
    }
    rc_set_feedback("已锁定 FRV，发送上车指令（%s）", seat_name);
    log_msg("[RAYCAST] SEATER8 board queued: sc=%llu entrance=%u\n",
        (unsigned long long)sc_id, state);
}

/* v10.42: NPC board - find the first non-player seater object in the global
 * obj-arr (mgr+0x38) and issue set_entering for IT. obj-arr[0] is the player
 * (seat=0 in the player path); SEAF units register at obj[1..N] when they
 * spawn (verified: 2 SEAF squads -> +12 registrations). F4-lock the FRV
 * first (sc_id comes from find_frv_sc_id).
 * v10.43: enumerate ALL non-player candidates (seat/id/obj + object header
 * dump to locate the unit back-reference field), and cycle the entrance
 * (seat position) on each F3 press: 0=passenger(mid) -> 1=passenger(rear)
 * -> 3=driver -> 2=gunner. The first candidate is still the target, but the
 * full list tells us which units registered so we can pick SEAF precisely. */
static int g_npc_entrance = 0;
static void f8_npc_board(void) {
    HMODULE gdll = GetModuleHandleA("game.dll");
    if (!gdll) { log_msg("[RAYCAST] SEATER8 npc-board FAIL: no game.dll\n"); return; }
    uint64_t gb = (uint64_t)(uintptr_t)gdll;
    uint64_t mgrB = 0;
    if (!rc_safe_read64(gb + 0x276ca88, &mgrB) || mgrB < 0x100000000ULL) {
        rc_set_feedback("NPC上车失败：找不到座位管理器");
        log_msg("[RAYCAST] SEATER8 npc-board FAIL: no seater mgr\n");
        return;
    }
    uint64_t mgrA = 0;
    if (!rc_safe_read64(gb + 0x276ca98, &mgrA) || mgrA < 0x100000000ULL) {
        rc_set_feedback("NPC上车失败：找不到座位集合管理器");
        log_msg("[RAYCAST] SEATER8 npc-board FAIL: no sc mgr\n");
        return;
    }
    uint64_t sc_id = 0;
    if (!find_frv_sc_id(&sc_id)) {
        rc_set_feedback("NPC上车失败：没找到载具（F4锁定FRV）");
        log_msg("[RAYCAST] SEATER8 npc-board FAIL: no seat_collection id\n");
        return;
    }
    /* scan obj-arr (mgr+0x38) for the first non-player non-empty object */
    uint64_t objs = 0;
    if (!rc_safe_read64(mgrB + 0x38, &objs) || objs < 0x100000000ULL) {
        rc_set_feedback("NPC上车失败：无对象数组");
        log_msg("[RAYCAST] SEATER8 npc-board FAIL: no obj-arr\n");
        return;
    }
    /* player id = obj[0]+8 low32 (existing find_frv_seater_id reads obj[0]) */
    uint64_t o0 = 0;
    if (!rc_safe_read64(objs, &o0) || o0 < 0x100000000ULL) {
        rc_set_feedback("NPC上车失败：玩家对象缺失");
        log_msg("[RAYCAST] SEATER8 npc-board FAIL: obj[0] missing\n");
        return;
    }
    uint64_t q0 = 0;
    rc_safe_read64(o0 + 8, &q0);
    uint32_t player_id = q0 & 0xFFFFFFFF;
    log_msg("[RAYCAST] SEATER8 npc-board: player obj[0] id=0x%x\n", player_id);
    /* v10.43: enumerate ALL non-player candidates, dump each object header */
    int seat = -1;
    int listed = 0;
    for (int i = 1; i < 64; i++) {
        uint64_t o = 0;
        if (!rc_safe_read64(objs + (uint64_t)i * 8, &o) || o < 0x100000000ULL) continue;
        uint64_t q1 = 0;
        if (!rc_safe_read64(o + 8, &q1)) continue;
        uint32_t id = q1 & 0xFFFFFFFF;
        if (id == 0 || id == 0xFFFFFFFF || id == player_id) continue;
        /* dump object header (8 qwords) to find unit back-reference */
        uint64_t hdr[8] = {0};
        int okh = 1;
        for (int j = 0; j < 8; j++)
            if (!rc_safe_read64(o + (uint64_t)j * 8, &hdr[j])) { okh = 0; break; }
        log_msg("[RAYCAST] SEATER8 npc-board: cand seat=%02d obj=%llx id=0x%x hdr=[%llx %llx %llx %llx | %llx %llx %llx %llx]%s\n",
            i, (unsigned long long)o, id,
            (unsigned long long)hdr[0], (unsigned long long)hdr[1],
            (unsigned long long)hdr[2], (unsigned long long)hdr[3],
            (unsigned long long)hdr[4], (unsigned long long)hdr[5],
            (unsigned long long)hdr[6], (unsigned long long)hdr[7],
            okh ? "" : " (hdr read fail)");
        if (seat < 0) seat = i;
        listed++;
        if (listed >= 12) break; /* enough for SEAF squads */
    }
    if (seat < 0) {
        rc_set_feedback("NPC上车失败：没找到非玩家单位（SEAF需已刷出）");
        log_msg("[RAYCAST] SEATER8 npc-board FAIL: no non-player obj (SEAF not spawned?)\n");
        return;
    }
    /* v10.43: cycle entrance on each press */
    static const int ent_cycle[] = {0, 1, 3, 2};
    int entrance = ent_cycle[g_npc_entrance % 4];
    g_npc_entrance++;
    static const char *ent_name[] = {"乘客位(中)", "乘客位(后)", "驾驶位", "炮手位"};
    static uint64_t apc_arg[9];
    apc_arg[0] = mgrB;
    apc_arg[1] = gb + RC_RVA_SE_CMD;
    apc_arg[2] = gb + RC_RVA_GOTO_NA;
    apc_arg[3] = gb + RC_RVA_ACT810;
    apc_arg[4] = sc_id;
    apc_arg[5] = (uint64_t)seat;   /* obj-arr index = seat */
    apc_arg[6] = (uint64_t)entrance; /* entrance: seat position */
    apc_arg[7] = (uint64_t)entrance; /* action (mirror player path guess) */
    apc_arg[8] = mgrA;
    if (!queue_apc((PAPCFUNC)apc_npc_board, apc_arg, 9)) {
        rc_set_feedback("NPC上车失败：命令没送进游戏线程");
        log_msg("[RAYCAST] SEATER8 npc-board APC queue FAILED\n");
        return;
    }
    rc_set_feedback("NPC上车指令已发送（seat=%d %s）", seat, ent_name[g_npc_entrance % 4]);
    log_msg("[RAYCAST] SEATER8 npc-board queued: seat=%d sc=%llu entrance=%u(%s)\n",
        seat, (unsigned long long)sc_id, entrance, ent_name[g_npc_entrance % 4]);
}

/* v10.45: NPC slot-write (bypass the command vtable - set_entering crashes
 * for SEAF because the command context binds the PLAYER unit, verified at
 * helldivers2.exe rva=0x9a1e8d). Directly write the seat slot + hash entry:
 *   - hash index = (seater_id * 2) & 0x1FF   (verified against 14 captures)
 *   - hash entry = (slot << 32) | seater_id   (open addressing, 0x200 cap)
 *   - slot[seat] 0x40 bytes: sc_id/seater_idx/role/node/entrance...
 * The seater object (obj-arr[seat]) must have id == seater_id for the
 * engine to accept the slot state (obj-arr index == slot index). We pick a
 * FREE slot (sc_id==0) so we don't clobber the player's occupied slot 0. */
static void f8_npc_slotwrite(void) {
    HMODULE gdll = GetModuleHandleA("game.dll");
    if (!gdll) { log_msg("[RAYCAST] SEATER8 slotwrite FAIL: no game.dll\n"); return; }
    uint64_t gb = (uint64_t)(uintptr_t)gdll;
    uint64_t mgr = 0;
    if (!rc_safe_read64(gb + 0x276ca88, &mgr) || mgr < 0x100000000ULL) {
        rc_set_feedback("槽直写失败：找不到座位管理器");
        return;
    }
    uint64_t sc_id = 0;
    if (!find_frv_sc_id(&sc_id)) {
        rc_set_feedback("槽直写失败：没找到载具（F4锁定FRV）");
        return;
    }
    /* 1. find a SEAF object: obj-arr object header hdr[0] == SEAF hash
     * 0x75f7e96af7dcd303 (verified: SEAF units store their resource hash at
     * object+0). Skip obj[0] (player). */
    uint64_t objs = 0;
    if (!rc_safe_read64(mgr + 0x38, &objs) || objs < 0x100000000ULL) {
        rc_set_feedback("槽直写失败：无对象数组");
        return;
    }
    uint64_t o0 = 0;
    if (!rc_safe_read64(objs, &o0) || o0 < 0x100000000ULL) {
        rc_set_feedback("槽直写失败：玩家对象缺失");
        return;
    }
    uint64_t q0 = 0;
    rc_safe_read64(o0 + 8, &q0);
    uint32_t player_id = q0 & 0xFFFFFFFF;
    int seaf_seat = -1;
    uint64_t seaf_obj = 0;
    uint32_t seaf_id = 0;
    for (int i = 1; i < 64; i++) {
        uint64_t o = 0;
        if (!rc_safe_read64(objs + (uint64_t)i * 8, &o) || o < 0x100000000ULL) continue;
        uint64_t h0 = 0, q1 = 0;
        if (!rc_safe_read64(o, &h0)) continue;
        if (h0 != 0x75f7e96af7dcd303ULL) continue;  /* SEAF resource hash */
        if (!rc_safe_read64(o + 8, &q1)) continue;
        uint32_t id = q1 & 0xFFFFFFFF;
        if (id == 0 || id == 0xFFFFFFFF || id == player_id) continue;
        seaf_seat = i; seaf_obj = o; seaf_id = id;
        break;
    }
    if (seaf_seat < 0) {
        rc_set_feedback("槽直写失败：没找到SEAF本体（需已刷出）");
        log_msg("[RAYCAST] SEATER8 slotwrite FAIL: no SEAF obj (hdr[0]!=SEAF hash)\n");
        return;
    }
    log_msg("[RAYCAST] SEATER8 slotwrite: SEAF seat=%d obj=%llx id=0x%x\n",
        seaf_seat, (unsigned long long)seaf_obj, seaf_id);
    /* 2. find a free slot: slot array (mgr+0x48), sc_id==0 (not occupied).
     * Skip seat 0 (player driver). We need the SEAF's obj index == slot
     * index, so prefer a slot whose obj-arr entry id==0 or matches a SEAF. */
    uint64_t slots = 0;
    if (!rc_safe_read64(mgr + 0x48, &slots) || slots < 0x100000000ULL) {
        rc_set_feedback("槽直写失败：无槽数组");
        return;
    }
    int target_slot = -1;
    for (int s = 1; s < 8; s++) {
        uint32_t sc0 = 0;
        if (!rc_safe_read32(slots + (uint64_t)s * 0x40, &sc0)) break;
        if (sc0 == 0) { target_slot = s; break; }
    }
    if (target_slot < 0) {
        rc_set_feedback("槽直写失败：没有空闲槽");
        return;
    }
    /* seat the SEAF at target_slot: the engine reads obj-arr[target_slot]
     * for the seater_id; if that obj is empty (id 0) we must put the SEAF
     * object there too. Simplest consistent approach: place the SEAF at
     * target_slot by writing its id into the slot AND (if the obj at that
     * index is empty) moving the obj pointer. */
    log_msg("[RAYCAST] SEATER8 slotwrite: target_slot=%d\n", target_slot);
    /* 3. hash entry: index = (seaf_id * 2) & 0x1FF, value = (slot<<32)|id */
    uint64_t htab = 0;
    if (!rc_safe_read64(mgr + 0x20, &htab) || htab < 0x100000000ULL) {
        rc_set_feedback("槽直写失败：无 hash 表");
        return;
    }
    uint64_t hindex = ((uint64_t)seaf_id * 2) & 0x1FF;
    uint64_t hval = ((uint64_t)target_slot << 32) | (uint64_t)seaf_id;
    /* write hash entry */
    uint64_t old_h = 0;
    rc_safe_read64(htab + hindex * 8, &old_h);
    /* WriteMemory for game process - we are inside the injected DLL so
     * plain stores work (same process). */
    *(volatile uint64_t *)(htab + hindex * 8) = hval;
    log_msg("[RAYCAST] SEATER8 slotwrite: hash[0x%llx] 0x%llx -> 0x%llx\n",
        (unsigned long long)hindex, (unsigned long long)old_h, (unsigned long long)hval);
    /* 4. write slot data (passenger template, from verified captures):
     * [sc_id seater_idx role node entrance 0x14 -1 0x1c -1 ...] */
    uint32_t slotw[16] = {0};
    slotw[0] = (uint32_t)sc_id;         /* sc_id */
    slotw[1] = 0x1a;                    /* seater_idx (FRV constant) */
    slotw[2] = 0x03;                    /* role = passenger */
    slotw[3] = 0x03;                    /* node */
    slotw[4] = 0x00;                    /* entrance = passenger(mid) */
    slotw[5] = 0x02;                    /* +0x14 marker seen in captures */
    slotw[6] = 0xFFFFFFFF;              /* -1 marker */
    slotw[7] = 0x02;                    /* +0x1c marker */
    slotw[8] = 0xFFFFFFFF;              /* -1 */
    /* rest zeros */
    for (int j = 0; j < 16; j++)
        *(volatile uint32_t *)(slots + (uint64_t)target_slot * 0x40 + (uint64_t)j * 4) = slotw[j];
    log_msg("[RAYCAST] SEATER8 slotwrite: slot[%d] written [%x %x %x %x %x %x %x %x %x ...]\n",
        target_slot, slotw[0], slotw[1], slotw[2], slotw[3], slotw[4],
        slotw[5], slotw[6], slotw[7], slotw[8]);
    /* 5. ensure obj-arr[target_slot] points at the SEAF object (engine reads
     * obj-arr[seat] for the seater id when processing the slot) */
    uint64_t old_obj = 0;
    rc_safe_read64(objs + (uint64_t)target_slot * 8, &old_obj);
    if (old_obj != seaf_obj) {
        *(volatile uint64_t *)(objs + (uint64_t)target_slot * 8) = seaf_obj;
        log_msg("[RAYCAST] SEATER8 slotwrite: obj-arr[%d] %llx -> %llx\n",
            target_slot, (unsigned long long)old_obj, (unsigned long long)seaf_obj);
    }
    rc_set_feedback("槽直写完成：SEAF->seat=%d", target_slot);
    log_msg("%s", "[RAYCAST] SEATER8 slotwrite DONE\n");
}

/* v10.46: NPC passenger pin (animation anchor). F4-lock the SEAF once (the
 * probe auto-stores it in _G.rc_seaf_unit by hash) and F4-lock the FRV once
 * (auto-stored in _G.rc_frv_unit). Then this key pins the SEAF onto the FRV
 * passenger seat using the seat anchor offset + teleport each tick. No full
 * scan in the tick (zero traversal, only the two locked units). */
static int g_npc_pin_active = 0;
/* v10.51: current pin-tick stage (0=idle 1=pose 2=xform 3=teleport 4=anim).
 * Written by the C tick loop before each stage's exec_lua so the SEH
 * handler can attribute a crash to the exact API call.
 * (g_pin_stage itself is forward-declared near the top of the file.) */
/* v10.50: C-side cache of the F4-hit unit indices (parsed from the rn hash
 * in do_raycast). The Lua-side string match (_G.rc_seaf_unit) never fired
 * because tostring(IdString64) format differs between engines; C already
 * parses "#ID[<hex>]" reliably (track armed key proves it), so we cache the
 * entity index here and re-fetch the unit from _G.rc_ents on F3. */
static int g_seaf_idx = -1;
static int g_frv_idx = -1;
static uint64_t g_seaf_key = 0;
static uint64_t g_frv_key = 0;
#define SEAF_HASH 0x75f7e96af7dcd303ULL
#define FRV_HASH  0xcc21c7ffd3ebefb9ULL
static void npc_pin_define(void) {
    exec_lua(
        "if _G.rc_pin_def then return 'def' end\n"
        "_G.rc_pin_def = true\n"
        "local S = stingray\n"
        "_G.rc_pin = nil\n"
        "_G.rc_pin_arm = function()\n"
        "  local seaf = _G.rc_seaf_unit\n"
        "  local frv = _G.rc_frv_unit\n"
        "  if not seaf then return 'no SEAF (F4-lock a SEAF first)' end\n"
        "  if not frv then return 'no FRV (F4-lock the FRV)' end\n"
        "  _G.rc_pin = { npc = seaf, frv = frv, t = 0 }\n"
        "  return 'pin armed (SEAF+FRV locked)'\n"
        "end\n"
        "_G.rc_pin_tick = function()\n"
        "  local p = _G.rc_pin\n"
        "  if not p then return end\n"
        "  p.t = (p.t or 0) + 1\n"
        "  local okp, pose = pcall(S.Unit.world_pose, p.frv)\n"
        "  if not okp or not pose then return end\n"
        "  -- passenger seat anchor (rear-left), in FRV local space\n"
        "  local okv, v = pcall(S.Matrix4x4.transform, pose, S.Vector3(1.18, -1.6, 0.935))\n"
        "  if okv and v and v.x then\n"
        "    pcall(S.Unit.teleport_local_position, p.npc, S.Vector3(v.x, v.y + 0.0, v.z))\n"
        "  end\n"
        "  if p.t == 3 then\n"
        "    for _, an in ipairs({'content/fac_helldivers/vehicles/frv/animation/idle_back_left',\n"
        "                         'content/fac_helldivers/vehicles/frv/animation/idle'}) do\n"
        "      local ok, e = pcall(S.Unit.play_simple_animation, p.npc, an)\n"
        "      if ok and not e then break end\n"
        "    end\n"
        "  end\n"
        "  return 'pin tick'\n"
        "end\n"
        "_G.rc_pin_clear = function() _G.rc_pin = nil return 'pin cleared' end\n"
        "return 'pin def'"
    );
}
static void f8_npc_pin(void) {
    npc_pin_define();
    if (g_npc_pin_active) {
        exec_lua("return _G.rc_pin_clear()");
        log_msg("[RAYCAST] pin: %s\n", g_last_result[0] ? g_last_result : "?");
        g_npc_pin_active = 0;
    } else {
        /* v10.50: C-side cache takes priority - re-fetch the unit from the
         * current entity array by cached index (the Lua string-match cache
         * _G.rc_seaf_unit never fired). If the indices are stale (entities
         * changed since the F4 scan), report it instead of failing silently. */
        char precmd[320];
        int pc_ok = 0;
        if (g_seaf_idx >= 0 || g_frv_idx >= 0) {
            /* Only set a global when the corresponding index is valid, so a
             * negative index (no cache) can never alias entity [0] (self). */
            if (g_seaf_idx >= 0 && g_frv_idx >= 0) {
                snprintf(precmd, sizeof(precmd),
                    "local e = _G.rc_ents "
                    "if not e then return 'no-ents' end "
                    "local seaf = e[%d] "
                    "local frv = e[%d] "
                    "if %d >= 0 and not seaf then return 'stale-seaf' end "
                    "if %d >= 0 and not frv then return 'stale-frv' end "
                    "if %d >= 0 then _G.rc_seaf_unit = seaf end "
                    "if %d >= 0 then _G.rc_frv_unit = frv end "
                    "return 'idx-ok'",
                    g_seaf_idx, g_frv_idx, g_seaf_idx, g_frv_idx, g_seaf_idx, g_frv_idx);
            } else if (g_seaf_idx >= 0) {
                snprintf(precmd, sizeof(precmd),
                    "local e = _G.rc_ents "
                    "if not e then return 'no-ents' end "
                    "local seaf = e[%d] "
                    "if %d >= 0 and not seaf then return 'stale-seaf' end "
                    "if %d >= 0 then _G.rc_seaf_unit = seaf end "
                    "return 'idx-ok'",
                    g_seaf_idx, g_seaf_idx, g_seaf_idx);
            } else {
                snprintf(precmd, sizeof(precmd),
                    "local e = _G.rc_ents "
                    "if not e then return 'no-ents' end "
                    "local frv = e[%d] "
                    "if %d >= 0 and not frv then return 'stale-frv' end "
                    "if %d >= 0 then _G.rc_frv_unit = frv end "
                    "return 'idx-ok'",
                    g_frv_idx, g_frv_idx, g_frv_idx);
            }
            exec_lua(precmd);
            pc_ok = (strcmp(g_last_result, "idx-ok") == 0);
            if (!pc_ok)
                log_msg("[RAYCAST] pin precache: %s (seaf=%d frv=%d)\n",
                    g_last_result[0] ? g_last_result : "?", g_seaf_idx, g_frv_idx);
        }
        if (!pc_ok && g_seaf_idx < 0 && g_frv_idx < 0) {
            /* no C cache at all - fall back to the Lua globals (may be nil) */
        }
        exec_lua("return _G.rc_pin_arm()");
        log_msg("[RAYCAST] pin: %s (seaf_idx=%d frv_idx=%d)\n",
            g_last_result[0] ? g_last_result : "?",
            g_seaf_idx, g_frv_idx);
        g_npc_pin_active = (g_last_result[0] == 'p'); /* 'pin armed' */
    }
}

static void probe_all_stingray_apis(void) {
    log_msg("%s", "[RAYCAST] === F10: Comprehensive stingray API scan ===\n");    
    // 1. Recursively scan ALL stingray subtables for raycast/physics keywords
    exec_lua(
        "local S = stingray\n"
        "if not S then return 'no stingray' end\n"
        "local results = {}\n"
        "local keywords = {'ray', 'cast', 'phys', 'pick', 'trace', 'sweep', 'overlap', 'collide', 'broad', 'query'}\n"
        "local function match_kw(name)\n"
        "  local lower = name:lower()\n"
        "  for _, kw in ipairs(keywords) do\n"
        "    if lower:find(kw) then return true end\n"
        "  end\n"
        "  return false\n"
        "end\n"
        "for k, v in pairs(S) do\n"
        "  if type(v) == 'table' then\n"
        "    for k2, v2 in pairs(v) do\n"
        "      if type(k2) == 'string' and match_kw(k2) then\n"
        "        table.insert(results, k..'.'..k2..'('..type(v2)..')')\n"
        "      end\n"
        "    end\n"
        "    -- Also check __index metatable\n"
        "    local mt = getmetatable(v)\n"
        "    if mt and mt.__index and type(mt.__index) == 'table' then\n"
        "      for k2, v2 in pairs(mt.__index) do\n"
        "        if type(k2) == 'string' and match_kw(k2) then\n"
        "          table.insert(results, k..'(mt).'..k2..'('..type(v2)..')')\n"
        "        end\n"
        "      end\n"
        "    end\n"
        "  end\n"
        "end\n"
        "table.sort(results)\n"
        "return 'Found '..#results..' matches: '..table.concat(results, ' | ')\n"
    );
    
    // 2. Try specific physics/raycast API calls
    exec_lua(
        "local S = stingray\n"
        "local w = S.Application.main_world()\n"
        "local M = S.Matrix4x4\n"
        "local pose = S.World.debug_camera_pose(w)\n"
        "local cam = M.translation(pose)\n"
        "local fwd = M.forward(pose)\n"
        "local V3 = S.Vector3\n"
        "local results = {}\n"
        "-- Try World.physics_world\n"
        "local ok, pw = pcall(S.World.physics_world, w)\n"
        "if ok and pw then table.insert(results, 'World.physics_world='..type(pw))\n"
        "else table.insert(results, 'World.physics_world err='..tostring(pw)) end\n"
        "-- Try World.raycast\n"
        "local ok2, r2 = pcall(S.World.raycast, w, cam, fwd, 100)\n"
        "if ok2 and r2 then table.insert(results, 'World.raycast='..type(r2))\n"
        "else table.insert(results, 'World.raycast err='..tostring(r2)) end\n"
        "-- Try PhysicsWorld\n"
        "if S.PhysicsWorld then\n"
        "  local ok3, r3 = pcall(S.PhysicsWorld.raycast, pw, cam, fwd, 100)\n"
        "  if ok3 and r3 then table.insert(results, 'PW.raycast='..type(r3))\n"
        "  else table.insert(results, 'PW.raycast err='..tostring(r3)) end\n"
        "end\n"
        "-- Try stingray.World.find_units with ray\n"
        "local ok4, r4 = pcall(S.World.find_units, w, 'ray', cam, fwd, 100)\n"
        "if ok4 and type(r4) == 'table' then table.insert(results, 'find_units(ray)='..#r4)\n"
        "else table.insert(results, 'find_units(ray) err='..tostring(r4)) end\n"
        "-- Try World.find_units_intersecting with Ray\n"
        "local ok5, r5 = pcall(S.World.find_units_intersecting, w, cam, fwd, 100)\n"
        "if ok5 and type(r5) == 'table' then table.insert(results, 'fui(ray)='..#r5)\n"
        "else table.insert(results, 'fui(ray) err='..tostring(r5)) end\n"
        "return table.concat(results, ' | ')\n"
    );
    
    // 3. Dump ALL World and Unit function names (complete list)
    exec_lua(
        "local S = stingray\n"
        "local w = S.Application.main_world()\n"
        "-- List all World methods\n"
        "local wfns = {}\n"
        "for k, v in pairs(S.World) do\n"
        "  table.insert(wfns, k..'('..type(v)..')')\n"
        "end\n"
        "table.sort(wfns)\n"
        "-- List all Unit methods\n"
        "local ufns = {}\n"
        "for k, v in pairs(S.Unit) do\n"
        "  table.insert(ufns, k..'('..type(v)..')')\n"
        "end\n"
        "table.sort(ufns)\n"
        "-- Check for world_position, world_pose, node_world_position\n"
        "local wp = S.Unit.world_position and 'yes' or 'no'\n"
        "local wps = S.Unit.world_pose and 'yes' or 'no'\n"
        "local nwp = S.Unit.node_world_position and 'yes' or 'no'\n"
        "return 'Unit.world_position='..wp..' world_pose='..wps..' node_world_position='..nwp\n"
        "  ..'\\nWorld['..#wfns..']: '..table.concat(wfns, ', ')\n"
        "  ..'\\nUnit['..#ufns..']: '..table.concat(ufns, ', ')\n"
    );
    
    log_msg("%s", "[RAYCAST] === F10 scan complete ===\n");
}

// ============================================================
// Raycast signature probe (F12) - verify Unit.box and
// Math.ray_box_intersection signatures via debug.getinfo
// and trial calls. No guessing: everything is measured.
// ============================================================
static void probe_raycast_signatures(void) {
    log_msg("%s", "[RAYCAST] === F12: raycast signature probe ===\n");

    // 1. nparams via debug.getinfo (Lua 5.1 supports 'u' option)
    exec_lua(
        "local S = stingray\n"
        "local parts = {}\n"
        "local ok, di = pcall(debug.getinfo, S.Math.ray_box_intersection, 'u')\n"
        "if ok and di then\n"
        "  parts[#parts+1] = 'rbi nparams='..tostring(di.nparams)..' vararg='..tostring(di.isvararg)\n"
        "else parts[#parts+1] = 'rbi getinfo FAIL: '..tostring(di) end\n"
        "local ok2, di2 = pcall(debug.getinfo, S.Unit.box, 'u')\n"
        "if ok2 and di2 then\n"
        "  parts[#parts+1] = 'Unit.box nparams='..tostring(di2.nparams)..' vararg='..tostring(di2.isvararg)\n"
        "else parts[#parts+1] = 'Unit.box getinfo FAIL: '..tostring(di2) end\n"
        "return table.concat(parts, ' | ')\n"
    );

    // 2. Unit.box return structure on a real unit (no guessing)
    exec_lua(
        "local S = stingray\n"
        "local w = S.Application.main_world()\n"
        "local ok, ents = pcall(S.World.entities, w)\n"
        "if not ok or type(ents) ~= 'table' or #ents == 0 then return 'no entities' end\n"
        "local u\n"
        "for i = 1, #ents do\n"
        "  local oka, a = pcall(S.Unit.alive, ents[i])\n"
        "  if oka and a then u = ents[i] break end\n"
        "end\n"
        "if not u then return 'no alive unit' end\n"
        "local okb, b1, b2 = pcall(S.Unit.box, u)\n"
        "if not okb then return 'Unit.box CALL FAIL: '..tostring(b1) end\n"
        "local parts = {'r1='..type(b1)..' r2='..type(b2)}\n"
        "local function probe(o, tag)\n"
        "  if type(o) ~= 'userdata' then parts[#parts+1] = tag..'='..type(o) return end\n"
        "  local mt = getmetatable(o)\n"
        "  parts[#parts+1] = tag..' mt='..tostring(mt and mt._name or '?')\n"
        "  local okm, m = pcall(function() return o.min end)\n"
        "  if okm and m then parts[#parts+1] = tag..'.min='..type(m)..' '..tostring(m)\n"
        "  else parts[#parts+1] = tag..'.min=nil/ERR' end\n"
        "  local okx, x = pcall(function() return o.x end)\n"
        "  parts[#parts+1] = tag..'.x='..(okx and tostring(x) or 'ERR')\n"
        "  local oki, i1 = pcall(function() return o[1] end)\n"
        "  parts[#parts+1] = tag..'[1]='..(oki and tostring(i1) or 'ERR')\n"
        "end\n"
        "probe(b1, 'b1')\n"
        "if type(b2) == 'userdata' then probe(b2, 'b2') end\n"
        "return table.concat(parts, ' | ')\n"
    );

    // 3. Slab-method self-test on synthetic box (no engine call, no crash)
    exec_lua(
        "local function slab(ox,oy,oz, dx,dy,dz, minx,miny,minz, maxx,maxy,maxz)\n"
        "  local tmin = -1e30\n"
        "  local tmax = 1e30\n"
        "  local ok = true\n"
        "  if dx ~= 0 then\n"
        "    local t1 = (minx - ox) / dx; local t2 = (maxx - ox) / dx\n"
        "    if t1 > t2 then t1, t2 = t2, t1 end\n"
        "    if t1 > tmin then tmin = t1 end\n"
        "    if t2 < tmax then tmax = t2 end\n"
        "  elseif ox < minx or ox > maxx then ok = false end\n"
        "  if ok and dy ~= 0 then\n"
        "    local t1 = (miny - oy) / dy; local t2 = (maxy - oy) / dy\n"
        "    if t1 > t2 then t1, t2 = t2, t1 end\n"
        "    if t1 > tmin then tmin = t1 end\n"
        "    if t2 < tmax then tmax = t2 end\n"
        "  elseif ok and (oy < miny or oy > maxy) then ok = false end\n"
        "  if ok and dz ~= 0 then\n"
        "    local t1 = (minz - oz) / dz; local t2 = (maxz - oz) / dz\n"
        "    if t1 > t2 then t1, t2 = t2, t1 end\n"
        "    if t1 > tmin then tmin = t1 end\n"
        "    if t2 < tmax then tmax = t2 end\n"
        "  elseif ok and (oz < minz or oz > maxz) then ok = false end\n"
        "  if not ok or tmax < tmin or tmax <= 0 then return nil end\n"
        "  return tmin\n"
        "end\n"
        "-- origin(0,0,0) dir(0,0,1) box z=5..7 x=-1..1 y=-1..1 -> expect 5\n"
        "local d1 = slab(0,0,0, 0,0,1, -1,-1,5, 1,1,7)\n"
        "-- box behind camera z=-7..-5 -> expect nil\n"
        "local d2 = slab(0,0,0, 0,0,1, -1,-1,-7, 1,1,-5)\n"
        "-- ray pointing away -> expect nil\n"
        "local d3 = slab(0,0,0, 0,0,-1, -1,-1,5, 1,1,7)\n"
        "return 'hit5='..tostring(d1)..' behind='..tostring(d2)..' away='..tostring(d3)\n"
    );

    // 4. World-box audit: local_position(unit,0) primary vs camera vs size.
    exec_lua(
        "local S = stingray\n"
        "local w = S.Application.main_world()\n"
        "local ents = S.World.entities(w)\n"
        "local M = S.Matrix4x4\n"
        "local pose_cam = S.World.debug_camera_pose(w)\n"
        "local cam = M.translation(pose_cam)\n"
        "local out = {}\n"
        "out[#out+1] = 'cam=('..string.format('%.1f',cam.x)..','..string.format('%.1f',cam.y)..','..string.format('%.1f',cam.z)..')'\n"
        "local counted = 0\n"
        "for i = 1, #ents do\n"
        "  if counted >= 5 then break end\n"
        "  local oka, a = pcall(S.Unit.alive, ents[i])\n"
        "  if oka and a then\n"
        "    local okb, b1, b2 = pcall(S.Unit.box, ents[i])\n"
        "    if okb and b1 then\n"
        "      local okp, lp = pcall(S.Unit.local_position, ents[i], 0)\n"
        "      if okp and lp then\n"
        "        out[#out+1] = 'u'..i..' lp=('..string.format('%.1f',lp.x)..','..string.format('%.1f',lp.y)..','..string.format('%.1f',lp.z)..') s=('..string.format('%.1f',b2.x)..','..string.format('%.1f',b2.y)..','..string.format('%.1f',b2.z)..')'\n"
        "        counted = counted + 1\n"
        "      end\n"
        "    end\n"
        "  end\n"
        "end\n"
        "return table.concat(out, ' | ')\n"
    );

    // 5. IdString32 probe: how to build 32-bit ID from path for Excel match
    exec_lua(
        "local S = stingray\n"
        "local w = S.Application.main_world()\n"
        "local ents = S.World.entities(w)\n"
        "local u\n"
        "for i = 1, #ents do\n"
        "  local oka, a = pcall(S.Unit.alive, ents[i])\n"
        "  if oka and a then u = ents[i] break end\n"
        "end\n"
        "if not u then return 'no unit' end\n"
        "local out = {}\n"
        "local okd, dn = pcall(S.Unit.debug_name, u)\n"
        "out[#out+1] = 'debug_name='..tostring(dn)\n"
        "local okr, rn = pcall(S.Unit.resource_name, u)\n"
        "out[#out+1] = 'resource_name='..tostring(rn)\n"
        "out[#out+1] = 'IdString32='..type(S.IdString32)\n"
        "if type(S.IdString32) == 'table' then\n"
        "  local ms = {}\n"
        "  for k, v in pairs(S.IdString32) do ms[#ms+1] = k..'='..type(v) end\n"
        "  table.sort(ms)\n"
        "  out[#out+1] = 'methods='..table.concat(ms, ',')\n"
        "  local okc, c = pcall(function() return S.IdString32('test_path') end)\n"
        "  out[#out+1] = 'call(path)='..tostring(c)\n"
        "elseif type(S.IdString32) == 'function' then\n"
        "  local okc, c = pcall(S.IdString32, 'test_path')\n"
        "  out[#out+1] = 'fn(path)='..tostring(c)\n"
        "end\n"
        "return table.concat(out, ' | ')\n"
    );
}

// ============================================================
// Hash lookup table loaded from 哈希对照表.txt (generated offline
// from Excel + HD2SDK friendlynames). Used to name hashes in-game.
// ============================================================
typedef struct { uint64_t hash; char name[160]; } HashEntry;
static HashEntry g_htab[32768];
static int g_htab_count = 0;

static int htab_cmp(const void *a, const void *b) {
    uint64_t ha = ((const HashEntry *)a)->hash;
    uint64_t hb = ((const HashEntry *)b)->hash;
    return (ha < hb) ? -1 : (ha > hb) ? 1 : 0;
}

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
static void setup_present_hook(void);
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
// Numpad2 - IdString64 table scan (Plan B): scan process memory for
// "#ID[<16hex>]" strings (Stingray hash<->debug-name table) and
// dump unique hashes + following path text to idstring_dump.txt.
// Runs on a SEPARATE thread so the game is never blocked.
// ============================================================
static DWORD WINAPI idstring_scan_thread(LPVOID arg) {
    (void)arg;
    log_msg("%s", "[RAYCAST] IdString scan thread started\n");
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *addr = NULL;
    int found = 0;
    static uint64_t seen[8192];
    int seen_count = 0;

    FILE *out = fopen(RC_DIR "idstring_dump.txt", "w");
    if (!out) {
        log_msg("%s", "[RAYCAST] Cannot open idstring_dump.txt\n");
        return 0;
    }

    int pages = 0;
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) && pages < 2000000) {
        pages++;
        // Only readable DATA pages (skip code/executable regions - much faster,
        // #ID[] strings live in data/heap). SEH protects against rare race.
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 64 &&
            (mbi.Protect & 0x100) == 0 &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY))) {
            uint8_t *base = (uint8_t *)mbi.BaseAddress;
            size_t size = mbi.RegionSize;
            __try {
                for (size_t i = 0; i + 24 < size; i++) {
                    // "#ID[" = 0x23 0x49 0x44 0x5B
                    if (base[i] == 0x23 && base[i + 1] == 0x49 &&
                        base[i + 2] == 0x44 && base[i + 3] == 0x5B) {
                        uint64_t h = 0;
                        int hx = 0;
                        for (int k = 0; k < 16 && i + 4 + k < size; k++) {
                            char c = (char)base[i + 4 + k];
                            if (c >= '0' && c <= '9')       { h = (h << 4) | (c - '0'); hx++; }
                            else if (c >= 'a' && c <= 'f')  { h = (h << 4) | (c - 'a' + 10); hx++; }
                            else if (c >= 'A' && c <= 'F')  { h = (h << 4) | (c - 'A' + 10); hx++; }
                            else break;
                        }
                        if (hx == 16 && i + 4 + 16 < size && base[i + 4 + 16] == ']') {
                            char path[128];
                            int pl = 0;
                            size_t j = i + 4 + 16 + 1;
                            while (j < size && pl < 127 && base[j] >= 0x20 && base[j] < 0x7f) {
                                path[pl++] = (char)base[j++];
                            }
                            path[pl] = 0;
                            int dup = 0;
                            for (int s = 0; s < seen_count; s++) {
                                if (seen[s] == h) { dup = 1; break; }
                            }
                            if (!dup && seen_count < 8192) {
                                seen[seen_count++] = h;
                                fprintf(out, "0x%016llx %s\n", (unsigned long long)h, path);
                                found++;
                            }
                        }
                    }
                }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    // page raced with unmap - skip rest of this page
                }
            }
        addr = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uint8_t *)mbi.BaseAddress) break;
    }
    fclose(out);
    log_msg("[RAYCAST] IdString scan done: %d unique entries -> idstring_dump.txt\n", found);
    return 0;
}

static void scan_idstring_table(void) {
    // Fire-and-forget: scan on a separate thread, game stays responsive
    static volatile LONG g_scan_running = 0;
    if (InterlockedCompareExchange(&g_scan_running, 1, 0) != 0) {
        log_msg("%s", "[RAYCAST] IdString scan already running, skip\n");
        return;
    }
    HANDLE h = CreateThread(NULL, 0, idstring_scan_thread, NULL, 0, NULL);
    if (h) {
        CloseHandle(h);
        log_msg("%s", "[RAYCAST] IdString scan started on background thread\n");
    } else {
        InterlockedExchange(&g_scan_running, 0);
        log_msg("%s", "[RAYCAST] Failed to start scan thread\n");
    }
}

// ============================================================
// Numpad6 - Path hash-match scan: brute-force the game's IdString table
// by hashing every '/'-containing ASCII string in process memory and
// comparing against unknown-name unit hashes. The resource path name for
// such units lives ONLY in this in-memory table (not in package data).
// ============================================================
static DWORD WINAPI path_match_thread(LPVOID arg) {
    (void)arg;
    log_msg("%s", "[RAYCAST] Path hash-match scan started\n");
    static const uint64_t targets[] = {
        0x1b798f4f99a0b8c8ULL,  /* air-box mystery unit */
        0x465f4895f3dc98d1ULL,  /* captain */
        0xc4744b18befbbf14ULL,  /* bridge crew (fc5b... pkg) */
        0x47d31418339a0f1bULL,  /* earlier hit */
    };
    const int ntargets = (int)(sizeof(targets) / sizeof(targets[0]));
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *addr = NULL;
    int pages = 0, candidates = 0, matches = 0;
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) && pages < 4000000) {
        pages++;
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 64 &&
            (mbi.Protect & 0x100) == 0 &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY))) {
            uint8_t *base = (uint8_t *)mbi.BaseAddress;
            size_t size = mbi.RegionSize;
            __try {
                size_t i = 0;
                while (i + 8 < size) {
                    if (base[i] >= 0x20 && base[i] < 0x7f) {
                        size_t s = i;
                        while (s < size && base[s] >= 0x20 && base[s] < 0x7f) s++;
                        size_t len = s - i;
                        if (len >= 8 && len < 512) {
                            int hasslash = 0;
                            for (size_t k = 0; k < len; k++)
                                if (base[i + k] == '/') { hasslash = 1; break; }
                            if (hasslash) {
                                uint64_t h = murmur2_64(base + i, len);
                                for (int t = 0; t < ntargets; t++) {
                                    if (h == targets[t]) {
                                        char sbuf[512];
                                        memcpy(sbuf, base + i, len);
                                        sbuf[len] = 0;
                                        log_msg("[RAYCAST] [PATHMATCH] 0x%016llx = %s\n",
                                            (unsigned long long)h, sbuf);
                                        matches++;
                                    }
                                }
                                candidates++;
                            }
                        }
                        i = s;
                    } else {
                        i++;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                /* page raced with unmap - skip rest of this page */
            }
        }
        addr = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uint8_t *)mbi.BaseAddress) break;
    }
    log_msg("[RAYCAST] Path hash-match scan done: %d candidates, %d matches\n", candidates, matches);
    return 0;
}

static void path_match_table(void) {
    static volatile LONG g_match_running = 0;
    if (InterlockedCompareExchange(&g_match_running, 1, 0) != 0) {
        log_msg("%s", "[RAYCAST] Path match scan already running, skip\n");
        return;
    }
    HANDLE h = CreateThread(NULL, 0, path_match_thread, NULL, 0, NULL);
    if (h) {
        CloseHandle(h);
        log_msg("%s", "[RAYCAST] Path hash-match scan started on background thread\n");
    } else {
        InterlockedExchange(&g_match_running, 0);
        log_msg("%s", "[RAYCAST] Failed to start path match thread\n");
    }
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
    // (render phase, inside Present hook). Drawing Gui.rect here on the
    // script thread produced white flicker and may have triggered the
    // anti-cheat (GUI commands outside the render phase).
}

// ============================================================
// Comprehensive dump: camera + 5 units + World struct
// F4: dump everything useful at once
// ============================================================
// Physics intersect probe (Numpad3): Unit.box is unreliable and
// World.find_units_intersecting does not exist. Last Lua hope: the engine's
// Broadphase. If Broadphase.add_unit(unit, radius) exists, it uses the unit's
// REAL world transform internally - then a ray query returns the exact unit
// the crosshair points at, dynamic or static.
// ============================================================
static void probe_nodes(void) {
    log_msg("%s", "[RAYCAST] === Numpad3: Broadphase probe ===\n");
    exec_lua(
        "local S = stingray\n"
        "local w = S.Application.main_world()\n"
        "local out = {}\n"
        "out[#out+1] = 'Broadphase='..type(S.Broadphase)\n"
        "if type(S.Broadphase) == 'table' then\n"
        "  local ms = {}\n"
        "  for k, v in pairs(S.Broadphase) do ms[#ms+1] = k..'='..type(v) end\n"
        "  table.sort(ms)\n"
        "  out[#out+1] = 'methods='..table.concat(ms, ',')\n"
        "  local ok, bp = pcall(S.Broadphase, 'rc_bp_test')\n"
        "  out[#out+1] = 'create='..tostring(ok)..' '..type(bp)\n"
        "  if ok and bp then\n"
        "    local ok2, ents = pcall(S.World.units, w)\n"
        "    local added = 0\n"
        "    if ok2 and type(ents) == 'table' then\n"
        "      for i = 1, math.min(#ents, 80) do\n"
        "        local ok3, r = pcall(bp.add_unit, bp, ents[i], 1.0)\n"
        "        if ok3 then added = added + 1 else out[#out+1] = 'add_unit err@'..i..':'..tostring(r) break end\n"
        "      end\n"
        "    end\n"
        "    out[#out+1] = 'add_unit added='..added\n"
        "    local M = S.Matrix4x4\n"
        "    local okp, pose = pcall(S.World.debug_camera_pose, w)\n"
        "    if okp and pose then\n"
        "      local cam = M.translation(pose)\n"
        "      local fwd = M.forward(pose)\n"
        "      local ok4, res = pcall(bp.query, bp, 'ray', cam, fwd, 100)\n"
        "      local n4 = 0\n"
        "      if ok4 and type(res) == 'table' then n4 = #res end\n"
        "      out[#out+1] = 'ray_query='..tostring(ok4)..' n='..n4..(ok4 and type(res) == 'table' and n4 > 0 and (' first='..tostring(res[1])) or '')\n"
        "      local ok5, res5 = pcall(bp.query, bp, 'box', cam.x-5, cam.y-5, cam.z-5, cam.x+5, cam.y+5, cam.z+5)\n"
        "      local n5 = 0\n"
        "      if ok5 and type(res5) == 'table' then n5 = #res5 end\n"
        "      out[#out+1] = 'box_query='..tostring(ok5)..' n='..n5\n"
        "    end\n"
        "  end\n"
        "end\n"
        "return table.concat(out, ' | ')\n"
    );
}

// ============================================================
// Unit transform brute-force (Numpad4): Lua exposes no world position for
// dynamic units, so read the unit's C++ object directly and scan for a
// camera-near coordinate triple (the world translation of its transform).
// Stand next to the target, hit Numpad4, and the logged +0x offsets with
// plausible coordinates reveal where the transform lives.
// ============================================================
static void probe_unit_transform(void) {
    if (!f_lua_touserdata || !g_L || !f_luaL_loadstring || !o_lua_pcall || !f_lua_newthread) return;
    log_msg("%s", "[RAYCAST] === Numpad4: Unit C++ transform scan ===\n");
    int top = f_lua_gettop(g_L);
    lua_State *T = f_lua_newthread(g_L);
    if (!T) { f_lua_settop(g_L, top); return; }
    const char *code =
        "local S = stingray\n"
        "local w = S.Application.main_world()\n"
        "local M = S.Matrix4x4\n"
        "local pose = S.World.debug_camera_pose(w)\n"
        "local cam = M.translation(pose)\n"
        "local ents = _G.rc_ents or {}\n"
        "local u = _G.rc_hit_unit\n"
        "if u then local oka, a = pcall(S.Unit.alive, u) if not (oka and a) then u = nil end end\n"
        "if not u then for i=1,#ents do local oka,a = pcall(S.Unit.alive, ents[i]) if oka and a then u = ents[i] break end end end\n"
        "if not u then return cam.x, cam.y, cam.z, nil end\n"
        "local okr, rn = pcall(S.Unit.resource_name, u)\n"
        "return cam.x, cam.y, cam.z, u, okr and tostring(rn) or '?'";
    int seh = 0;
    if (f_luaL_loadstring(T, code) != 0) {
        log_msg("[RAYCAST] Numpad4 loadstring FAILED\n");
        f_lua_settop(g_L, top);
        return;
    }
    __try { o_lua_pcall(T, 0, 5, 0); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Diagnostic probe: keep the crash contained AND do NOT poison the
        // global segfault cooldown that guards F4 (per user: fix, don't break).
        log_msg("[RAYCAST] Numpad4 SEH 0x%08X (isolated; if F4 misbehaves after this, restart game)\n",
            GetExceptionCode());
        seh = 1;
    }
    if (!seh) {
        g_cam_x = (float)f_lua_tonumber(T, 1);
        g_cam_y = (float)f_lua_tonumber(T, 2);
        g_cam_z = (float)f_lua_tonumber(T, 3);
        void *ud = f_lua_touserdata(T, 4);
        const char *rn = f_lua_tolstring(T, 5, NULL);
        if (!ud) {
            log_msg("[RAYCAST] no target unit (press F4 first to set rc_hit_unit, then stand next to it)\n");
        } else {
            log_msg("[RAYCAST] probing unit ud=%p rn=%s cam=(%.1f,%.1f,%.1f)\n",
                ud, rn ? rn : "?", g_cam_x, g_cam_y, g_cam_z);
            if (is_readable(ud, 32)) {
                void *cpp = *(void **)ud;
                if (cpp && is_readable(cpp, 64)) {
                    int scan = is_readable(cpp, 4096) ? 4096 : 512;
                    log_msg("[RAYCAST] unit cpp=%p scanning %d bytes for cam match\n", cpp, scan);
                    scan_floats("UnitCpp", cpp, scan, g_cam_x, g_cam_y, g_cam_z);
                } else {
                    log_msg("[RAYCAST] cpp=%p unreadable\n", cpp);
                }
            } else {
                log_msg("[RAYCAST] ud unreadable\n");
            }
        }
    }
    f_lua_settop(g_L, top);
}

// ============================================================
// Archive / resource probe (Numpad5): the Blender SDK matches Archive IDs
// against a community-maintained table; a path's first segment ("content")
// may not be in it. Probe the engine's resource/archive APIs to enumerate
// what the game actually has loaded, so the user can match SDK entries.
// ============================================================
static void probe_archives(void) {
    log_msg("%s", "[RAYCAST] === Numpad5: Archive/resource probe ===\n");
    exec_lua(
        "local S = stingray\n"
        "local out = {}\n"
        "out[#out+1] = 'Resource='..type(S.Resource)\n"
        "if type(S.Resource) == 'table' then\n"
        "  local ms = {}\n"
        "  for k, v in pairs(S.Resource) do ms[#ms+1] = k..'='..type(v) end\n"
        "  table.sort(ms)\n"
        "  out[#out+1] = 'Resource.methods='..table.concat(ms, ',')\n"
        "end\n"
        "if type(S.Application) == 'table' then\n"
        "  local ms = {}\n"
        "  for k, v in pairs(S.Application) do\n"
        "    local ks = tostring(k):lower()\n"
        "    if type(v) == 'function' and (ks:find('archiv') or ks:find('resource') or ks:find('pack') or ks:find('mount')) then\n"
        "      ms[#ms+1] = tostring(k)\n"
        "    end\n"
        "  end\n"
        "  table.sort(ms)\n"
        "  out[#out+1] = 'App.resource-fns='..table.concat(ms, ',')\n"
        "end\n"
        "if type(S.Application.archives) == 'function' then\n"
        "  local ok, r = pcall(S.Application.archives)\n"
        "  out[#out+1] = 'archives()='..tostring(ok)..' '..tostring(type(r) == 'table' and #r or type(r))\n"
        "end\n"
        "return table.concat(out, ' | ')\n"
    );
}

// ============================================================
// Camera + unit-position deep probe (F3 / first F4 each session).
// Finds all World/Camera camera-ish functions, calls candidates,
// and cross-checks box center vs world_position vs node_world_position
// vs local_position on one alive unit - this answers the
// "which coordinate space is Unit.box in" question definitively.
// ============================================================
static int g_cam_probed = 0;

static void probe_camera(void) {
    exec_lua(
        "local S = stingray\n"
        "local w = S.Application.main_world()\n"
        "local out = {}\n"
        "local function camfns_of(t)\n"
        "  local r = {}\n"
        "  for k, v in pairs(t) do\n"
        "    local ks = tostring(k)\n"
        "    if type(v) == 'function' and string.find(string.lower(ks), 'camera') then\n"
        "      r[#r+1] = ks\n"
        "    end\n"
        "  end\n"
        "  table.sort(r)\n"
        "  return r\n"
        "end\n"
        "local cf1 = camfns_of(S.World)\n"
        "out[#out+1] = 'World.camera-fns='..(#cf1 > 0 and table.concat(cf1, ',') or 'none')\n"
        "if type(S.Camera) == 'table' then\n"
        "  local cf2 = {}\n"
        "  for k, v in pairs(S.Camera) do\n"
        "    if type(v) == 'function' then cf2[#cf2+1] = tostring(k) end\n"
        "  end\n"
        "  table.sort(cf2)\n"
        "  out[#out+1] = 'Camera.fns='..(#cf2 > 0 and table.concat(cf2, ',') or 'none')\n"
        "end\n"
        "-- reference: debug_camera_pose\n"
        "local M = S.Matrix4x4\n"
        "local okp, pose = pcall(S.World.debug_camera_pose, w)\n"
        "if okp and pose then\n"
        "  local t = M.translation(pose)\n"
        "  local f = M.forward(pose)\n"
        "  out[#out+1] = string.format('debug_cam pos=(%.2f,%.2f,%.2f) fwd=(%.3f,%.3f,%.3f)', t.x, t.y, t.z, f.x, f.y, f.z)\n"
        "else\n"
        "  out[#out+1] = 'debug_camera_pose ERR: '..tostring(pose)\n"
        "end\n"
        "-- position cross-check on the unit we last F4-hit (rc_hit_unit),\n"
        "-- falling back to the first alive unit when nothing was hit yet\n"
        "local ents = _G.rc_ents or {}\n"
        "local u = _G.rc_hit_unit\n"
        "if u then\n"
        "  local oka0, a0 = pcall(S.Unit.alive, u)\n"
        "  if not (oka0 and a0) then u = nil end\n"
        "end\n"
        "if not u then\n"
        "  for i=1,#ents do\n"
        "    local oka, a = pcall(S.Unit.alive, ents[i])\n"
        "    if oka and a then u = ents[i] break end\n"
        "  end\n"
        "end\n"
        "if u then\n"
        "  local okr, rn = pcall(S.Unit.resource_name, u)\n"
        "  out[#out+1] = 'unit rn='..(okr and tostring(rn) or '?')\n"
        "  local ob, b1, b2 = pcall(S.Unit.box, u)\n"
        "  if ob and b1 and b1.x then\n"
        "    local bx, by, bz, mx, my, mz\n"
        "    if b2 and b2.x and b2.x >= b1.x and b2.y >= b1.y and b2.z >= b1.z then\n"
        "      bx = (b1.x+b2.x)/2; by = (b1.y+b2.y)/2; bz = (b1.z+b2.z)/2\n"
        "      mx, my, mz = 'minmax', b2.x, b2.y\n"
        "    else bx, by, bz, mx, my, mz = b1.x, b1.y, b1.z, 'center', b2.x, b2.y end\n"
        "    out[#out+1] = string.format('box(%s) c=(%.2f,%.2f,%.2f) b1=(%.2f,%.2f,%.2f) b2=(%.2f,%.2f,%.2f)', mx, bx, by, bz, b1.x, b1.y, b1.z, my, mz, b2 and b2.z or -9)\n"
        "  end\n"
        "  local owp, wp = pcall(S.Unit.world_position, u)\n"
        "  out[#out+1] = 'world_position: '..(owp and (type(wp) == 'userdata' and string.format('(%.2f,%.2f,%.2f)', wp.x, wp.y, wp.z) or tostring(wp)) or ('ERR '..tostring(wp)))\n"
        "  local own, wn = pcall(S.Unit.node_world_position, u, 0)\n"
        "  out[#out+1] = 'node_world_position(0): '..(own and (type(wn) == 'userdata' and string.format('(%.2f,%.2f,%.2f)', wn.x, wn.y, wn.z) or tostring(wn)) or ('ERR '..tostring(wn)))\n"
        "  local olp, lp = pcall(S.Unit.local_position, u, 0)\n"
        "  out[#out+1] = 'local_position(0): '..(olp and (type(lp) == 'userdata' and string.format('(%.2f,%.2f,%.2f)', lp.x, lp.y, lp.z) or tostring(lp)) or ('ERR '..tostring(lp)))\n"
        "  local owp2, wp2 = pcall(S.Unit.world_pose, u)\n"
        "  if owp2 and wp2 then\n"
        "    local t2 = M.translation(wp2)\n"
        "    out[#out+1] = string.format('world_pose pos=(%.2f,%.2f,%.2f)', t2.x, t2.y, t2.z)\n"
        "  end\n"
        "-- scene-graph parent chain: local_pose at each level, cumulative translation\n"
        "local olp0, lpose0 = pcall(S.Unit.local_pose, u)\n"
        "if olp0 and lpose0 then\n"
        "  local t0 = M.translation(lpose0)\n"
        "  out[#out+1] = string.format('local_pose t=(%.2f,%.2f,%.2f)', t0.x, t0.y, t0.z)\n"
        "else\n"
        "  out[#out+1] = 'local_pose ERR: '..tostring(lpose0)\n"
        "end\n"
        "local ok_mul, mmul = pcall(function() return type(M.multiply) end)\n"
        "out[#out+1] = 'Matrix4x4.multiply='..tostring(ok_mul and mmul or 'ERR')\n"
        "local ok_tr, mtr = pcall(function() return type(M.transform) end)\n"
        "out[#out+1] = 'Matrix4x4.transform='..tostring(ok_tr and mtr or 'ERR')\n"
        "local cur = u\n"
        "local chain = {}\n"
        "for d = 1, 16 do\n"
        "  local ok_par, par = pcall(S.Unit.scene_graph_parent, cur)\n"
        "  if not ok_par or not par then break end\n"
        "  local ok_pp, pp = pcall(S.Unit.local_pose, par)\n"
        "  if ok_pp and pp then\n"
        "    local tp = M.translation(pp)\n"
        "    chain[#chain+1] = string.format('d%d t=(%.2f,%.2f,%.2f)', d, tp.x, tp.y, tp.z)\n"
        "    cur = par\n"
        "  else\n"
        "    chain[#chain+1] = 'd'..d..' local_pose ERR'\n"
        "    break\n"
        "  end\n"
        "end\n"
        "out[#out+1] = 'parent-chain ('..#chain..'): '..(#chain > 0 and table.concat(chain, ' ') or 'root')\n"
        "-- Camera object hunt REMOVED: looping Unit.camera over hundreds of\n"
        "-- units crashed the engine (SEH) and made the whole probe return\n"
        "-- empty. The per-frame projection already uses Matrix4x4.right/up\n"
        "-- from the debug camera pose, which is sufficient.\n"
        "out[#out+1] = 'got_camera=skip'\n"
        "end\n"
        "return table.concat(out, ' | ')\n"
    );
    if (g_last_result[0]) log_msg("[RAYCAST] CAMERA PROBE: %s\n", g_last_result);
    else log_msg("%s", "[RAYCAST] CAMERA PROBE: (empty)\n");
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

    // Camera probe moved to F3 only. Auto-probing on every first F4 proved
    // unstable (Unit.camera hunt crashes on some units -> SEH -> CAMERA
    // PROBE empty + pollutes the cooldown right at raycast start).
    // if (!g_cam_probed) {
    //     g_cam_probed = 1;
    //     probe_camera();
    // }

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
            "if hx > 10 or hy > 10 or hz > 10 then return 'huge', rn_str, nh_str, wcx, wcy, wcz, hx, hy, hz, cdist, 'huge', boxmode end\n"
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
            "      local hx2 = rn_str:match('#ID%[%x+%]') or ''\n"
            "      local hx3 = hx2:sub(5, -2) or ''\n"
            "      if hx3 == '75f7e96af7dcd303' then _G.rc_seaf_unit = u end\n"
            "      if hx3 == 'cc21c7ffd3ebefb9' or hx3 == 'e0a48d0be9a7453f' then _G.rc_frv_unit = u end\n"
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
            "      local hx2 = rn_str:match('#ID%[%x+%]') or ''\n"
            "      local hx3 = hx2:sub(5, -2) or ''\n"
            "      if hx3 == '75f7e96af7dcd303' then _G.rc_seaf_unit = u end\n"
            "      if hx3 == 'cc21c7ffd3ebefb9' or hx3 == 'e0a48d0be9a7453f' then _G.rc_frv_unit = u end\n"
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
                        /* v10.50: cache SEAF/FRV entity index by rn hash.
                         * Parse "#ID[<hex>]" the same way track does. */
                        if (rn) {
                            uint64_t h2 = 0;
                            const char *p = strstr(rn, "#ID[");
                            if (p) h2 = (uint64_t)strtoull(p + 4, NULL, 16);
                            if (h2 == SEAF_HASH) {
                                g_seaf_idx = i; g_seaf_key = h2;
                            } else if (h2 == FRV_HASH) {
                                g_frv_idx = i; g_frv_key = h2;
                            }
                        }
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

    // Lazy-load the persisted crash-skip registry here (NOT in DllMain: file
    // I/O inside DllMain can deadlock the loader and the inject never lands).
    {
        static int loaded = 0;
        if (!loaded) { loaded = 1; crash_skip_load(); }
    }

    // Present hook setup is deferred here as well: DllMain ran it under the
    // loader lock while VirtualQuery-ing ~500k pages of address space, which
    // could stall every other thread's LoadLibrary/GetProcAddress. Running it
    // on the game thread on the first pcall is safe.
    {
        static int present_done = 0;
        if (!present_done) { present_done = 1; setup_present_hook(); }
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

    // Install the OutputDebugStringW hook (game thread - safe, once).
    // Captures the engine's [Seater] logs for the menu + SEAF-ride work.
    // DISABLED (2026-08-28 06:5x): OutputDebugStringW's entry contains
    // RIP-relative instructions; the 5-byte patch + trampoline misaligns
    // them and crashes the game (two crashes confirmed). Do NOT re-enable
    // without full-instruction coverage + a complete RIP-rel check.
    // install_odsw_hook();

    // Install the component type-name hook (game thread - safe, once).
    // Captures the real component type names (rdx) from the pool-realloc
    // reporter at game.dll+0xd411b0.
    // DISABLED FOR GOOD (2026-08-28 18:3x): confirmed with a freshly
    // compiled, correctly injected DLL - the inline patch crashes the game
    // deterministically (WinLicense/VMProtect integrity check). Inline
    // patching of game.dll is a dead end; type names stay unreadable via
    // the C layer. Hardware-breakpoint observation (v7) is the only safe
    // mechanism in this game.
    // install_type_name_hook();

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
    
    // F2 - basic probe (dev-only, disabled)
    static DWORD last_f2 = 0;
    if (0 && (GetAsyncKeyState(VK_F2) & 0x8000) && (tick - last_f2 > 500)) {
        last_f2 = tick;
        log_msg("%s", "[RAYCAST] === F2: API probe ===\n");
        exec_lua(
            "local S = stingray "
            "if not S then return 'no stingray' end "
            "local function t(n) return S[n] and type(S[n]) or 'nil' end "
            "return 'App:'..t('Application'), 'World:'..t('World'), "
            "'Unit:'..t('Unit'), 'Camera:'..t('Camera'), "
            "'Broadphase:'..t('Broadphase'), 'Gui:'..t('Gui')"
        );
        exec_lua(
            "local S = stingray "
            "local w = S.Application.main_world() "
            "local fns = {} "
            "for k, v in pairs(S.World) do "
            "  if type(v) == 'function' then table.insert(fns, k) end "
            "end "
            "table.sort(fns) "
            "return 'World: ' .. table.concat(fns, ', ')"
        );
        exec_lua(
            "local S = stingray "
            "local fns = {} "
            "for k, v in pairs(S.Unit) do "
            "  if type(v) == 'function' then table.insert(fns, k) end "
            "end "
            "table.sort(fns) "
            "return 'Unit: ' .. table.concat(fns, ', ')"
        );
        // Probe Sphere/Vector3/Matrix4x4 APIs
        exec_lua(
            "local S = stingray "
            "local parts = {} "
            "for _, name in ipairs({'Sphere', 'Vector3', 'Matrix4x4', 'Viewport', 'Camera'}) do "
            "  local t = S[name] and type(S[name]) or 'nil' "
            "  local info = name..':'..t "
            "  if t == 'table' then "
            "    local fns = {} "
            "    for k, v in pairs(S[name]) do "
            "      if type(v) == 'function' then table.insert(fns, k) end "
            "    end "
            "    table.sort(fns) "
            "    info = info .. ' ['..table.concat(fns, ',')..']' "
            "  end "
            "  table.insert(parts, info) "
            "end "
            "return table.concat(parts, ' | ')"
        );
    }
    
    // F3 - NPC passenger pin (v10.46): pin F4-locked SEAF onto F4-locked FRV
    // passenger seat. SEAF/FRV auto-cached by hash in the F4 probe
    // (rc_seaf_unit / rc_frv_unit), so F4 each once, then this toggles.
    static DWORD last_f3 = 0;
    if ((GetAsyncKeyState(VK_F3) & 0x8000) && (tick - last_f3 > 800)) {
        last_f3 = tick;
        f8_npc_pin();
    }
    // Pin tick every ~120ms while armed (zero traversal, only locked units).
    // v10.53: stages 3-6 probe candidate position-set APIs ONE PER EXEC (a
    // native crash inside pcall() still crashes the whole chunk - SEH only
    // isolates the exec, so each candidate must be its own exec_lua to be
    // attributable via g_pin_stage). stage 7 probes animations.
    static DWORD last_pin = 0;
    if (g_npc_pin_active && (tick - last_pin > 120)) {
        last_pin = tick;
        g_pin_stage++;
        if (g_pin_stage > 7) g_pin_stage = 1;
        g_quiet_exec = 1;
        switch (g_pin_stage) {
        case 1: /* pose: read FRV world pose */
            exec_lua("local S = stingray "
                     "local p=_G.rc_pin if not p then return end "
                     "local ok,pose=pcall(S.Unit.world_pose,p.frv) "
                     "if ok and pose then _G.rc_ppose=pose return 'pose-ok' end "
                     "_G.rc_ppose=nil return 'pose-fail'");
            break;
        case 2: /* xform: seat anchor point in world space */
            exec_lua("local S = stingray "
                     "local p=_G.rc_pin if not p then return end "
                     "local ok,v=pcall(S.Matrix4x4.transform,_G.rc_ppose,S.Vector3(1.18,-1.6,0.935)) "
                     "if ok and v and v.x then _G.rc_pv=v return 'xform-ok' end "
                     "return 'xform-fail'");
            break;
        case 3: /* probe: Unit.teleport_local_position (engine-returned pos) */
            exec_lua("local S = stingray "
                     "local p=_G.rc_pin if not p then return end "
                     "if type(S.Unit.teleport_local_position) ~= 'function' then return 'tlp-missing' end "
                     "local ok1,pos = pcall(S.Unit.world_position, p.npc) "
                     "if not ok1 or not pos then return 'tlp-nowp' end "
                     "local ok2 = pcall(S.Unit.teleport_local_position, p.npc, pos) "
                     "return ok2 and 'tlp-ok' or 'tlp-fail'");
            break;
        case 4: /* probe: Unit.teleport_local_position (explicit Vector3) */
            exec_lua("local S = stingray "
                     "local p=_G.rc_pin if not p then return end "
                     "if type(S.Unit.teleport_local_position) ~= 'function' then return 'tlp-missing' end "
                     "local ok1,pos = pcall(S.Unit.world_position, p.npc) "
                     "if not ok1 or not pos or not pos.x then return 'tlp-nowp' end "
                     "local ok2 = pcall(S.Unit.teleport_local_position, p.npc, S.Vector3(pos.x,pos.y,pos.z)) "
                     "return ok2 and 'tlp3-ok' or 'tlp3-fail'");
            break;
        case 5: /* probe: Unit.set_local_position (engine-returned pos) */
            exec_lua("local S = stingray "
                     "local p=_G.rc_pin if not p then return end "
                     "if type(S.Unit.set_local_position) ~= 'function' then return 'slp-missing' end "
                     "local ok1,pos = pcall(S.Unit.world_position, p.npc) "
                     "if not ok1 or not pos then return 'slp-nowp' end "
                     "local ok2 = pcall(S.Unit.set_local_position, p.npc, pos) "
                     "return ok2 and 'slp-ok' or 'slp-fail'");
            break;
        case 6: /* probe: Unit.set_position (engine-returned pos) */
            exec_lua("local S = stingray "
                     "local p=_G.rc_pin if not p then return end "
                     "if type(S.Unit.set_position) ~= 'function' then return 'sp-missing' end "
                     "local ok1,pos = pcall(S.Unit.world_position, p.npc) "
                     "if not ok1 or not pos then return 'sp-nowp' end "
                     "local ok2 = pcall(S.Unit.set_position, p.npc, pos) "
                     "return ok2 and 'sp-ok' or 'sp-fail'");
            break;
        case 7: /* probe: animations (first one that doesn't crash) */
            exec_lua("local S = stingray "
                     "local p=_G.rc_pin if not p then return end "
                     "local anims = { "
                     "  'content/fac_helldivers/vehicles/frv/animation/idle_back_left', "
                     "  'content/fac_helldivers/vehicles/frv/animation/idle', "
                     "  'content/characters/npc/seaf/animations/idle' "
                     "} "
                     "for _,an in ipairs(anims) do "
                     "  local ok,e = pcall(S.Unit.play_simple_animation, p.npc, an) "
                     "  if ok and not e then _G.rc_anim_ok = an return 'anim-ok' end "
                     "end "
                     "return 'anim-all-fail'");
            break;
        }
        g_quiet_exec = 0;
        /* v10.51: report a stage failure once per stage (not every 120ms
         * tick); successes stay silent under g_quiet_exec. */
        static int s_stage_fail_log = -1;
        if (g_last_result[0] && strstr(g_last_result, "-fail")) {
            if (g_pin_stage != s_stage_fail_log) {
                s_stage_fail_log = g_pin_stage;
                log_msg("[RAYCAST] pin stage %d: %s\n", g_pin_stage, g_last_result);
            }
        } else {
            s_stage_fail_log = -1;
        }
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
    if ((GetAsyncKeyState(VK_F5) & 0x8000) && (tick - last_f5 > 500)) {
        last_f5 = tick;
        g_continuous_raycast = !g_continuous_raycast;
        char buf[128];
        snprintf(buf, sizeof(buf), "[RAYCAST] Continuous: %s\n", 
            g_continuous_raycast ? "ON" : "OFF");
        log_msg("%s", buf);
    }
    
    // Continuous raycast (~2 fps, reduced for performance)
    static DWORD last_cont = 0;
    if (g_continuous_raycast && (tick - last_cont > 500)) {
        last_cont = tick;
        g_verbose_log = 0; // quiet in continuous mode
        do_raycast();
    }
    
    // F6 - Unit/Material API probe (for the emissive-glow highlight idea)
    // NOTE: only ENUMERATES method names. Calling Unit.material() directly
    // native-crashed (SEH-swallowed, no output) - the engine cannot be
    // poked that way from the isolated coroutine.
    static DWORD last_f6 = 0;
    if ((GetAsyncKeyState(VK_F6) & 0x8000) && (tick - last_f6 > 800)) {
        last_f6 = tick;
        log_msg("%s", "[RAYCAST] === F6: Unit/Material API ===\n");
        exec_lua(
            "local S = stingray "
            "local out = {} "
            "if S.Unit then "
            "  local ms = {} "
            "  for k, v in pairs(S.Unit) do "
            "    local ks = tostring(k):lower() "
            "    if type(v) == 'function' and (ks:find('material') or ks:find('visual') or ks:find('shader') or ks:find('mesh')) then ms[#ms+1] = tostring(k) end "
            "  end "
            "  table.sort(ms) "
            "  out[#out+1] = 'Unit.mat-vis='..table.concat(ms, ',') "
            "end "
            "if S.Material then "
            "  local mf = {} "
            "  for k, v in pairs(S.Material) do if type(v) == 'function' then table.insert(mf, tostring(k)) end end "
            "  table.sort(mf) "
            "  out[#out+1] = 'Material.fns='..table.concat(mf, ',') "
            "end "
            "if S.MaterialShader then "
            "  local sf = {} "
            "  for k, v in pairs(S.MaterialShader) do if type(v) == 'function' then table.insert(sf, tostring(k)) end end "
            "  table.sort(sf) "
            "  out[#out+1] = 'MaterialShader.fns='..table.concat(sf, ',') "
            "end "
            "if S.Material and S.Material.__index then "
            "  local mi = {} "
            "  for k, v in pairs(S.Material.__index) do if type(v) == 'function' then table.insert(mi, tostring(k)) end end "
            "  table.sort(mi) "
            "  out[#out+1] = 'Material.obj='..table.concat(mi, ',') "
            "end "
            "return table.concat(out, ' | ')"
        );
    }
    
    // INSERT - Broadphase probe (dev-only, disabled)
    static DWORD last_insert = 0;
    if (0 && (GetAsyncKeyState(VK_INSERT) & 0x8000) && (tick - last_insert > 800)) {
        last_insert = tick;
        probe_broadphase();
    }

    // F7 - Dump engine C-function addresses. Stingray's tostring() prints
    // "[function]" with NO address, so we walk the "stingray.Unit" table and
    // read the CClosure struct directly via lua_topointer. f sits at +16
    // (GCHeader next(8)+tt/marked/isC/nupvalues(4)+pad(4)) on 64-bit Lua 5.1,
    // fallback +24. We walk on a fresh coroutine thread (T) so the stack stays
    // isolated: a crash cannot poison the game main stack, and we never need
    // f_lua_gettop (Stingray may not export it - it's a macro in stock Lua).
    static DWORD last_f7 = 0;
    if ((GetAsyncKeyState(VK_F7) & 0x8000) && (tick - last_f7 > 800)) {
        last_f7 = tick;
        log_msg("%s", "[RAYCAST] === F7: engine fn addresses (CClosure walk) ===\n");
        dump_lua_exports();
        if (!g_L || !f_lua_newthread || !f_lua_getfield ||
            !f_lua_type || !f_lua_topointer) {
            log_msg("[RAYCAST] F7 diag: g_L=%p newthread=%p getfield=%p type=%p topointer=%p\n",
                (void*)g_L, (void*)f_lua_newthread,
                (void*)f_lua_getfield, (void*)f_lua_type, (void*)f_lua_topointer);
            log_msg("%s", "[RAYCAST] F7: lua walk APIs unavailable\n");
            return; // (inside update drawer; keeps stack untouched)
        }
        const char* names[] = {
            "world_position", "alive", "box", "local_position", "local_pose",
            "scene_graph_link", "scene_graph_parent", "animation_wanted_root_pose",
            "resource_name", "query_material", "set_material", "world", "id", "name_hash"
        };
        lua_State* T = f_lua_newthread(g_L); // pushes thread obj on g_L; T stack empty
        if (!T) { log_msg("%s", "[RAYCAST] F7: newthread failed\n"); return; }
        __try {
            f_lua_getfield(T, LUA_GLOBALSINDEX, "stingray"); // Stingray has no lua_getglobal export
            int t0 = f_lua_type(T, -1);
            log_msg("[RAYCAST] F7 step1 stingray type=%d (want %d)\n", t0, LUA_TTABLE);
            if (t0 == LUA_TTABLE) {
                f_lua_getfield(T, -1, "Unit");
                int t1 = f_lua_type(T, -1);
                log_msg("[RAYCAST] F7 step2 Unit type=%d (want %d)\n", t1, LUA_TTABLE);
                if (t1 == LUA_TTABLE) {
                for (int i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
                    f_lua_getfield(T, -1, names[i]);
                    int tf = f_lua_type(T, -1);
                    uintptr_t fn = 0;
                    if (tf == LUA_TFUNCTION) {
                        // LuaJIT CClosure: f sits at +24 (GCHeader 16 + nupvalues
                        // 4 + pad 4); stock 5.1 puts f at +16. lua_tocfunction is
                        // authoritative and needs no offset guessing.
                        if (f_lua_tocfunction) {
                            lua_CFunction cfn = f_lua_tocfunction(T, -1);
                            if (cfn) fn = (uintptr_t)cfn;
                        }
                        if (!fn) {
                            const void* tv = f_lua_topointer(T, -1);
                            if (tv) {
                                memcpy(&fn, (const char*)tv + 24, sizeof(fn));
                                if (fn < 0x10000) { // not plausible; try +16
                                    fn = 0;
                                    memcpy(&fn, (const char*)tv + 16, sizeof(fn));
                                }
                            }
                        }
                        log_msg("[RAYCAST] F7 %-28s type=%d f=0x%llX\n",
                            names[i], tf, (unsigned long long)fn);
                        // dump upvalues - engine fns often close over core pointers
                        if (f_lua_getupvalue) {
                            for (int n = 1; n <= 8; n++) {
                                const char* un = f_lua_getupvalue(T, -1, n);
                                if (!un) break;
                                int ut = f_lua_type(T, -1);
                                if (ut == LUA_TNUMBER) {
                                    log_msg("[RAYCAST]     uv[%d] '%s' number=%.6g\n", n, un, f_lua_tonumber(T, -1));
                                } else if (ut == LUA_TSTRING) {
                                    const char* us = f_lua_tolstring(T, -1, NULL);
                                    log_msg("[RAYCAST]     uv[%d] '%s' string='%s'\n", n, un, us ? us : "?");
                                } else if (ut == LUA_TTABLE) {
                                    log_msg("[RAYCAST]     uv[%d] '%s' table\n", n, un);
                                } else if (ut == LUA_TUSERDATA) {
                                    const void* ud = f_lua_touserdata(T, -1);
                                    log_msg("[RAYCAST]     uv[%d] '%s' userdata=0x%llX\n", n, un, (unsigned long long)(uintptr_t)ud);
                                } else if (ut == LUA_TFUNCTION) {
                                    lua_CFunction uf = f_lua_tocfunction ? f_lua_tocfunction(T, -1) : NULL;
                                    log_msg("[RAYCAST]     uv[%d] '%s' function f=0x%llX\n", n, un, (unsigned long long)(uintptr_t)uf);
                                } else if (ut == LUA_TBOOLEAN) {
                                    log_msg("[RAYCAST]     uv[%d] '%s' boolean\n", n, un);
                                } else {
                                    log_msg("[RAYCAST]     uv[%d] '%s' type=%d\n", n, un, ut);
                                }
                                f_lua_settop(T, -2); // pop upvalue value
                            }
                        }
                    } else {
                        log_msg("[RAYCAST] F7 %-28s type=%d (not function)\n", names[i], tf);
                    }
                    if (fn > 0x10000) {
                        unsigned char buf[192];
                        SIZE_T got = 0;
                        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)fn, buf, sizeof(buf), &got) && got) {
                            // which module is this fn in?
                            HMODULE fnmod = NULL;
                            char modname[64] = "?";
                            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)fn, &fnmod) && fnmod) {
                                GetModuleBaseNameA(GetCurrentProcess(), fnmod, modname, sizeof(modname));
                            }
                            char hex[768];
                            size_t o = 0;
                            for (SIZE_T k = 0; k < got; k++)
                                o += (size_t)sprintf_s(hex + o, sizeof(hex) - o, "%02X ", buf[k]);
                            log_msg("[RAYCAST] fn %-28s @ 0x%llX [%s]: %s\n", names[i], (unsigned long long)fn, modname, hex);
                            // resolve call [rip+disp] (FF 15) indirect targets -
                            // engine fns resolve the unit handle through these
                            for (int j = 0; j + 5 < (int)got; j++) {
                                if (buf[j] == 0xFF && buf[j + 1] == 0x15) {
                                    int32_t disp;
                                    memcpy(&disp, buf + j + 2, 4);
                                    uintptr_t slot = (uintptr_t)(fn + j + 6 + disp);
                                    uintptr_t target = 0;
                                    SIZE_T tr = 0;
                                    if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)slot, &target, sizeof(target), &tr) && tr == sizeof(target)) {
                                        HMODULE tmod = NULL;
                                        char tmodname[64] = "?";
                                        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)target, &tmod) && tmod)
                                            GetModuleBaseNameA(GetCurrentProcess(), tmod, tmodname, sizeof(tmodname));
                                        log_msg("[RAYCAST]   %-28s call[%d] slot=0x%llX fn=0x%llX [%s]\n",
                                            names[i], j, (unsigned long long)slot, (unsigned long long)target, tmodname);
                                        if (target > 0x10000) {
                                            unsigned char tb[96];
                                            SIZE_T tg = 0;
                                            if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)target, tb, sizeof(tb), &tg) && tg) {
                                                char thex[384]; size_t to = 0;
                                                for (SIZE_T k = 0; k < tg; k++)
                                                    to += (size_t)sprintf_s(thex + to, sizeof(thex) - to, "%02X ", tb[k]);
                                                log_msg("[RAYCAST]     tgt bytes: %s\n", thex);
                                            }
                                        }
                                    }
                                }
                            }
                            // resolve relative call (E8 rel32) sub-functions
                            for (int j = 0; j + 4 < (int)got; j++) {
                                if (buf[j] == 0xE8) {
                                    int32_t disp;
                                    memcpy(&disp, buf + j + 1, 4);
                                    uintptr_t sub = (uintptr_t)(fn + j + 5 + disp);
                                    HMODULE smod = NULL;
                                    char smodname[64] = "?";
                                    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)sub, &smod) && smod)
                                        GetModuleBaseNameA(GetCurrentProcess(), smod, smodname, sizeof(smodname));
                                    log_msg("[RAYCAST]   %-28s E8[%d] sub=0x%llX [%s]\n",
                                        names[i], j, (unsigned long long)sub, smodname);
                                    if (sub > 0x10000) {
                                        unsigned char sb[96];
                                        SIZE_T sg = 0;
                                        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)sub, sb, sizeof(sb), &sg) && sg) {
                                            char shex[384]; size_t so = 0;
                                            for (SIZE_T k = 0; k < sg; k++)
                                                so += (size_t)sprintf_s(shex + so, sizeof(shex) - so, "%02X ", sb[k]);
                                            log_msg("[RAYCAST]     E8 tgt: %s\n", shex);
                                        }
                                    }
                                }
                            }
                        } else {
                            log_msg("[RAYCAST] fn %-28s @ 0x%llX: read FAILED\n", names[i], (unsigned long long)fn);
                        }
                    }
                    f_lua_settop(T, -2); // pop the fn
                }
                // enumerate EVERY method in the Unit table via lua_next
                if (f_lua_next && f_lua_pushnil && f_lua_tolstring) {
                    f_lua_pushnil(T);
                    while (f_lua_next(T, -2) != 0) { // key -2, value -1
                        if (f_lua_type(T, -1) == LUA_TFUNCTION) {
                            const char* k = f_lua_tolstring(T, -2, NULL);
                            lua_CFunction cfn = f_lua_tocfunction ? f_lua_tocfunction(T, -1) : NULL;
                            log_msg("[RAYCAST]   Unit.%s f=0x%llX\n", k ? k : "?",
                                (unsigned long long)(uintptr_t)cfn);
                        }
                        f_lua_settop(T, -2); // pop value, keep key for next
                    }
                    f_lua_settop(T, -2); // pop the last key
                }
                } else {
                    log_msg("%s", "[RAYCAST] F7: stingray.Unit not a table\n");
                }
                f_lua_settop(T, -2); // pop Unit
            } else {
                log_msg("%s", "[RAYCAST] F7: stingray not a table\n");
            }
            f_lua_settop(T, 0); // reset T stack
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            log_msg("[RAYCAST] F7 SEH 0x%08X - walk aborted, T stack reset\n", GetExceptionCode());
            f_lua_settop(T, 0);
        }
        f_lua_settop(g_L, -2); // pop the thread object pushed by newthread
    }

    // F8 - C-level handle resolution test (dev)
    static DWORD last_f8 = 0;
    if ((GetAsyncKeyState(VK_F8) & 0x8000) && (tick - last_f8 > 1000)) {
        last_f8 = tick;
        int old_q = g_quiet_exec, old_b = g_exec_bypass;
        g_quiet_exec = 1; g_exec_bypass = 1;
        test_handle_resolve();
        g_quiet_exec = old_q; g_exec_bypass = old_b;
    }

    // F9 - Full memory dump to mem_dump.txt (offline analysis)
    static DWORD last_f9 = 0;
    if ((GetAsyncKeyState(VK_F9) & 0x8000) && (tick - last_f9 > 1500)) {
        last_f9 = tick;
        dump_memory_to_file();
    }

    // F10 - Comprehensive stingray API probe (dev-only, disabled)
    static DWORD last_f10 = 0;
    if (0 && (GetAsyncKeyState(VK_F10) & 0x8000) && (tick - last_f10 > 1000)) {
        last_f10 = tick;
        probe_all_stingray_apis();
    }

    // F11 - Toggle continuous visualization (user's primary key - RESTORED)
    static DWORD last_f11 = 0;
    if ((GetAsyncKeyState(VK_F11) & 0x8000) && (tick - last_f11 > 500)) {
        last_f11 = tick;
        g_continuous_viz = !g_continuous_viz;
        g_continuous_raycast = g_continuous_viz; // also enable raycast scan
        char buf[128];
        snprintf(buf, sizeof(buf), "[RAYCAST] Viz mode: %s (raycast+draw)\n",
            g_continuous_viz ? "ON" : "OFF");
        log_msg("%s", buf);
    }

    // F12 - Raycast signature probe (dev-only, disabled)
    static DWORD last_f12 = 0;
    if (0 && (GetAsyncKeyState(VK_F12) & 0x8000) && (tick - last_f12 > 1000)) {
        last_f12 = tick;
        probe_raycast_signatures();
    }

    // Numpad1 - Nearby-unit scan: find_units_intersecting around camera,
    // dump hash + resource_name for every unit (hash<->path mapping)
    static DWORD last_f13 = 0;
    if ((GetAsyncKeyState(VK_NUMPAD1) & 0x8000) && (tick - last_f13 > 1000)) {
        last_f13 = tick;
        scan_nearby_units();
    }

    // Numpad2 - Animation/vehicle API probe. Uses the exact pairs() pattern
    // F6 is proven to work with (no getmetatable walks: a __pairs metamethod
    // on an engine table made exec_lua return silently). Split into two
    // exec_lua calls so a failure in one still yields the other's results.
    static DWORD last_f14 = 0;
    if ((GetAsyncKeyState(VK_NUMPAD2) & 0x8000) && (tick - last_f14 > 1000)) {
        last_f14 = tick;
        log_msg("[RAYCAST] === NUMPAD2: probe (segfault_flag=%d) ===\n", g_segfault_flag);
        exec_lua(
            "local S = stingray "
            "local out = {} "
            "local function walk(name, t) "
            "  local fns = {} "
            "  if type(t) == 'table' then "
            "    for k, v in pairs(t) do "
            "      local ks = tostring(k):lower() "
            "      if type(v) == 'function' and (ks:find('anim') or ks:find('skelet') or ks:find('pose') or ks:find('ragdoll') "
            "         or ks:find('vehic') or ks:find('seat') or ks:find('weapon') or ks:find('fire') or ks:find('aim') "
            "         or ks:find('occup') or ks:find('attach') or ks:find('mount') or ks:find('drive') "
            "         or ks:find('board') or ks:find('enter')) then fns[#fns+1] = tostring(k) end "
            "    end "
            "  end "
            "  if #fns > 0 then table.sort(fns) out[#out+1] = name..'='..table.concat(fns, ',') end "
            "end "
            "walk('Unit', S.Unit) "
            "walk('World', S.World) "
            "walk('Application', S.Application) "
            "return table.concat(out, ' | ')"
        );
        exec_lua(
            "local S = stingray "
            "local out = {} "
            "local tops = {} "
            "if type(S) == 'table' then for k, v in pairs(S) do local ks = tostring(k):lower() if type(v) == 'table' and (ks:find('anim') or ks:find('vehic') or ks:find('seat') or ks:find('actor') or ks:find('skelet') or ks:find('weapon') or ks:find('ai')) then tops[#tops+1] = tostring(k) end end end "
            "table.sort(tops) out[#out+1] = 'top-anim-tables='..table.concat(tops, ',') "
            "for _, t in ipairs({'Animator','Animation','AnimSet','Vehicle','Seat','AIAgent','Actor','Skeleton','Weapon','Ragdoll'}) do "
            "  if S[t] and type(S[t]) == 'table' then "
            "    local fns = {} "
            "    for k, v in pairs(S[t]) do if type(v) == 'function' then fns[#fns+1] = tostring(k) end end "
            "    table.sort(fns) out[#out+1] = t..' table='..table.concat(fns, ',') "
            "  end "
            "end "
            "return table.concat(out, ' | ')"
        );
        // All top-level tables (no filter) + _G keys matching interaction /
        // vehicle / gameplay keywords - a vehicle/seat entry point may live
        // under a module whose name does not contain anim/vehic/seat/etc.
        exec_lua(
            "local S = stingray "
            "local allt = {} "
            "local cnt = 0 "
            "if type(S) == 'table' then for k, v in pairs(S) do cnt = cnt + 1 if type(v) == 'table' then allt[#allt+1] = tostring(k) end end end "
            "table.sort(allt) "
            "local gk = {} "
            "local ok, k = pcall(next, _G, nil) "
            "while ok and k do "
            "  local kl = tostring(k):lower() "
            "  if kl:find('vehicle') or kl:find('seat') or kl:find('interact') or kl:find('enter') or kl:find('mount') "
            "     or kl:find('drive') or kl:find('ride') or kl:find('board') or kl:find('occup') or kl:find('passenger') "
            "     or kl:find('gunner') or kl:find('game') or kl:find('logic') or kl:find('controller') then "
            "    gk[#gk+1] = tostring(k) "
            "  end "
            "  ok, k = pcall(next, _G, k) "
            "end "
            "table.sort(gk) "
             "return 'ALL-TOP('..cnt..')='..table.concat(allt, ',') .. ' | G-KEYS='..table.concat(gk, ',')"
        );
        // All Unit/World/Application methods (no keyword filter) - decide
        // whether components (Seater etc.) are reachable from Lua, e.g. via
        // Unit.component / flow_variable style APIs. Split per table: the
        // combined string overflows the 4096 result buffer.
        exec_lua(
            "local S = stingray "
            "local fns = {} "
            "if type(S.World) == 'table' then for k, v in pairs(S.World) do if type(v) == 'function' then fns[#fns+1] = tostring(k) end end end "
            "table.sort(fns) return 'World-ALL='..table.concat(fns, ',')"
        );
        exec_lua(
            "local S = stingray "
            "local fns = {} "
            "if type(S.Application) == 'table' then for k, v in pairs(S.Application) do if type(v) == 'function' then fns[#fns+1] = tostring(k) end end end "
            "table.sort(fns) return 'Application-ALL='..table.concat(fns, ',')"
        );
        // AI table methods (pathfinding / move interfaces for NPCs)
        exec_lua(
            "local S = stingray "
            "local fns = {} "
            "if type(S.AI) == 'table' then for k, v in pairs(S.AI) do if type(v) == 'function' then fns[#fns+1] = tostring(k) end end end "
            "table.sort(fns) return 'AI-ALL='..table.concat(fns, ',')"
        );
    }

    // Numpad3 - Broadphase/unit probe (dev-only, disabled)
    static DWORD last_f15 = 0;
    if (0 && (GetAsyncKeyState(VK_NUMPAD3) & 0x8000) && (tick - last_f15 > 1000)) {
        last_f15 = tick;
        probe_nodes();
    }

    // Numpad4 - Unit C++ transform scan (dev-only, disabled)
    static DWORD last_f16 = 0;
    if (0 && (GetAsyncKeyState(VK_NUMPAD4) & 0x8000) && (tick - last_f16 > 1000)) {
        last_f16 = tick;
        probe_unit_transform();
    }

    // Numpad5 - Archive/resource probe (dev-only, disabled)
    static DWORD last_f17 = 0;
    if (0 && (GetAsyncKeyState(VK_NUMPAD5) & 0x8000) && (tick - last_f17 > 1000)) {
        last_f17 = tick;
        probe_archives();
    }

    // Numpad5 - Install the engine Seater set_entering hook (observe the
    // real player-board call: args = seater obj / seat idx / etc.)
    static DWORD last_seaterkey = 0;
    if ((GetAsyncKeyState(VK_NUMPAD5) & 0x8000) && (tick - last_seaterkey > 800)) {
        last_seaterkey = tick;
        install_seater_hook();
    }
    // Poll the zero-code hardware-breakpoint seater buffer (only prints
    // when new hits) - v7: no code patched, anti-tamper safe.
    se7_poll_log();

    // Numpad6 - Path hash-match scan (find resource path names from memory)
    static DWORD last_f18 = 0;
    if ((GetAsyncKeyState(VK_NUMPAD6) & 0x8000) && (tick - last_f18 > 1000)) {
        last_f18 = tick;
        path_match_table();
    }

    // Numpad7 - Dump the unpacked game.dll image for offline Ghidra analysis
    static DWORD last_f19 = 0;
    if ((GetAsyncKeyState(VK_NUMPAD7) & 0x8000) && (tick - last_f19 > 3000)) {
        last_f19 = tick;
        dump_game_module();
    }

    // Numpad8 - NPC auto-ride toggle (F4-targeted unit <-> FRV passenger
    // seat). (F11 is the continuous-viz toggle; F12 is the Steam screenshot
    // key - both taken, so ride moved to Numpad8.)
    static DWORD last_ridekey = 0;
    if ((GetAsyncKeyState(VK_NUMPAD8) & 0x8000) && (tick - last_ridekey > 800)) {
        last_ridekey = tick;
        npc_ride_toggle();
    }

    // Ride tick every ~120ms while a ride is armed (only then - avoids
    // spamming 'off' into the log every frame when no ride is active)
    static DWORD last_ride = 0;
    if (g_ride_active && (tick - last_ride > 120)) {
        last_ride = tick;
        g_quiet_exec = 1;
        exec_lua("if _G.rc_ride_tick then _G.rc_ride_tick() end");
        g_quiet_exec = 0;
    }

    // Numpad9 - Register F4-targeted unit as the SEAF template for auto-gunner
    static DWORD last_gunkey = 0;
    if ((GetAsyncKeyState(VK_NUMPAD9) & 0x8000) && (tick - last_gunkey > 800)) {
        last_gunkey = tick;
        npc_gunner_register();
    }

    // Numpad0 - dump FRV seater slots + player seater context (v10.33)
    static DWORD last_f7se = 0;
    if ((GetAsyncKeyState(VK_NUMPAD0) & 0x8000) && (tick - last_f7se > 800)) {
        last_f7se = tick;
        f7_find_frv();
        dump_player_ctx();
    }
    // Numpad+ - call set_entering(Y, 0, 1)  (enter driver seat)
    static DWORD last_f8se = 0;
    if ((GetAsyncKeyState(VK_ADD) & 0x8000) && (tick - last_f8se > 800)) {
        last_f8se = tick;
        f8_set_entering(0, 0);
    }
    // Numpad- - EXIT command: command_queue_exit(mgr, seater_id, instant)
    static DWORD last_f9se = 0;
    if ((GetAsyncKeyState(VK_SUBTRACT) & 0x8000) && (tick - last_f9se > 800)) {
        last_f9se = tick;
        f8_exit_command();
    }

    // Auto-gunner scan every 2s (detect newly called-in FRVs) - DISABLED:
    // the full World.units walk + per-unit resource_name crashes at the C
    // layer every ~2s (SEH 0xC0000005 loop, log flood). gunner_pin also
    // disabled: its unconditional 120ms exec_lua (fresh coroutine per call)
    // was a second crash-loop source under an unstable Lua state. Both are
    // re-enabled once made crash-safe.
    static DWORD last_gscan = 0;
    if (0 && (tick - last_gscan > 2000)) {
        last_gscan = tick;
        g_quiet_exec = 1;
        exec_lua("if _G.rc_gunner_tick then _G.rc_gunner_tick() end");
        g_quiet_exec = 0;
    }
    static DWORD last_gpin = 0;
    if (0 && (tick - last_gpin > 120)) {
        last_gpin = tick;
        g_quiet_exec = 1;
        exec_lua("if _G.rc_gunner_pin then _G.rc_gunner_pin() end");
        g_quiet_exec = 0;
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

    // Component explorer (v4): refresh ~2s or on addon request. SEH-safe
    // reads; game base resolved fresh each call so it survives re-maps.
    comp_explorer_tick();

    return result;
}

// ============================================================
// Jammer Bypass (anti-cheat bypass from CE table)
// ============================================================
static const uint8_t jammer_aob[] = {
    0x4D, 0x8B, 0x3C, 0xC7,
    0x4C, 0x89, 0x7C, 0x24,
    0x00,
    0x41, 0xF6, 0x47,
    0x00, 0x00,
    0x0F, 0x84
};
static const int jammer_aob_len = sizeof(jammer_aob);
static const int jammer_offset = 14;

static uint8_t *aob_scan(uint8_t *start, size_t size, const uint8_t *pattern, int pat_len) {
    if (size < (size_t)pat_len) return NULL;
    for (size_t i = 0; i <= size - pat_len; i++) {
        int match = 1;
        for (int j = 0; j < pat_len; j++) {
            if (pattern[j] != 0x00 && start[i + j] != pattern[j]) {
                match = 0;
                break;
            }
        }
        if (match) return &start[i];
    }
    return NULL;
}

static void apply_jammer_bypass(void) {
    log_msg("%s", "[RAYCAST] Applying Jammer Bypass...\n");
    
    HMODULE game_dll = GetModuleHandleA("game.dll");
    if (!game_dll) {
        log_msg("%s", "[RAYCAST] game.dll not found\n");
        return;
    }
    
    uint8_t *base = (uint8_t *)game_dll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        log_msg("%s", "[RAYCAST] Invalid DOS header\n");
        return;
    }
    
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        log_msg("%s", "[RAYCAST] Invalid NT signature\n");
        return;
    }
    
    // Scan all code sections
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    uint8_t *found = NULL;
    
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            uint8_t *sec_start = base + sec[i].VirtualAddress;
            SIZE_T sec_size = sec[i].Misc.VirtualSize;
            
            char buf[256];
            char sec_name[9] = {0};
            memcpy(sec_name, sec[i].Name, 8);
            snprintf(buf, sizeof(buf), "[RAYCAST] Scanning '%s': 0x%zx bytes\n", sec_name, sec_size);
            log_msg("%s", buf);
            
            found = aob_scan(sec_start, sec_size, jammer_aob, jammer_aob_len);
            if (found) break;
        }
    }
    
    if (!found) {
        log_msg("%s", "[RAYCAST] Jammer AOB not found - bypass skipped\n");
        return;
    }
    
    char buf[256];
    snprintf(buf, sizeof(buf), "[RAYCAST] Jammer AOB at game.dll+0x%zx\n", (size_t)(found - base));
    log_msg("%s", buf);
    
    uint8_t *target = found + jammer_offset;
    snprintf(buf, sizeof(buf), "[RAYCAST] Patch target: game.dll+0x%zx [%02x %02x %02x %02x %02x %02x]\n",
        (size_t)(target - base), target[0], target[1], target[2], target[3], target[4], target[5]);
    log_msg("%s", buf);
    
    // Patch JE (0F 84) -> NOP + JMP (90 E9) using safe_virtual_protect
    DWORD old_protect;
    uint8_t *page_base = (uint8_t *)((uintptr_t)target & ~(uintptr_t)0xFFF);
    
    if (!safe_virtual_protect(page_base, 0x2000, PAGE_EXECUTE_READWRITE, &old_protect)) {
        snprintf(buf, sizeof(buf), "[RAYCAST] safe_virtual_protect failed for jammer\n");
        log_msg("%s", buf);
        return;
    }
    
    target[0] = 0x90;
    target[1] = 0xE9;
    
    DWORD dummy;
    safe_virtual_protect(page_base, 0x2000, old_protect, &dummy);
    FlushInstructionCache(GetCurrentProcess(), target, 6);
    
    log_msg("%s", "[RAYCAST] Jammer Bypass applied!\n");
}

// ============================================================
// ============================================================
// D3D12/11 Present hook - render-phase line drawing
// LineObject.dispatch() MUST be called during render phase
// (outside of it, it segfaults - verified step6). We hook
// IDXGISwapChain::Present (vtable index 8) to get that timing.
// ============================================================
typedef HRESULT (STDMETHODCALLTYPE *Present_fn)(void *sc, UINT sync, UINT flags);
static Present_fn g_orig_present = NULL;
static volatile LONG g_present_hooked = 0;
static volatile DWORD g_present_thread = 0;

// dxgi.dll CBaseSwapChain::Present prologue (D3D11 & D3D12 share it):
//   48 8B C4        mov rax, rsp
//   48 89 58 08     mov [rax+8], rbx
//   57              push rdi
//   48 83 EC 20     sub rsp, 20h
static const uint8_t g_present_pat[] = {
    0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20
};

static int is_exec_addr(void *p) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return 0;
    return (mbi.State == MEM_COMMIT) && ((mbi.Protect & 0xF0) != 0);
}

static uint8_t *find_pattern_in_module(HMODULE mod, const uint8_t *pat, int len) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((uint8_t *)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    uint8_t *sec = (uint8_t *)mod + nt->OptionalHeader.BaseOfCode;
    size_t size = nt->OptionalHeader.SizeOfCode;
    for (size_t i = 0; i + (size_t)len <= size; i++) {
        int m = 1;
        for (int j = 0; j < len; j++) {
            if (sec[i + j] != pat[j]) { m = 0; break; }
        }
        if (m) return sec + i;
    }
    return NULL;
}

// Scan all committed memory for a qword equal to present_addr.
// The qword must be a vtable slot (index 8): vtable[0..7] executable.
static void *find_vtable_slot(uint64_t present_addr) {
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *addr = NULL;
    int scans = 0;
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) && scans < 500000) {
        scans++;
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0 &&
            (mbi.Protect & 0x100) == 0) { // skip PAGE_GUARD
            uint8_t *base = (uint8_t *)mbi.BaseAddress;
            size_t size = mbi.RegionSize;
            for (size_t i = 64; i + 8 <= size; i += 8) {
                if (*(uint64_t *)(base + i) == present_addr) {
                    int valid = 1;
                    for (int k = 0; k < 8; k++) {
                        uint64_t fn = *(uint64_t *)(base + i - 64 + k * 8);
                        if (!is_exec_addr((void *)fn)) { valid = 0; break; }
                    }
                    if (valid) return base + i;
                }
            }
        }
        addr = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uint8_t *)mbi.BaseAddress) break;
    }
    return NULL;
}

// ============================================================
// Swapchain vtable scan - NO byte patterns, purely structural.
// IDXGISwapChain vtable slots [0][1][2][7][8] (QueryInterface,
// AddRef, Release, GetDevice, Present) all point into dxgi.dll.
// This cannot false-positive on game code.
// ============================================================
struct ModRange { uint8_t *base; size_t size; char name[64]; };
static struct ModRange g_mods[512];
static int g_mod_count = 0;

static void collect_modules(void) {
    g_mod_count = 0;
    HMODULE mods[512];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(GetCurrentProcess(), mods, sizeof(mods), &needed, LIST_MODULES_ALL)) return;
    int count = (int)(needed / sizeof(HMODULE));
    if (count > 512) count = 512;
    for (int i = 0; i < count && g_mod_count < 512; i++) {
        HMODULE h = mods[i];
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)h;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((uint8_t *)h + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
        g_mods[g_mod_count].base = (uint8_t *)h;
        g_mods[g_mod_count].size = nt->OptionalHeader.SizeOfImage;
        GetModuleBaseNameA(GetCurrentProcess(), h, g_mods[g_mod_count].name,
            sizeof(g_mods[g_mod_count].name));
        g_mod_count++;
    }
}

static int in_mod(uint8_t *p, const struct ModRange *m) {
    return p >= m->base && p < m->base + m->size;
}

// Find IDXGISwapChain Present vtable slot[8] candidates.
// STRICT verification to kill the old false-positive (which hooked a vtable
// that was never called): QI/AddRef/Release ([0][1][2]) must point into
// dxgi.dll AND be strictly increasing (real COM vtables are contiguous),
// slots [3..8] must all point into dxgi.dll, and slot[8] (Present) must
// match a known Present function prologue byte pattern.
#define MAX_SC_CANDIDATES 8
static void *g_sc_candidates[MAX_SC_CANDIDATES];
static int g_sc_candidate_count = 0;

static int is_present_prologue(const uint8_t *addr) {
    static const uint8_t pats[4][12] = {
        // Win10 1903+: mov rax,rsp; mov [rax+8],rbx; push rdi; sub rsp,20h
        {0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x57,0x48,0x83,0xEC,0x20},
        // Variant: mov [rsp+8],rbx; push rdi; sub rsp,20h; mov ebx,[rcx+8]
        {0x48,0x89,0x5C,0x24,0x08,0x57,0x48,0x83,0xEC,0x20,0x8B,0x59},
        // Variant with extra push rsi/r15
        {0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x57,0x41,0x56,0x48,0x83},
        // Win11 dxgi: 4C 8B DC 49 89 5B 08 (mov r11,rsp; mov [r11+8],rbx)
        {0x4C,0x8B,0xDC,0x49,0x89,0x5B,0x08,0x57,0x48,0x83,0xEC,0x20}
    };
    for (int p = 0; p < 4; p++) {
        int ok = 1;
        for (int j = 0; j < 12; j++) {
            if (addr[j] != pats[p][j]) { ok = 0; break; }
        }
        if (ok) return 1;
    }
    return 0;
}

static void find_swapchain_present_slots(void) {
    g_sc_candidate_count = 0;
    int dxgi_idx = -1;
    for (int i = 0; i < g_mod_count; i++) {
        if (_stricmp(g_mods[i].name, "dxgi.dll") == 0) { dxgi_idx = i; break; }
    }
    if (dxgi_idx < 0) return;
    const struct ModRange *dxgi = &g_mods[dxgi_idx];

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *addr = NULL;
    int pages = 0;
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) && pages < 500000) {
        pages++;
        if (mbi.State == MEM_COMMIT && mbi.RegionSize >= 0x90 &&
            (mbi.Protect & 0x100) == 0 && (mbi.Protect & 0x02)) { // RW data
            uint8_t *base = (uint8_t *)mbi.BaseAddress;
            size_t size = mbi.RegionSize;
            for (size_t i = 0; i + 0x90 <= size && g_sc_candidate_count < MAX_SC_CANDIDATES; i += 8) {
                uint64_t *slots = (uint64_t *)(base + i);
                if (!in_mod((uint8_t *)slots[0], dxgi)) continue;
                if (!in_mod((uint8_t *)slots[1], dxgi)) continue;
                if (!in_mod((uint8_t *)slots[2], dxgi)) continue;
                if (!(slots[1] > slots[0] && slots[2] > slots[1])) continue;
                if (!in_mod((uint8_t *)slots[3], dxgi)) continue;
                if (!in_mod((uint8_t *)slots[4], dxgi)) continue;
                if (!in_mod((uint8_t *)slots[5], dxgi)) continue;
                if (!in_mod((uint8_t *)slots[6], dxgi)) continue;
                if (!in_mod((uint8_t *)slots[7], dxgi)) continue;
                if (!in_mod((uint8_t *)slots[8], dxgi)) continue;
                if (!is_present_prologue((const uint8_t *)slots[8])) continue;
                g_sc_candidates[g_sc_candidate_count++] = &((uint8_t *)base)[i + 8 * 8];
            }
        }
        addr = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uint8_t *)mbi.BaseAddress) break;
    }
    log_msg("[RAYCAST] Present candidates: %d\n", g_sc_candidate_count);
    for (int k = 0; k < g_sc_candidate_count; k++) {
        log_msg("[RAYCAST]   cand %d slot=%p orig=%p\n", k, g_sc_candidates[k],
            *(void **)g_sc_candidates[k]);
    }
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

static HRESULT STDMETHODCALLTYPE PresentHook(void *sc, UINT sync, UINT flags) {
    if (!g_present_thread) {
        g_present_thread = GetCurrentThreadId();
        log_msg("[RAYCAST] Present first call on thread %u\n", g_present_thread);
    }
    // Pure-C heartbeat (no Lua): proves the hook fires every few seconds.
    static DWORD last_ph = 0;
    DWORD pt = GetTickCount();
    if (pt - last_ph > 5000) {
        last_ph = pt;
        log_msg("[RAYCAST] PresentHook alive thread=%u flag=%ld exec_gL=%p\n",
            GetCurrentThreadId(), g_segfault_flag, (void *)g_L);
    }
    HRESULT hr = g_orig_present(sc, sync, flags);
    if (g_present_hooked) {
        // IMPORTANT: NO Lua calls from the render thread. exec_lua here raced
        // the game's own Lua thread (cross-thread lua_pcall) and deadlocked the
        // game ("not responding"). 3D lines are drawn on the game thread by
        // draw_3d_lines_game_thread() from hk_lua_pcall instead.
    }
    return hr;
}

// Install our PresentHook into a vtable slot. Returns 1 on success.
static int install_present_slot(void *slot) {
    g_orig_present = *(Present_fn *)slot;
    DWORD old;
    if (!safe_virtual_protect(slot, 8, PAGE_READWRITE, &old)) {
        log_msg("%s", "[RAYCAST] Present vtable protect failed\n");
        return 0;
    }
    *(Present_fn *)slot = PresentHook;
    safe_virtual_protect(slot, 8, old, &old);
    g_present_hooked = 1;
    log_msg("[RAYCAST] Present hooked: slot=%p orig=%p\n", slot, g_orig_present);
    return 1;
}

static void setup_present_hook(void) {
    HMODULE dxgi = GetModuleHandleA("dxgi.dll");
    if (!dxgi) {
        log_msg("%s", "[RAYCAST] dxgi.dll not loaded, no Present hook\n");
        return;
    }

    // Dump module info to understand what we're scanning
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)dxgi;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((uint8_t *)dxgi + dos->e_lfanew);
    log_msg("[RAYCAST] dxgi.dll base=%p image_size=%u code_size=%u\n",
        dxgi, nt->OptionalHeader.SizeOfImage, nt->OptionalHeader.SizeOfCode);

    // Collect module ranges for the structural scan
    collect_modules();

    // PRIMARY: strict multi-candidate swapchain vtable scan
    // (Present prologue verified + contiguous dxgi QI/AddRef/Release).
    find_swapchain_present_slots();
    if (g_sc_candidate_count > 0) {
        for (int k = 0; k < g_sc_candidate_count; k++) {
            log_msg("[RAYCAST] Trying Present candidate %d\n", k);
            if (install_present_slot(g_sc_candidates[k])) return;
        }
        log_msg("%s", "[RAYCAST] All Present candidates failed to install\n");
    } else {
        log_msg("%s", "[RAYCAST] Strict scan found no swapchain vtable\n");
    }

    // FALLBACK: byte-pattern scan (original logic kept)
    static const uint8_t pats[4][12] = {
        // Win10 1903+: mov rax,rsp; mov [rax+8],rbx; push rdi; sub rsp,20h
        {0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x57,0x48,0x83,0xEC,0x20},
        // Variant: mov [rsp+8],rbx; push rdi; sub rsp,20h; mov ebx,[rcx+8]
        {0x48,0x89,0x5C,0x24,0x08,0x57,0x48,0x83,0xEC,0x20,0x8B,0x59},
        // Variant with extra push rsi/r15
        {0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x57,0x41,0x56,0x48,0x83},
        // Win11 dxgi: 4C 8B DC 49 89 5B 08 (mov r11,rsp; mov [r11+8],rbx)
        {0x4C,0x8B,0xDC,0x49,0x89,0x5B,0x08,0x57,0x48,0x83,0xEC,0x20}
    };

    uint8_t *found_pat = NULL;
    int found_pat_idx = -1;
    for (int pi = 0; pi < 4; pi++) {
        uint8_t *m = find_pattern_in_module(dxgi, pats[pi], 12);
        if (m) {
            found_pat = m;
            found_pat_idx = pi;
            break;
        }
    }

    if (!found_pat) {
        log_msg("%s", "[RAYCAST] All Present patterns failed in dxgi.dll\n");
        // NOTE: the old cross-module fallback (scanning helldivers2.exe etc.)
        // was REMOVED because it false-positively hooked engine functions that
        // merely share the Present prologue, crashing the game at injection
        // (sessions 04:38 and 14:42 both died at "Present pattern 1 found in
        // helldivers2.exe"). Rendering is now owned by the ReShade addon
        // (hd2_addon.addon64), so a self-hooked Present is neither needed
        // nor wanted. If the original behavior is ever required, the block
        // below is where it used to live.
        log_msg("%s", "[RAYCAST] Present hook skipped: render layer handled by ReShade addon\n");
        return;
    }

    log_msg("[RAYCAST] Present pattern %d at %p\n", found_pat_idx, found_pat);
    void *slot = find_vtable_slot((uint64_t)(uintptr_t)found_pat);
    if (!slot) {
        log_msg("%s", "[RAYCAST] No vtable slot found for Present (swapchain not located)\n");
        return;
    }
    install_present_slot(slot);
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
        
        // Apply Jammer Bypass first
        // TEST MODE: disabled to check whether patching game.dll code is what
        // triggers GameGuard's code-integrity check (game force-closes after a
        // while when the patch is applied). If disabling stops the kicks, the
        // patch must be replaced with a non-code-patching approach.
        //apply_jammer_bypass();

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
        
        // Present hook is set up lazily on the first lua_pcall (NOT here in
        // DllMain - the full-address-space vtable scan under the loader lock
        // could stall other threads; see hk_lua_pcall).
        //setup_present_hook();
        
        snprintf(buf, sizeof(buf), "[RAYCAST] Hook installed. trampoline=%p\n", tramp);
        log_msg("%s", buf);
        log_msg("%s", "[RAYCAST] Keys: F4=raycast F5=continuous F6=material-probe Numpad1=nearby Numpad6=path-match\n");
    } else if (reason == DLL_PROCESS_DETACH) {
        // Unregister from ReShade and release shared memory
        hd2_addon_detach();
    }
    
    return TRUE;
}
