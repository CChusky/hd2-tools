/* overlay.c - HD2 Target Overlay（用户版）
 * 外部透明覆盖层：读取 Local\HD2RaycastShm 显示 F4 锁定目标信息。
 * 零游戏内依赖：不需要 ReShade / DebugView / addon。
 *
 * 构建: build_overlay.bat
 * 用法: 先启动游戏并注入 hd2_raycast_hook.dll，再运行 overlay.exe。
 * 热键: Ctrl+Shift+L 切换语言, Ctrl+Shift+H 显示/隐藏
 * 配置: config.ini（同目录）, 语言: lang_zh.ini / lang_en.ini
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <objidl.h>   /* IStream - required by gdiplus.h */
#include <gdiplus.h>
#include <stdio.h>
#include <string.h>
#include "shm_proto.h"

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

using namespace Gdiplus;

/* ---------------- config ---------------- */
static char g_lang[16] = "zh";
static int g_show_panel = 1, g_show_line = 1, g_show_mark = 1, g_show_hint = 1;
static float g_scale = 1.0f;
static int g_panel_x = 16, g_panel_y = 16;
static int g_monitor_cfg = -1; /* -1 = follow game window, 0 = primary, 1..N = monitor index */
static char g_exe_dir[MAX_PATH];

static void skip_bom(char *p) {
    /* UTF-8 BOM 容错 */
    if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF) {
        p[0] = p[1] = p[2] = ' ';
    }
}

static void cfg_load(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char buf[512];
    while (fgets(buf, sizeof buf, f)) {
        char *p = buf;
        while (*p == ' ' || *p == '\t') p++;
        skip_bom(p);
        if (*p == '#' || *p == ';' || *p == '\n' || *p == '\r' || *p == 0) continue;
        char key[64], val[256];
        if (sscanf(p, "%63[^= \t]=%255s", key, val) == 2) {
            if (!strcmp(key, "lang")) snprintf(g_lang, sizeof g_lang, "%s", val);
            else if (!strcmp(key, "show_panel")) g_show_panel = atoi(val);
            else if (!strcmp(key, "show_line")) g_show_line = atoi(val);
            else if (!strcmp(key, "show_mark")) g_show_mark = atoi(val);
            else if (!strcmp(key, "show_hint")) g_show_hint = atoi(val);
            else if (!strcmp(key, "scale")) g_scale = (float)atof(val);
            else if (!strcmp(key, "panel_x")) g_panel_x = atoi(val);
            else if (!strcmp(key, "panel_y")) g_panel_y = atoi(val);
            else if (!strcmp(key, "monitor")) g_monitor_cfg = atoi(val);
        }
    }
    fclose(f);
}

/* ---------------- i18n ---------------- */
static char T_title[256], T_locked[256], T_distance[256], T_none[256],
            T_wait[256], T_type[256], T_cmd[256], T_hint[256],
            T_scanbox[256];

static void i18n_default_zh(void) {
    snprintf(T_title, sizeof T_title, "HD2 目标覆盖层");
    snprintf(T_locked, sizeof T_locked, "锁定目标");
    snprintf(T_distance, sizeof T_distance, "距离");
    snprintf(T_none, sizeof T_none, "未锁定");
    snprintf(T_wait, sizeof T_wait, "等待游戏 (未检测到共享内存)");
    snprintf(T_type, sizeof T_type, "类型");
    snprintf(T_cmd, sizeof T_cmd, "反馈");
    snprintf(T_hint, sizeof T_hint, "Ctrl+Shift+L 语言 | Ctrl+Shift+H 显隐 | Ctrl+Shift+Q 退出");
    snprintf(T_scanbox, sizeof T_scanbox, "扫描盒");
}

static void i18n_load(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char buf[512];
    while (fgets(buf, sizeof buf, f)) {
        char *p = buf;
        while (*p == ' ' || *p == '\t') p++;
        skip_bom(p);
        if (*p == '#' || *p == ';' || *p == '\n' || *p == '\r' || *p == 0) continue;
        char key[64], val[256];
        if (sscanf(p, "%63[^= \t]=%255s", key, val) == 2) {
            char *dst = NULL;
            if (!strcmp(key, "title")) dst = T_title;
            else if (!strcmp(key, "locked")) dst = T_locked;
            else if (!strcmp(key, "distance")) dst = T_distance;
            else if (!strcmp(key, "none")) dst = T_none;
            else if (!strcmp(key, "wait")) dst = T_wait;
            else if (!strcmp(key, "type")) dst = T_type;
            else if (!strcmp(key, "cmd")) dst = T_cmd;
            else if (!strcmp(key, "hint")) dst = T_hint;
            else if (!strcmp(key, "scanbox")) dst = T_scanbox;
            if (dst) snprintf(dst, 256, "%s", val);
        }
    }
    fclose(f);
}

static void i18n_reload(void) {
    char lp[MAX_PATH];
    snprintf(lp, sizeof lp, "%slang_%s.ini", g_exe_dir, g_lang);
    i18n_default_zh();
    i18n_load(lp);
}

/* UTF-8 -> UTF-16 (stack buffer, len <= 511 bytes input) */
static const wchar_t *utf8w(const char *s, wchar_t *out, int outlen) {
    if (!s || !*s) { out[0] = 0; return out; }
    MultiByteToWideChar(CP_UTF8, 0, s, -1, out, outlen);
    return out;
}

/* ---------------- shm ---------------- */
static struct rc_shm_data *g_shm = NULL;
static HANDLE g_shm_map = NULL;
static int g_shm_ok = 0;

static void shm_attach(void) {
    if (g_shm_ok) return;
    g_shm_map = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, RC_SHM_NAME);
    if (!g_shm_map) return;
    g_shm = (struct rc_shm_data *)MapViewOfFile(g_shm_map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(struct rc_shm_data));
    if (!g_shm) { CloseHandle(g_shm_map); g_shm_map = NULL; return; }
    if (g_shm->magic == RC_SHM_MAGIC && g_shm->version == RC_SHM_VERSION)
        g_shm_ok = 1;
}

/* ---------------- window ---------------- */
static HWND g_hwnd = NULL;
static HDC g_memdc = NULL;
static HBITMAP g_bmp = NULL;
static void *g_bits = NULL;
static int g_w = 0, g_h = 0;
static int g_vsx = 0, g_vsy = 0;   /* virtual screen origin */

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_HOTKEY:
        if (w == 1) { /* toggle language */
            if (!strcmp(g_lang, "zh")) snprintf(g_lang, sizeof g_lang, "en");
            else snprintf(g_lang, sizeof g_lang, "zh");
            i18n_reload();
        } else if (w == 2) { /* toggle visibility */
            ShowWindow(g_hwnd, IsWindowVisible(g_hwnd) ? SW_HIDE : SW_SHOWNA);
        } else if (w == 3) { /* quit (v1.1) */
            PostQuitMessage(0);
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

/* ---------------- window placement (multi-monitor aware) ---------------- */
static DWORD g_game_pid = 0;
static DWORD g_game_gone_since = 0; /* v1.1: auto-exit when the game closes */

static BOOL CALLBACK enum_win(HWND h, LPARAM lp) {
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid == g_game_pid && IsWindowVisible(h) && GetWindowTextLengthW(h) > 0) {
        *(HWND *)lp = h;
        return FALSE;
    }
    return TRUE;
}

/* v1.2: game-process liveness check (Toolhelp, no process handle - same
 * approach as watcher v3.7, avoids Themida blocking OpenProcess). Used by
 * the auto-exit logic: the old check looked for the game WINDOW, which
 * fails for long stretches under fullscreen-exclusive rendering and made
 * the overlay quit mid-game ("overlay keeps disappearing"). */
static int game_process_alive(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    int alive = 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"helldivers2.exe") == 0) { alive = 1; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return alive;
}

static HWND find_game_window(void) {
    if (!g_game_pid) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"helldivers2.exe") == 0) { g_game_pid = pe.th32ProcessID; break; }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
    }
    if (!g_game_pid) return NULL;
    HWND h = NULL;
    EnumWindows(enum_win, (LPARAM)&h);
    return h;
}

struct mon_ctx { int want; int cur; HMONITOR hit; };
static BOOL CALLBACK enum_mon(HMONITOR h, HDC, LPRECT, LPARAM lp) {
    struct mon_ctx *c = (struct mon_ctx *)lp;
    if (c->cur == c->want) { c->hit = h; return FALSE; }
    c->cur++;
    return TRUE;
}

static HMONITOR pick_monitor(HWND game) {
    if (g_monitor_cfg >= 0) {
        struct mon_ctx c = { g_monitor_cfg, 0, NULL };
        EnumDisplayMonitors(NULL, NULL, enum_mon, (LPARAM)&c);
        if (c.hit) return c.hit;
    }
    if (game) return MonitorFromWindow(game, MONITOR_DEFAULTTONEAREST);
    POINT pt = {0, 0};
    return MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
}

static void win_resize_dib(void) {
    if (g_bmp) { DeleteObject(g_bmp); g_bmp = NULL; g_bits = NULL; }
    BITMAPINFO bi = {0};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = g_w;
    bi.bmiHeader.biHeight = -g_h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    g_bmp = CreateDIBSection(g_memdc, &bi, DIB_RGB_COLORS, &g_bits, NULL, 0);
    SelectObject(g_memdc, g_bmp);
}

/* 跟随游戏窗口所在显示器（或 config 指定显示器），每 500ms 调用 */
static void win_place(void) {
    HWND game = find_game_window();
    /* v1.2: auto-exit checks the PROCESS, not the window. Under
     * fullscreen-exclusive the game window can be invisible/untitled for
     * long stretches; the old window-based check quit the overlay mid-game
     * ("overlay keeps disappearing"). Process gone for 10s -> quit. */
    if (g_game_pid) {
        if (!game_process_alive()) {
            if (!g_game_gone_since) g_game_gone_since = GetTickCount();
            else if (GetTickCount() - g_game_gone_since > 10000) {
                PostQuitMessage(0);
                return;
            }
        } else {
            g_game_gone_since = 0;
        }
    }
    HMONITOR mon = pick_monitor(game);
    MONITORINFO mi = { sizeof(mi) };
    if (!mon || !GetMonitorInfoA(mon, &mi)) {
        if (!g_w) { g_w = GetSystemMetrics(SM_CXSCREEN); g_h = GetSystemMetrics(SM_CYSCREEN); win_resize_dib(); }
        return;
    }
    int x = mi.rcMonitor.left, y = mi.rcMonitor.top;
    int w = mi.rcMonitor.right - mi.rcMonitor.left;
    int h = mi.rcMonitor.bottom - mi.rcMonitor.top;
    if (w != g_w || h != g_h) {
        g_vsx = x; g_vsy = y; g_w = w; g_h = h;
        win_resize_dib();
    } else {
        g_vsx = x; g_vsy = y;
    }
    if (g_hwnd)
        SetWindowPos(g_hwnd, HWND_TOPMOST, g_vsx, g_vsy, g_w, g_h,
                     SWP_NOACTIVATE | SWP_NOSENDCHANGING);
}

static void win_create(HINSTANCE hi) {
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = wndproc;
    wc.hInstance = hi;
    wc.lpszClassName = L"HD2OverlayCls";
    RegisterClassW(&wc);
    g_memdc = CreateCompatibleDC(NULL);
    g_hwnd = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_NOACTIVATE,
        L"HD2OverlayCls", L"HD2Overlay", WS_POPUP,
        0, 0, 640, 480, NULL, NULL, hi, NULL); /* 占位，win_place 立即定位 */
    win_place();
    RegisterHotKey(g_hwnd, 1, MOD_CONTROL | MOD_SHIFT, 'L');
    RegisterHotKey(g_hwnd, 2, MOD_CONTROL | MOD_SHIFT, 'H');
    RegisterHotKey(g_hwnd, 3, MOD_CONTROL | MOD_SHIFT, 'Q');
    ShowWindow(g_hwnd, SW_SHOWNA);
}

/* ---------------- 内置实体名表（常用，完整对照表后续接入） ---------------- */
struct name_entry { uint64_t hash; const char *name; };
static const struct name_entry g_names[] = {
    { 0x75f7e96af7dcd303ULL, "SEAF支援载荷一" },
    { 0xcc21c7ffd3ebefb9ULL, "M-102 FRV" },
    { 0x548136f6ULL,        "SEAF MK2" },
    { 0xa6dcc225ULL,        "SEAF 机枪兵" },
    { 0xc47287d7ULL,        "SEAF 医疗兵" },
    { 0x78dabc73ULL,        "SEAF 队长" },
    { 0xd108b49ce580b5c5ULL,"鹈鹕空降艇" },
};
static const char *lookup_name(uint64_t hash) {
    for (size_t i = 0; i < sizeof(g_names) / sizeof(g_names[0]); i++)
        if (g_names[i].hash == hash) return g_names[i].name;
    return NULL;
}

/* v1.3: return the idx-th UTF-8 character of the shm atlas charset (the
 * label_slots entries are character indices into atlas_chars, same data
 * the ReShade fx samples from its glyph texture). */
static wchar_t atlas_char_at(const char *chars, int idx) {
    const unsigned char *p = (const unsigned char *)chars;
    int ci = 0;
    while (*p) {
        unsigned char c = p[0];
        int l = 1;
        if ((c & 0xE0) == 0xC0) l = 2;
        else if ((c & 0xF0) == 0xE0) l = 3;
        else if ((c & 0xF8) == 0xF0) l = 4;
        if (ci == idx) {
            wchar_t wc[4] = {0};
            int wn = MultiByteToWideChar(CP_UTF8, 0, (const char *)p, l, wc, 3);
            return wn > 0 ? wc[0] : L'?';
        }
        p += l; ci++;
    }
    return L'?';
}

/* ---------------- render ---------------- */
static void draw_line(Graphics &g, const float *p1, const float *p2, int w, int h,
                      const Pen &pen) {
    float x1 = p1[0] * w, y1 = p1[1] * h;
    float x2 = p2[0] * w, y2 = p2[1] * h;
    /* 归一化坐标落在屏幕外则跳过 */
    if (x1 < -9999 || x2 < -9999) return;
    g.DrawLine(&pen, x1, y1, x2, y2);
}

static void render(void) {
    if (!g_hwnd || !g_bits) return;
    Graphics g(g_memdc);
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.Clear(Color(0, 0, 0, 0)); /* 全透明背景 */

    wchar_t wbuf[512];
    Font font_title(L"Microsoft YaHei", (REAL)(18 * g_scale), FontStyleBold, UnitPixel);
    Font font_body(L"Microsoft YaHei", (REAL)(14 * g_scale), FontStyleRegular, UnitPixel);
    Font font_small(L"Microsoft YaHei", (REAL)(12 * g_scale), FontStyleRegular, UnitPixel);
    SolidBrush br_text(Color(255, 235, 235, 235));
    SolidBrush br_dim(Color(220, 170, 170, 170));
    SolidBrush br_green(Color(255, 90, 220, 130));
    SolidBrush br_yellow(Color(255, 240, 200, 80));

    /* ---- 命中线框（模型轮廓 + AABB + 扫描盒）----
     * v1.3: colors/thickness aligned to HD2HUD.fx - cyan mesh wireframe
     * (0.2,1.0,0.6,0.98), yellow AABB hidden when a real mesh exists. */
    if (g_shm_ok) {
        if (g_show_line) {
            Pen pen_line(Color(250, 51, 255, 153), 4.0f);  /* fx cyan, ~2.4px dist */
            Pen pen_box(Color(240, 255, 255, 0), 2.0f);    /* fx yellow */
            Pen pen_scan(Color(110, 120, 180, 255), 1.0f);
            uint32_t mc = g_shm->ui_mesh_count;
            if (mc > 8192) mc = 8192;
            for (uint32_t i = 0; i + 1 < mc; i += 2)
                draw_line(g, g_shm->ui_mesh[i], g_shm->ui_mesh[i + 1], g_w, g_h, pen_line);
            /* AABB 角点 0..3 为底面四角、4..7 为顶面（按引擎输出序连线）。
             * fx hides the coarse box whenever a real mesh wireframe exists. */
            if (mc < 4 && g_shm->ui_hitbox[0][0] > -9999.0f) {
                const float *b = &g_shm->ui_hitbox[0][0];
                for (int i = 0; i < 4; i++)
                    draw_line(g, b + i * 2, b + ((i + 1) % 4) * 2, g_w, g_h, pen_box);
                for (int i = 0; i < 4; i++)
                    draw_line(g, b + i * 2, b + (i + 4) * 2, g_w, g_h, pen_box);
                for (int i = 4; i < 8; i++)
                    draw_line(g, b + i * 2, b + (4 + ((i + 1) % 4)) * 2, g_w, g_h, pen_box);
            }
            uint32_t sc = g_shm->ui_scanbox_count;
            if (sc > 16) sc = 16;
            /* v1.4: full 12-edge wireframe per scan box (was: bottom 4 edges
             * only, which looked like a flat funnel). Matches HD2HUD.fx. */
            static const int scan_edge[12][2] = {
                {0,1},{1,3},{3,2},{2,0},   /* bottom */
                {4,5},{5,7},{7,6},{6,4},   /* top */
                {0,4},{1,5},{2,6},{3,7}    /* vertical */
            };
            for (uint32_t k = 0; k < sc; k++) {
                const float *b = &g_shm->ui_scanbox[k][0][0];
                for (int e = 0; e < 12; e++)
                    draw_line(g, b + scan_edge[e][0] * 2, b + scan_edge[e][1] * 2, g_w, g_h, pen_scan);
            }
        }
        /* ---- v1.4: fixed crosshair at screen center (magenta) ----
         * The detection ray always fires from screen center; the fx shader
         * draws this same cross. Without it the overlay had no aim anchor. */
        Pen pen_cross(Color(230, 255, 0, 255), 2.0f);
        float ccx = g_w * 0.5f, ccy = g_h * 0.5f;
        g.DrawLine(&pen_cross, ccx - 14, ccy, ccx + 14, ccy);
        g.DrawLine(&pen_cross, ccx, ccy - 14, ccx, ccy + 14);
        /* ---- ray beam: screen center -> hit point (magenta, matches fx) */
        if (g_shm->ui_hit[2] > 0.5f) {
            Pen pen_ray(Color(200, 255, 0, 255), 1.5f);
            g.DrawLine(&pen_ray, ccx, ccy,
                       g_shm->ui_hit[0] * g_w, g_shm->ui_hit[1] * g_h);
        }
        /* ---- 命中标记 ---- */
        if (g_show_mark && g_shm->ui_hit[2] > 0.5f) {
            float nx = g_shm->ui_hit[0] * g_w, ny = g_shm->ui_hit[1] * g_h;
            Pen pen_mark(Color(255, 255, 80, 80), 2.0f);
            g.DrawLine(&pen_mark, nx - 10, ny, nx + 10, ny);
            g.DrawLine(&pen_mark, nx, ny - 10, nx, ny + 10);
        }
    }

    /* ---- v1.3: fx-style text label ----
     * Rebuilt from the shm atlas slots (identical chars to HD2HUD.fx) and
     * rendered anchored at the hit-box TOP-CENTER: white glyphs on
     * translucent-black per-char backdrops, multi-line, scaled by screen
     * height (S.y/2160, 48px atlas cell / 34px bold glyph) - matching the
     * local ReShade build's visual output. */
    if (g_show_panel) {
        if (!g_shm_ok) {
            /* no game data yet: small waiting hint, top-left */
            SolidBrush wait_bg(Color(140, 0, 0, 0));
            g.FillRectangle(&wait_bg, 8, 8, 280, 30);
            g.DrawString(utf8w(T_wait, wbuf, 512), -1, &font_body,
                         PointF(14, 12), &br_yellow);
        } else if ((g_shm->flags & 1) && g_shm->label_count > 0) {
            float sc = (float)g_h / 2160.0f;
            float sch = 48.0f * sc;                    /* atlas cell on screen */
            float row_h = sch + 4.0f;
            float glyph = 34.0f * sc;                  /* fx: ATLAS_CELL-14 bold */
            Font fx_font(L"Microsoft YaHei", glyph, FontStyleBold, UnitPixel);
            SolidBrush br_white(Color(255, 255, 255, 235)); /* fx 1,1,0.92 */
            SolidBrush br_back(Color(140, 0, 0, 0));        /* fx 0,0,0,0.55 */

            /* anchor: hit-box top-center (same as the addon's label_cfg) */
            float ax = 0, ay = 1e9f;
            int nv = 0;
            for (int i = 0; i < 8; i++) {
                if (g_shm->ui_hitbox[i][0] >= 0.0f) {
                    ax += g_shm->ui_hitbox[i][0];
                    if (g_shm->ui_hitbox[i][1] < ay) ay = g_shm->ui_hitbox[i][1];
                    nv++;
                }
            }
            if (nv >= 4) {
                ax = ax / nv * g_w;
                ay = ay * g_h;
                int n = g_shm->label_count;
                if (n > 96) n = 96;
                /* v1.4: measure EVERY char with GDI+ (matches DrawString).
                 * The old code advanced by the hook's GDI GetTextExtentPoint32W
                 * advance (label_widths), which is narrower than GDI+ renders,
                 * so glyphs overlapped ("text stacking"). */
                float adv[96];
                for (int i = 0; i < n; i++) {
                    int32_t slot = g_shm->label_slots[i];
                    adv[i] = 0;
                    if (slot == -2) continue;
                    if (slot < 0) { n = i; break; }
                    wchar_t ch = atlas_char_at(g_shm->atlas_chars, slot);
                    if (ch) {
                        RectF rf;
                        g.MeasureString(&ch, 1, &fx_font, PointF(0, 0), &rf);
                        adv[i] = rf.Width + 2.0f;
                    }
                }
                /* pass 1: rows + widest row (screen px) */
                int nrows = 1;
                float crow = 0, maxrow = 0;
                for (int i = 0; i < n; i++) {
                    int32_t slot = g_shm->label_slots[i];
                    if (slot == -2) { if (crow > maxrow) maxrow = crow; crow = 0; nrows++; }
                    else if (slot >= 0) crow += adv[i];
                    else break;
                }
                if (crow > maxrow) maxrow = crow;
                float block_h = nrows * sch + (nrows - 1) * 4.0f;
                float x0 = ax - maxrow * 0.5f;
                float y0 = ay - block_h - 8.0f;
                float cx = x0, cy = y0;
                for (int i = 0; i < n; i++) {
                    int32_t slot = g_shm->label_slots[i];
                    if (slot == -2) { cy += row_h; cx = x0; continue; }
                    if (slot < 0) break;
                    wchar_t ch = atlas_char_at(g_shm->atlas_chars, slot);
                    if (adv[i] > 0.5f && ch) {
                        g.FillRectangle(&br_back, cx, cy, adv[i], sch);
                        g.DrawString(&ch, 1, &fx_font, PointF(cx, cy + 1.0f), &br_white);
                    }
                    cx += adv[i];
                }
            }
        }
    }

    /* ---- 底部热键提示 ---- */
    if (g_show_hint) {
        SolidBrush hint_bg(Color(120, 0, 0, 0));
        g.FillRectangle(&hint_bg, 8, g_h - 34, 420, 26);
        g.DrawString(utf8w(T_hint, wbuf, 512), -1, &font_small,
                     PointF(14, (REAL)(g_h - 31)), &br_dim);
    }

    /* ---- 合成到屏幕 ---- */
    POINT src = {0, 0};
    POINT dst = {g_vsx, g_vsy};
    SIZE sz = {g_w, g_h};
    BLENDFUNCTION bf = {AC_SRC_OVER, 0, 255, AC_SRC_ALPHA};
    UpdateLayeredWindow(g_hwnd, NULL, &dst, &sz, g_memdc, &src, 0, &bf, ULW_ALPHA);
}

/* ---------------- main ---------------- */
int WINAPI WinMain(HINSTANCE hi, HINSTANCE, LPSTR, int) {
    /* v1.2: single-instance guard - two overlays stacked on top of each
     * other (watcher auto-start + manual run) caused flickering/misleading
     * disappearances. */
    CreateMutexA(NULL, TRUE, "Local\\HD2OverlayMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    /* exe 目录 */
    GetModuleFileNameA(NULL, g_exe_dir, sizeof g_exe_dir);
    char *slash = strrchr(g_exe_dir, '\\');
    if (slash) slash[1] = 0; else g_exe_dir[0] = 0;

    char p[MAX_PATH];
    snprintf(p, sizeof p, "%sconfig.ini", g_exe_dir);
    cfg_load(p);
    i18n_reload();

    GdiplusStartupInput gsi;
    ULONG_PTR gdi_tok = 0;
    GdiplusStartup(&gdi_tok, &gsi, NULL);

    win_create(hi);
    shm_attach();

    MSG msg;
    DWORD last_place = 0;
    for (;;) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) goto done;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        DWORD now = GetTickCount();
        if (now - last_place > 500) { last_place = now; win_place(); }
        if (IsWindowVisible(g_hwnd)) {
            if (!g_shm_ok) shm_attach(); /* 游戏可能晚于 overlay 启动 */
            render();
        }
        Sleep(33); /* ~30 fps */
    }
done:
    GdiplusShutdown(gdi_tok);
    return 0;
}
