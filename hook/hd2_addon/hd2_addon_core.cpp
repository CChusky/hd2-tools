/*
 * HD2 Raycast HUD - ReShade addon core (compiled into hd2_raycast_hook.dll)
 *
 * Renders the hit-target HUD WITHOUT the ReShade menu layer and WITHOUT
 * touching the game UI: it drives a ReShade effect shader (HD2HUD.fx) whose
 * technique runs every frame in the render pipeline. This addon only reads
 * the shared memory written by the C hook (game thread) and feeds the fx
 * uniforms from the reshade_finish_effects event (render thread, every frame).
 *
 * ReShade's official installer builds have "limited add-on functionality"
 * (RESHADE_ADDON==1) which skips scanning *.addon64 files, but they fully
 * export the addon API (ReShadeRegisterAddon/RegisterEvent/...), so we
 * register as an EXTERNAL addon at runtime - that path is not blocked.
 */

// CRITICAL include order: imgui.h MUST come before reshade.hpp - the latter
// (reshade_overlay.hpp) only redirects ImGui:: calls to ReShade's function
// table when IMGUI_VERSION_NUM is already defined.
#define ImTextureID ImU64
#include <imgui.h>
#include <reshade.hpp>

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>

// ---- shared memory protocol (must match hd2_raycast_hook.c) ----
#define RC_SHM_NAME "Local\\HD2RaycastShm"
#define RC_SHM_MAGIC 0x52434432u
#define RC_SHM_VERSION 4
#define RC_SHM_BOXES_MAX 256
#define RC_COMP_MAX_UNITS 64
#define RC_COMP_MAX_PER_UNIT 24
#define RC_COMP_MAX_ITEMS (RC_COMP_MAX_UNITS * RC_COMP_MAX_PER_UNIT)
#define RC_COMP_MAX_TYPES 128

struct rc_shm_box {
    float x, y, z;
    float hx, hy, hz;
};

struct rc_comp_type {
    uint32_t type_id;
    char name[48];
};

struct rc_comp_item {
    uint32_t unit;
    uint32_t type_id;
    uint32_t valid;
    uint32_t flags;
    uint64_t obj;
    char type_name[48];
};

struct rc_shm_data {
    volatile uint32_t magic;
    volatile uint32_t version;
    volatile uint32_t seq;
    volatile uint32_t flags;   // 1 = hit valid, 2 = boxes valid
    float cam_x, cam_y, cam_z;
    float fwd_x, fwd_y, fwd_z;
    float cam_rx, cam_ry, cam_rz;
    float cam_ux, cam_uy, cam_uz;
    float hit_x, hit_y, hit_z;
    float hit_dist;
    uint64_t hit_hash64;
    uint32_t hit_thin;
    char hit_name[96];
    char hit_rn[128];
    uint32_t box_count;
    struct rc_shm_box boxes[RC_SHM_BOXES_MAX];
    uint32_t ui_line[4];
    float ui_hit[3];
    float ui_hitbox[8][2];
    uint32_t ui_mark_count;
    float ui_marks[128][2];
    uint32_t ui_scanbox_count;
    float ui_scanbox[16][8][2];
    float ui_mbox[4][8][2];
    uint32_t ui_mesh_count;
    float ui_mesh[8192][2];
    volatile uint32_t atlas_rev;
    uint32_t atlas_count;
    char atlas_chars[256];
    int32_t label_count;
    int32_t label_slots[96];
    float label_widths[96];
    /* v4: component explorer (unused here, layout must stay in sync) */
    volatile uint32_t comp_seq;
    uint32_t comp_refresh;
    uint32_t comp_unit_count;
    uint32_t comp_units[RC_COMP_MAX_UNITS];
    float comp_unit_pos[RC_COMP_MAX_UNITS][3];
    uint32_t comp_type_count;
    struct rc_comp_type comp_types[RC_COMP_MAX_TYPES];
    uint32_t comp_item_count;
    struct rc_comp_item comp_items[RC_COMP_MAX_ITEMS];
    uint32_t comp_evt_count;
    char comp_evt[6][192];
    uint32_t hit_unit_id;
    volatile uint32_t cmd_seq;
    uint32_t cmd_type;
    uint64_t cmd_addr;
    uint32_t cmd_val32;
    float    cmd_valf;
    volatile uint32_t cmd_done;
    char cmd_feedback[128];  /* v10.4: on-screen command feedback */
};

static HMODULE g_self = NULL;
static bool g_registered = false;

static HANDLE g_shm_map = NULL;
static struct rc_shm_data *g_shm = NULL;
static bool g_shm_ok = false;
static uint32_t g_snap_seq = 0;
static struct rc_shm_data g_snap;
static bool g_snap_valid = false;

// ---- fx handles ----
static reshade::api::effect_technique g_tech;
static reshade::api::effect_uniform_variable g_u_hitmark, g_u_marks, g_u_hitbox, g_u_scanbox;
static reshade::api::effect_uniform_variable g_u_mbox;
static reshade::api::effect_uniform_variable g_u_mesh;  // v3: real mesh outline pts
static reshade::api::effect_uniform_variable g_u_mesh_cfg;   // {point_count,...}
static reshade::api::effect_uniform_variable g_u_mesh_rect;  // {minx,miny,maxx,maxy}
static reshade::api::effect_texture_variable g_u_atlas_texture;
static reshade::api::effect_uniform_variable g_u_atlas_cfg, g_u_slots, g_u_label_cfg, g_u_label_w;
static bool g_fx_ready = false;
static bool g_fx_failed = false;
// Which runtime failed fx init (multi-runtime retry: a failure on the early
// D3D11 runtime must not block the real D3D12 render runtime).
static reshade::api::effect_runtime *g_fx_failed_rt = nullptr;
// Runtime the cached fx handles were found on. ReShade destroys + recreates
// the effect runtime on ResizeBuffers / fullscreen toggles, which invalidates
// every cached technique/uniform/texture handle. Any set_uniform_value_float
// on the new runtime with an old handle crashes (observed: dxgi.dll
// ACCESS_VIOLATION 0xc0000005 right after "Recreated runtime environment").
static reshade::api::effect_runtime *g_fx_rt = nullptr;
// Last fx init failure reason (surfaced to the C side via
// hd2_addon_last_error so F4 prints WHY fx failed).
static char g_fx_errstr[256] = {0};
static char g_shm_errstr[160] = {0};

// ---- glyph atlas (GDI-rendered, uploaded to the fx texture uniform) ----
static uint8_t *g_atlas_px = nullptr;
static int g_atlas_w = 0, g_atlas_h = 0;
static uint32_t g_atlas_rendered_rev = 0xFFFFFFFFu;
static const int ATLAS_COLS = 8;
static const int ATLAS_CELL = 48;
// Fixed atlas canvas. MUST match the rc_atlas texture size in HD2HUD.fx
// (ReShade update_texture rejects mismatched sizes - the old 384xH atlas
// was being uploaded into a 64x64 texture and the text never rendered).
static const int ATLAS_CANVAS = 1024;

static int utf8_seq_len(unsigned char c) {
    if (c < 0x80) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return 1;
}

// Render every unique char into the glyph atlas using a system font (GDI).
// White glyphs on transparent background -> luminance becomes alpha so the
// fx shader can blend them on top of the translucent black backdrop.
static bool render_atlas(const char *utf8_chars, uint32_t nchars) {
    if (nchars == 0 || nchars > 128 || utf8_chars == nullptr) return false;

    bool ok = false;
    __try {
        int rows = (int)((nchars + ATLAS_COLS - 1) / ATLAS_COLS);
        int w = ATLAS_CANVAS;
        int h = ATLAS_CANVAS;
        if (rows * ATLAS_CELL > h) {
            int max_rows = h / ATLAS_CELL;
            nchars = (uint32_t)(max_rows * ATLAS_COLS);
        }

        HDC hdc = CreateCompatibleDC(nullptr);
        if (!hdc) return false;
        BITMAPINFO bi = {};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -h;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        void *bits = nullptr;
        HBITMAP bmp = CreateDIBSection(hdc, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
        if (!bmp || !bits) {
            if (bmp) DeleteObject(bmp);
            DeleteDC(hdc);
            return false;
        }
        HGDIOBJ old_bmp = SelectObject(hdc, bmp);
        memset(bits, 0, (size_t)w * h * 4);

        HFONT font = CreateFontA(ATLAS_CELL - 14, 0, 0, 0, FW_BOLD, 0, 0, 0,
            DEFAULT_CHARSET, 0, 0, ANTIALIASED_QUALITY, 0, "Microsoft YaHei");
        if (!font) font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HGDIOBJ old_font = SelectObject(hdc, font);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255, 255, 255));

        int ci = 0;
        const unsigned char *p = (const unsigned char *)utf8_chars;
        while (*p && ci < (int)nchars) {
            int len = utf8_seq_len(*p);
            wchar_t wc[8] = {0};
            int wn = MultiByteToWideChar(CP_UTF8, 0, (const char *)p, len, wc, 7);
            if (wn > 0) {
                int gx = (ci % ATLAS_COLS) * ATLAS_CELL;
                int gy = (ci / ATLAS_COLS) * ATLAS_CELL;
                RECT r = { gx, gy, gx + ATLAS_CELL, gy + ATLAS_CELL };
                // DT_LEFT: glyph starts at the cell's left edge so the fx
                // shader can sample cell x=0..advance directly (the shader
                // places chars at their real advance width, not full cells).
                DrawTextW(hdc, wc, wn, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOCLIP);
            }
            p += len;
            ci++;
        }
        SelectObject(hdc, old_font);

        // CRITICAL: convert the DIB pixels BEFORE DeleteObject(bmp) - the
        // 'bits' pointer is invalid as soon as the DIB section is destroyed.
        // Reading it afterwards is use-after-free (crash at a fixed offset
        // inside render_atlas, observed with the game's own crash report).
        uint8_t *px = (uint8_t *)realloc(g_atlas_px, (size_t)w * h * 4);
        if (px) {
            g_atlas_px = px;
            const uint8_t *src = (const uint8_t *)bits;
            for (int i = 0; i < w * h; i++) {
                uint8_t b = src[i * 4 + 0], g = src[i * 4 + 1], r = src[i * 4 + 2];
                uint8_t lum = r > g ? r : g;
                if (b > lum) lum = b;
                px[i * 4 + 0] = 255;
                px[i * 4 + 1] = 255;
                px[i * 4 + 2] = 255;
                px[i * 4 + 3] = lum;
            }
            g_atlas_w = w;
            g_atlas_h = h;
            ok = true;
        }

        SelectObject(hdc, old_bmp);
        DeleteObject(font);
        DeleteObject(bmp);
        DeleteDC(hdc);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // GDI crash inside atlas render - never take the game down.
        reshade::log::message(reshade::log::level::warning,
            "HD2 HUD: render_atlas crashed (SEH) - label skipped");
        ok = false;
    }
    return ok;
}

// ---------------------------------------------------------------- shm ----

static void shm_attach()
{
    if (g_shm_map) return;
    // ALL_ACCESS: the menu issues write commands (comp_refresh / cmd_*) back
    // to the hook through the same mapping.
    g_shm_map = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, RC_SHM_NAME);
    if (!g_shm_map) {
        snprintf(g_shm_errstr, sizeof(g_shm_errstr),
            "shm: OpenFileMappingA('%s') failed err=%lu",
            RC_SHM_NAME, (unsigned long)GetLastError());
        return;
    }
    g_shm = (struct rc_shm_data *)MapViewOfFile(g_shm_map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(struct rc_shm_data));
    if (!g_shm || g_shm->magic != RC_SHM_MAGIC || g_shm->version != RC_SHM_VERSION) {
        snprintf(g_shm_errstr, sizeof(g_shm_errstr),
            "shm: map failed (view=%d) or bad header magic=%08X ver=%u",
            g_shm ? 1 : 0,
            g_shm ? (unsigned int)g_shm->magic : 0u,
            g_shm ? (unsigned int)g_shm->version : 0u);
        if (g_shm) { UnmapViewOfFile(g_shm); g_shm = NULL; }
        CloseHandle(g_shm_map); g_shm_map = NULL;
        return;
    }
    g_shm_ok = true;
}

static void shm_take_snapshot()
{
    if (!g_shm_ok || !g_shm) return;
    uint32_t s1, s2;
    do {
        s1 = g_shm->seq;
        memcpy(&g_snap, g_shm, sizeof(g_snap));
        s2 = g_shm->seq;
    } while (s1 != s2);
    if (s1 != g_snap_seq) {
        g_snap_seq = s1;
        g_snap_valid = true;
    }
}

// --------------------------------------------------------------- fx ----

// Bind a uniform by name, with a full-enumeration fallback. Direct
// find_uniform_variable fails under ReShade Performance Mode and when the
// effect-name argument does not match the loaded effect's file name; the
// enumeration path matches on the variable name alone (substring), so it
// works in both cases - including ReShade builds that prefix uniform names
// with the effect name (e.g. "HD2HUD/rc_hitmark").
static void bind_uniform(reshade::api::effect_runtime *rt, const char *name,
                         reshade::api::effect_uniform_variable *out)
{
    if (out->handle != 0) return;
    // 1) direct lookups by both plausible effect names
    *out = rt->find_uniform_variable("HD2HUD", name);
    if (out->handle == 0) *out = rt->find_uniform_variable("HD2HUD.fx", name);
    if (out->handle != 0) return;
    // 2) enumerate: try the exact file name first (a runtime may only expose
    //    uniforms under it), then the bare name, then ALL effects. Match by
    //    substring so prefixed names ("HD2HUD/rc_hitmark") also bind.
    auto try_enum = [rt, name, out](const char *effect_name) {
        if (out->handle != 0) return;
        rt->enumerate_uniform_variables(effect_name,
            [name, out](reshade::api::effect_runtime *r,
                        reshade::api::effect_uniform_variable v) {
                if (out->handle != 0) return;
                char vn[160]; size_t sz = sizeof(vn) - 1;
                r->get_uniform_variable_name(v, vn, &sz);
                vn[sz] = 0;
                if (strstr(vn, name) != nullptr)
                    *out = v;
            });
    };
    try_enum("HD2HUD.fx");
    try_enum("HD2HUD");
    try_enum(nullptr);
}

// Staged fx init, called every frame until ready:
//  - stage 1: find + enable the technique (handle exists immediately)
//  - stage 2: bind uniforms/texture - these only become visible AFTER
//    ReShade compiles the (lazy) effect, which happens async on later
//    frames, so we retry each frame instead of failing permanently.
//    (Observed on ReShade 6.8.0: technique found in the same frame that
//    enumerate_uniform_variables returned ZERO uniforms for every effect
//    including '<all>' - classic lazy-compile timing.)
// Reset every fx handle + state so fx_tick rebinds on the current runtime.
// Must be called whenever the effect runtime is destroyed/recreated
// (ResizeBuffers, fullscreen toggle, adapter change) - the cached handles are
// only valid on the runtime they were found on.
static void fx_reset_handles()
{
    g_tech = {};
    g_u_hitmark = {}; g_u_marks = {}; g_u_hitbox = {}; g_u_scanbox = {};
    g_u_mbox = {};
    g_u_mesh = {}; g_u_mesh_cfg = {}; g_u_mesh_rect = {};
    g_u_atlas_texture = {};
    g_u_atlas_cfg = {}; g_u_slots = {}; g_u_label_cfg = {}; g_u_label_w = {};
    g_fx_ready = false;
    g_fx_failed = false;
    g_fx_failed_rt = nullptr;
    g_fx_rt = nullptr;
    // Force the glyph atlas to re-render + re-upload on the new runtime
    // (the old texture resource was destroyed with the old runtime).
    g_atlas_rendered_rev = 0xFFFFFFFFu;
}

// ReShade destroys + recreates the effect runtime on ResizeBuffers /
// fullscreen toggles. Drop every cached handle before the old runtime goes
// away so nothing touches them afterwards.
static void on_destroy_effect_runtime(reshade::api::effect_runtime *rt)
{
    (void)rt;
    if (g_fx_rt != nullptr || g_fx_ready) {
        fx_reset_handles();
        reshade::log::message(reshade::log::level::info,
            "HD2 HUD: effect runtime destroyed, fx handles reset");
    }
}

static void fx_tick(reshade::api::effect_runtime *rt)
{
    if (g_fx_ready || rt == nullptr) return;
    // The game creates multiple effect runtimes (early D3D11 swapchains +
    // the real D3D12 one). A hard failure on one runtime must NOT poison
    // the others: track which runtime failed and retry fresh on another.
    if (g_fx_failed && g_fx_failed_rt == rt) return;
    if (g_fx_failed) g_fx_failed = false;

    // ---- stage 1: technique ----
    if (g_tech.handle == 0) {
        g_tech = rt->find_technique("HD2HUD", "HD2HUD");
        if (g_tech.handle == 0)
            g_tech = rt->find_technique("HD2HUD.fx", "HD2HUD");
        if (g_tech.handle == 0) {
            rt->enumerate_techniques(nullptr,
                [](reshade::api::effect_runtime *r, reshade::api::effect_technique t) {
                    if (g_tech.handle != 0) return;
                    char tn[160]; size_t sz = sizeof(tn) - 1;
                    r->get_technique_name(t, tn, &sz);
                    tn[sz] = 0;
                    if (strstr(tn, "HD2HUD") != nullptr) g_tech = t;
                });
        }
        if (g_tech.handle == 0) {
            snprintf(g_fx_errstr, sizeof(g_fx_errstr),
                "fx: technique 'HD2HUD' not found on this runtime");
            g_fx_failed = true;
            g_fx_failed_rt = rt;
            return;
        }
        rt->set_technique_state(g_tech, true);
        reshade::log::message(reshade::log::level::info,
            "HD2 HUD: technique found and enabled");
    }

    // ---- stage 2: uniforms / texture (retried until the effect compiles) ----
    if (g_u_hitmark.handle == 0) {
        bind_uniform(rt, "rc_hitmark", &g_u_hitmark);
        bind_uniform(rt, "rc_marks", &g_u_marks);
        bind_uniform(rt, "rc_hitbox", &g_u_hitbox);
        bind_uniform(rt, "rc_scanbox", &g_u_scanbox);
        bind_uniform(rt, "rc_mbox", &g_u_mbox);
        bind_uniform(rt, "rc_mesh", &g_u_mesh);
        bind_uniform(rt, "rc_mesh_cfg", &g_u_mesh_cfg);
        bind_uniform(rt, "rc_mesh_rect", &g_u_mesh_rect);
        bind_uniform(rt, "rc_atlas_cfg", &g_u_atlas_cfg);
        bind_uniform(rt, "rc_slots", &g_u_slots);
        bind_uniform(rt, "rc_label_cfg", &g_u_label_cfg);
        bind_uniform(rt, "rc_label_w", &g_u_label_w);

        g_u_atlas_texture = rt->find_texture_variable("HD2HUD", "rc_atlas");
        if (g_u_atlas_texture.handle == 0)
            g_u_atlas_texture = rt->find_texture_variable("HD2HUD.fx", "rc_atlas");
    }

    if (g_u_hitmark.handle != 0 && g_u_marks.handle != 0 &&
        g_u_hitbox.handle != 0 && g_u_scanbox.handle != 0 &&
        g_u_label_w.handle != 0) {
        g_fx_ready = true;
        g_fx_rt = rt;
        reshade::log::message(reshade::log::level::info,
            "HD2 HUD: fx uniforms ready, rendering via render pipeline");
        return;
    }

    // Still waiting for the effect to compile - warn at most every ~10s so
    // the log does not flood while we keep retrying silently each frame.
    static int miss_frames = 0;
    if ((++miss_frames % 600) == 0) {
        char line[192];
        snprintf(line, sizeof(line),
            "HD2 HUD: still waiting for uniforms hitmark=%d marks=%d hitbox=%d scanbox=%d",
            (int)(g_u_hitmark.handle == 0), (int)(g_u_marks.handle == 0),
            (int)(g_u_hitbox.handle == 0), (int)(g_u_scanbox.handle == 0));
        reshade::log::message(reshade::log::level::warning, line);
        snprintf(g_fx_errstr, sizeof(g_fx_errstr),
            "fx: waiting for uniforms hitmark=%d marks=%d hitbox=%d scanbox=%d",
            (int)(g_u_hitmark.handle == 0), (int)(g_u_marks.handle == 0),
            (int)(g_u_hitbox.handle == 0), (int)(g_u_scanbox.handle == 0));
    }
}
static void on_reshade_finish_effects(reshade::api::effect_runtime *rt,
    reshade::api::command_list *cmd_list,
    reshade::api::resource_view rtv,
    reshade::api::resource_view rtv_srgb)
{
    // Attach shared memory FIRST - independent of fx init. fx failure
    // must not block shm (it previously did: fx init failed ->
    // early return -> shm_attach never ran -> status bit1 always 0).
    shm_attach();
    // Runtime was recreated (ResizeBuffers / fullscreen toggle): cached
    // handles belong to the old runtime and would crash every
    // set_uniform_value_float below. Reset so fx_tick rebinds fresh.
    if (g_fx_rt != rt) fx_reset_handles();
    fx_tick(rt);
    if (!g_fx_ready) return;
    if (!g_shm_ok) return;
    shm_take_snapshot();
    if (!g_snap_valid) return;

    const struct rc_shm_data &s = g_snap;

    // ---- hit mark (yellow box at projected hit point) ----
    float hitm[4] = { 0, 0, 0, 0.02f };
    if (s.ui_hit[2]) {
        hitm[0] = s.ui_hit[0];
        hitm[1] = s.ui_hit[1];
        hitm[2] = 1.0f;
    }
    rt->set_uniform_value_float(g_u_hitmark, hitm, 4);

    // ---- hit box: 8 projected AABB corners -> 12-edge wireframe ----
    {
        static float hitbox_buf[8 * 4];
        for (int c = 0; c < 8; c++) {
            if (s.ui_hitbox[c][0] >= 0.0f && s.ui_hitbox[c][1] >= 0.0f) {
                hitbox_buf[c * 4 + 0] = s.ui_hitbox[c][0];
                hitbox_buf[c * 4 + 1] = s.ui_hitbox[c][1];
                hitbox_buf[c * 4 + 2] = 1.0f;
                hitbox_buf[c * 4 + 3] = 0.0f;
            } else {
                hitbox_buf[c * 4 + 0] = 0;
                hitbox_buf[c * 4 + 1] = 0;
                hitbox_buf[c * 4 + 2] = 0;
                hitbox_buf[c * 4 + 3] = 0;
            }
        }
        rt->set_uniform_value_float(g_u_hitbox, hitbox_buf, 8 * 4);
    }

    // ---- scan marks (yellow dots at projected box centers) ----
    static float marks_buf[64 * 4];
    uint32_t mcount = s.ui_mark_count < 128 ? s.ui_mark_count : 128;
    for (uint32_t i = 0; i < 64; i++) {
        if (i < mcount) {
            marks_buf[i * 4 + 0] = s.ui_marks[i][0];
            marks_buf[i * 4 + 1] = s.ui_marks[i][1];
            marks_buf[i * 4 + 2] = 1.0f;   // on
            marks_buf[i * 4 + 3] = 0.006f; // half size (normalized)
        } else {
            marks_buf[i * 4 + 0] = 0;
            marks_buf[i * 4 + 1] = 0;
            marks_buf[i * 4 + 2] = 0;
            marks_buf[i * 4 + 3] = 0;
        }
    }
    rt->set_uniform_value_float(g_u_marks, marks_buf, 64 * 4);

    // ---- scan box wireframes: up to 16 boxes x 8 corners ----
    {
        static float scanbuf[16 * 8 * 4];
        uint32_t sbc = s.ui_scanbox_count < 16 ? s.ui_scanbox_count : 16;
        for (uint32_t i = 0; i < 16 * 8; i++) {
            uint32_t bx = i / 8, cn = i % 8;
            if (bx < sbc && s.ui_scanbox[bx][cn][0] >= 0.0f && s.ui_scanbox[bx][cn][1] >= 0.0f) {
                scanbuf[i * 4 + 0] = s.ui_scanbox[bx][cn][0];
                scanbuf[i * 4 + 1] = s.ui_scanbox[bx][cn][1];
                scanbuf[i * 4 + 2] = 1.0f;
                scanbuf[i * 4 + 3] = (float)bx;
            } else {
                scanbuf[i * 4 + 0] = 0;
                scanbuf[i * 4 + 1] = 0;
                scanbuf[i * 4 + 2] = 0;
                scanbuf[i * 4 + 3] = 0;
            }
        }
        rt->set_uniform_value_float(g_u_scanbox, scanbuf, 16 * 8 * 4);
    }

    // ---- method-comparison boxes: 4 methods x 8 corners, color = w (0..3) ----
    if (g_u_mbox.handle != 0) {
        static float mbuf[4 * 8 * 4];
        for (int mi = 0; mi < 4; mi++) {
            for (int cn = 0; cn < 8; cn++) {
                int i = mi * 8 + cn;
                if (s.ui_mbox[mi][cn][0] >= 0.0f && s.ui_mbox[mi][cn][1] >= 0.0f) {
                    mbuf[i * 4 + 0] = s.ui_mbox[mi][cn][0];
                    mbuf[i * 4 + 1] = s.ui_mbox[mi][cn][1];
                    mbuf[i * 4 + 2] = 1.0f;
                    mbuf[i * 4 + 3] = (float)mi;  // color index
                } else {
                    mbuf[i * 4 + 0] = 0;
                    mbuf[i * 4 + 1] = 0;
                    mbuf[i * 4 + 2] = 0;
                    mbuf[i * 4 + 3] = -1.0f;
                }
            }
        }
        rt->set_uniform_value_float(g_u_mbox, mbuf, 4 * 8 * 4);
    }

    // ---- v3: real mesh outline edges (segments, 2 endpoints each) ----
    // Bounded to MESH_PTS (3072) to match HD2HUD.fx's rc_mesh[3072]; the
    // effect's constant buffer must stay under the D3D11 4096-entry limit.
    if (g_u_mesh.handle != 0) {
        static float meshbuf[3072 * 4];
        uint32_t mc = s.ui_mesh_count;
        if (mc > 3072) mc = 3072;
        for (uint32_t i = 0; i < 3072; i++) {
            if (i < mc) {   // C side already culled behind-cam/offscreen verts
                meshbuf[i * 4 + 0] = s.ui_mesh[i][0];
                meshbuf[i * 4 + 1] = s.ui_mesh[i][1];
                meshbuf[i * 4 + 2] = 1.0f;
                meshbuf[i * 4 + 3] = 0.0f;
            } else {
                meshbuf[i * 4 + 0] = 0;
                meshbuf[i * 4 + 1] = 0;
                meshbuf[i * 4 + 2] = 0;
                meshbuf[i * 4 + 3] = -1.0f;
            }
        }
        rt->set_uniform_value_float(g_u_mesh, meshbuf, 3072 * 4);

        // per-frame cheap gates for the fx: point count (so the shader does
        // not run a per-pixel count loop over all 3072 entries) plus the
        // mesh's screen-space AABB (so pixels far from the target skip the
        // edge loop entirely instead of testing every edge).
        if (g_u_mesh_cfg.handle != 0 && g_u_mesh_rect.handle != 0) {
            float cfgv[4] = { (float)mc, 0, 0, 0 };
            rt->set_uniform_value_float(g_u_mesh_cfg, cfgv, 4);
            float rminx = 1, rminy = 1, rmaxx = 0, rmaxy = 0;
            for (uint32_t i = 0; i < mc; i++) {
                float x0 = s.ui_mesh[i][0], y0 = s.ui_mesh[i][1];
                if (x0 < rminx) rminx = x0;
                if (y0 < rminy) rminy = y0;
                if (x0 > rmaxx) rmaxx = x0;
                if (y0 > rmaxy) rmaxy = y0;
            }
            if (rmaxx < rminx) { rminx = 0; rminy = 0; rmaxx = 0; rmaxy = 0; }
            float rectv[4] = { rminx, rminy, rmaxx, rmaxy };
            rt->set_uniform_value_float(g_u_mesh_rect, rectv, 4);
        }
    }

    // ---- self-rendered text: glyph atlas + label uniforms ----
    if (g_u_atlas_texture.handle != 0 && g_u_atlas_cfg.handle != 0 && g_u_slots.handle != 0 && g_u_label_cfg.handle != 0) {
        // render + upload the atlas only when the char set changed
        if (s.atlas_rev != g_atlas_rendered_rev) {
            // Mark the rev as handled REGARDLESS of render success, so a
            // failed/crashed render does not retry every frame (which would
            // re-crash repeatedly once the effect is active).
            g_atlas_rendered_rev = s.atlas_rev;
            if (render_atlas(s.atlas_chars, s.atlas_count)) {
                rt->update_texture(g_u_atlas_texture, (uint32_t)g_atlas_w, (uint32_t)g_atlas_h, g_atlas_px);
                char msg[128];
                snprintf(msg, sizeof(msg), "HD2 HUD: atlas updated (%ux%u, rev=%u)",
                    (unsigned)g_atlas_w, (unsigned)g_atlas_h, (unsigned)s.atlas_rev);
                reshade::log::message(reshade::log::level::info, msg);
            }
        }
        float cfg[4] = { (float)g_atlas_w, (float)g_atlas_h, (float)ATLAS_COLS, (float)ATLAS_CELL };
        rt->set_uniform_value_float(g_u_atlas_cfg, cfg, 4);

        // Label slots as FLOAT (int arrays over uniform int[64] proved
        // unreliable in ReShade 6.8 - newline sentinel -2 was lost and every
        // char rendered on one line). fx reads them from float4 rc_slots[16].
        int32_t n = s.label_count;
        if (n > 96) n = 96;
        float fslots[96];
        for (int i = 0; i < 96; i++) fslots[i] = (i < n) ? (float)s.label_slots[i] : -1.0f;
        rt->set_uniform_value_float(g_u_slots, fslots, 96);

        float fwidths[96];
        for (int i = 0; i < 96; i++) fwidths[i] = (i < n) ? s.label_widths[i] : 0.0f;
        rt->set_uniform_value_float(g_u_label_w, fwidths, 96);

        float on = (n > 0 && (s.flags & 1u)) ? 1.0f : 0.0f;
        float ax = 0.5f, ay = 0.5f;
        // anchor = top-center of the hit box: average X + topmost (min)
        // screen Y of the visible corners. The fx shader draws the label
        // ABOVE this point, so the text no longer covers the wireframe.
        if (s.flags & 1u) {
            float cx = 0;
            float cy = 1e30f;
            int k = 0;
            for (int c = 0; c < 8; c++) {
                if (s.ui_hitbox[c][0] >= 0 && s.ui_hitbox[c][1] >= 0) {
                    cx += s.ui_hitbox[c][0];
                    if (s.ui_hitbox[c][1] < cy) cy = s.ui_hitbox[c][1];
                    k++;
                }
            }
            if (k > 0) { ax = cx / k; ay = cy; }
        }
        float lc[4] = { ax, ay, (float)n, on };
        rt->set_uniform_value_float(g_u_label_cfg, lc, 4);
    }
}

// ------------------------------------------------------------ menu ----

// Component explorer menu (v4). Rendered from the reshade_overlay event
// (full ImGui interaction context). Ctrl+M toggles.
static bool g_menu_open = false;
static bool g_key_prev_ctrl_m = false;
static int g_sel_unit_idx = -1;
static int g_sel_item_idx = -1;
static uint32_t g_mem_base_off = 0;
static int g_edit_row = -1;
static char g_edit_hex[32];
static char g_edit_flt[32];
static int g_edit_mode = 0;

static void menu_hotkey()
{
    bool cm = ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_M);
    if (cm && !g_key_prev_ctrl_m) {
        g_menu_open = !g_menu_open;
        if (g_menu_open && g_shm) g_shm->comp_refresh = 1; // fresh data on open
    }
    g_key_prev_ctrl_m = cm;
}

static bool safe_read_dwords(uint64_t addr, uint32_t *out, int n)
{
    __try {
        for (int i = 0; i < n; i++) out[i] = *(volatile uint32_t *)(addr + i * 4);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static void issue_write_u32(uint64_t addr, uint32_t val)
{
    if (!g_shm) return;
    g_shm->cmd_addr = addr;
    g_shm->cmd_val32 = val;
    g_shm->cmd_valf = 0.0f;
    g_shm->cmd_type = 1;
    g_shm->cmd_seq++;
}

static void issue_write_f32(uint64_t addr, float val)
{
    if (!g_shm) return;
    g_shm->cmd_addr = addr;
    g_shm->cmd_valf = val;
    g_shm->cmd_val32 = 0;
    g_shm->cmd_type = 2;
    g_shm->cmd_seq++;
}

static void menu_render(const struct rc_shm_data &s)
{
    menu_hotkey();
    if (!g_menu_open) return;

    ImGui::SetNextWindowSize(ImVec2(760, 520), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(60, 60), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Component Explorer", &g_menu_open)) {
        ImGui::End();
        return;
    }

    ImGui::TextColored(ImVec4(1, 0.8f, 0.3f, 1), "units: %u   components: %u   types: %u",
        s.comp_unit_count, s.comp_item_count, s.comp_type_count);
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        if (g_shm) g_shm->comp_refresh = 1;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(Ctrl+M hides menu)");

    // ---- v5b: known component type names (captured via type-name hook) ----
    if (s.comp_type_count > 0) {
        if (ImGui::CollapsingHeader("Known component types")) {
            uint32_t shown = 0;
            for (uint32_t i = 0; i < s.comp_type_count && i < RC_COMP_MAX_TYPES; i++) {
                if (s.comp_types[i].name[0]) {
                    ImGui::Text("  [%u] %s", s.comp_types[i].type_id, s.comp_types[i].name);
                    shown++;
                }
            }
            if (!shown) ImGui::TextDisabled("  (none)");
        }
    }
    ImGui::Separator();

    // ---- live engine component events (captured via ODSW hook) ----
    if (s.comp_evt_count > 0) {
        ImGui::TextColored(ImVec4(0.4f, 1, 0.6f, 1), "engine events:");
        uint32_t n = s.comp_evt_count;
        int last = (int)(n % 6);
        for (int k = 0; k < 6; k++) {
            int idx = (last - k + 6) % 6;
            if ((int)n - k < 0) break;
            if (s.comp_evt[idx][0])
                ImGui::TextWrapped("%s", s.comp_evt[idx]);
        }
        ImGui::Separator();
    }

    // ---- unit list (left) + component table (right) ----
    float list_w = 210.0f;
    ImGui::BeginChild("unit_list", ImVec2(list_w, 0), true);
    for (uint32_t i = 0; i < s.comp_unit_count && i < RC_COMP_MAX_UNITS; i++) {
        int ncomp = 0;
        for (uint32_t k = 0; k < s.comp_item_count; k++)
            if (s.comp_items[k].unit == s.comp_units[i]) ncomp++;
        char buf[64];
        snprintf(buf, sizeof(buf), "unit %u  (%d)", s.comp_units[i], ncomp);
        if (ImGui::Selectable(buf, g_sel_unit_idx == (int)i)) {
            g_sel_unit_idx = (int)i;
            g_sel_item_idx = -1;
        }
    }
    ImGui::EndChild();
    ImGui::SameLine();

    ImGui::BeginChild("comp_table", ImVec2(0, 0), true);
    if (g_sel_unit_idx >= 0 && g_sel_unit_idx < (int)s.comp_unit_count) {
        uint32_t uid = s.comp_units[g_sel_unit_idx];
        ImGui::Text("components of unit %u:", uid);
        ImGui::Separator();
        ImGui::Columns(4);
        ImGui::Text("type"); ImGui::NextColumn();
        ImGui::Text("type id"); ImGui::NextColumn();
        ImGui::Text("obj addr"); ImGui::NextColumn();
        ImGui::Text("valid"); ImGui::NextColumn();
        ImGui::Separator();
        for (uint32_t k = 0; k < s.comp_item_count; k++) {
            const struct rc_comp_item &it = s.comp_items[k];
            if (it.unit != uid) continue;
            char buf[32];
            snprintf(buf, sizeof(buf), "%s##%u", it.type_name, k);
            if (ImGui::Selectable(buf, g_sel_item_idx == (int)k, ImGuiSelectableFlags_SpanAllColumns))
                g_sel_item_idx = (int)k;
            ImGui::NextColumn();
            ImGui::Text("%u", it.type_id); ImGui::NextColumn();
            snprintf(buf, sizeof(buf), "%llx", (unsigned long long)it.obj);
            ImGui::Text("%s", buf); ImGui::NextColumn();
            ImGui::Text("%s", it.valid ? "yes" : "no"); ImGui::NextColumn();
            ImGui::Separator();
        }
        ImGui::Columns(1);
    } else {
        ImGui::TextDisabled("select a unit on the left");
    }
    ImGui::EndChild();

    ImGui::Separator();

    // ---- memory viewer for the selected component ----
    if (g_sel_item_idx >= 0 && g_sel_item_idx < (int)s.comp_item_count) {
        const struct rc_comp_item &it = s.comp_items[g_sel_item_idx];
        uint64_t obj = it.obj;
        if (!obj) {
            ImGui::TextDisabled("component object address is null");
        } else {
            ImGui::Text("memory @ %llx  type=%s  unit=%u", (unsigned long long)obj, it.type_name, it.unit);
            ImGui::SameLine();
            if (ImGui::Button("+64")) g_mem_base_off += 64;
            ImGui::SameLine();
            if (ImGui::Button("-64") && g_mem_base_off >= 64) g_mem_base_off -= 64;
            ImGui::SameLine();
            ImGui::TextDisabled("offset 0x%x", g_mem_base_off);

            uint32_t dwords[32];
            if (safe_read_dwords(obj + g_mem_base_off, dwords, 32)) {
                ImGui::Columns(4);
                for (int r = 0; r < 8; r++) {
                    for (int c = 0; c < 4; c++) {
                        int idx = r * 4 + c;
                        uint32_t dv = dwords[idx];
                        float fv = *(float *)&dv;
                        uint64_t a = obj + g_mem_base_off + idx * 4;
                        ImGui::Text("+0x%03x", (unsigned)(g_mem_base_off + idx * 4));
                        ImGui::SameLine();
                        ImGui::Text("%08X", dv);
                        if (ImGui::IsItemClicked()) {
                            g_edit_row = idx;
                            snprintf(g_edit_hex, sizeof(g_edit_hex), "%08X", dv);
                            snprintf(g_edit_flt, sizeof(g_edit_flt), "%.4f", (double)fv);
                            g_edit_mode = 0;
                        }
                        ImGui::SameLine();
                        ImGui::Text("=%.3f", (double)fv);
                        ImGui::SameLine();
                        if (ImGui::SmallButton("W")) {
                            issue_write_u32(a, dv);
                            g_edit_row = idx;
                            snprintf(g_edit_hex, sizeof(g_edit_hex), "%08X", dv);
                            snprintf(g_edit_flt, sizeof(g_edit_flt), "%.4f", (double)fv);
                            g_edit_mode = 0;
                        }
                        if (g_edit_row == idx) {
                            ImGui::SameLine();
                            ImGui::PushID(idx);
                            if (g_edit_mode == 0) {
                                ImGui::SetNextItemWidth(120);
                                if (ImGui::InputText("hex", g_edit_hex, sizeof(g_edit_hex),
                                        ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_AutoSelectAll)) {
                                    uint32_t v = (uint32_t)strtoul(g_edit_hex, NULL, 16);
                                    if (ImGui::IsItemDeactivatedAfterEdit()) { issue_write_u32(a, v); g_edit_row = -1; }
                                }
                                ImGui::SameLine();
                                if (ImGui::SmallButton("float")) g_edit_mode = 1;
                            } else {
                                ImGui::SetNextItemWidth(120);
                                if (ImGui::InputText("flt", g_edit_flt, sizeof(g_edit_flt),
                                        ImGuiInputTextFlags_CharsDecimal | ImGuiInputTextFlags_AutoSelectAll)) {
                                    float v = (float)atof(g_edit_flt);
                                    if (ImGui::IsItemDeactivatedAfterEdit()) { issue_write_f32(a, v); g_edit_row = -1; }
                                }
                                ImGui::SameLine();
                                if (ImGui::SmallButton("hex")) g_edit_mode = 0;
                            }
                            ImGui::PopID();
                        }
                        ImGui::NextColumn();
                    }
                }
                ImGui::Columns(1);
                ImGui::TextDisabled("click a value to edit (hex or float); Enter commits the write");
            } else {
                ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1), "memory read failed (address no longer mapped)");
            }
        }
    }

    ImGui::End();
}

// F4 hit target's component list, drawn below the bottom-left hit panel.
// The C hook records each unit's world position (comp_unit_pos), so we can
// associate the hit point with the nearest unit and show its components.
static void draw_hit_comps(const struct rc_shm_data &s)
{
    if (!(s.flags & 1u)) return;
    if (s.comp_unit_count == 0 || s.comp_item_count == 0) return;
    int best = -1;
    float bestd = 1e30f;
    for (uint32_t i = 0; i < s.comp_unit_count; i++) {
        float dx = s.comp_unit_pos[i][0] - s.hit_x;
        float dy = s.comp_unit_pos[i][1] - s.hit_y;
        float dz = s.comp_unit_pos[i][2] - s.hit_z;
        float d = dx * dx + dy * dy + dz * dz;
        if (d < bestd) { bestd = d; best = (int)i; }
    }
    if (best < 0 || bestd > 400.0f) return; // unit farther than ~20 m: no match
    uint32_t uid = s.comp_units[best];
    ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(12, io.DisplaySize.y - 300), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(0.65f);
    ImGui::Begin("##hit_comps", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
        ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav |
        ImGuiWindowFlags_NoSavedSettings);
    ImGui::TextColored(ImVec4(0, 1, 0.5f, 1), "components (unit %u):", uid);
    int shown = 0;
    for (uint32_t k = 0; k < s.comp_item_count; k++) {
        if (s.comp_items[k].unit != uid) continue;
        if (shown >= 24) break;
        ImGui::Text("%s", s.comp_items[k].type_name);
        shown++;
    }
    if (shown == 0) ImGui::TextDisabled("(none)");
    ImGui::End();
}

// v10.6: command feedback is rendered by the game-side F4 label pipeline
// (glyph atlas + fx shader, row 5 of the target label). Nothing to draw
// here - this addon only needs to keep the shm mirror in sync.

static void on_reshade_overlay(reshade::api::effect_runtime *rt)
{
    (void)rt;
    shm_attach();
    if (!g_shm_ok) return;
    shm_take_snapshot();
    if (!g_snap_valid) return;
    draw_hit_comps(g_snap);
    menu_render(g_snap);
}

// ------------------------------------------------------------ lifecycle ----

extern "C" __declspec(dllexport) void hd2_addon_attach(HMODULE self_module)
{
    g_self = self_module;
}

extern "C" __declspec(dllexport) void hd2_addon_try_register()
{
    if (g_registered || g_self == NULL) return;
    HMODULE dxgi = GetModuleHandleA("dxgi.dll");
    if (dxgi == NULL) {
        OutputDebugStringW(L"[HD2-ADDON] dxgi.dll (ReShade) not loaded yet\n");
        return;
    }
    if (!reshade::register_addon(g_self)) {
        OutputDebugStringW(L"[HD2-ADDON] register_addon FAILED (ReShade loaded but registration rejected)\n");
        return;
    }
    reshade::register_event<reshade::addon_event::reshade_finish_effects>(on_reshade_finish_effects);
    reshade::register_event<reshade::addon_event::reshade_overlay>(on_reshade_overlay);
    reshade::register_event<reshade::addon_event::destroy_effect_runtime>(on_destroy_effect_runtime);
    g_registered = true;
    reshade::log::message(reshade::log::level::info,
        "HD2 HUD: addon registered (render-pipeline HUD, no menu dependency)");
    OutputDebugStringW(L"[HD2-ADDON] registered OK\n");
}

extern "C" __declspec(dllexport) void hd2_addon_detach()
{
    if (g_registered) {
        reshade::unregister_event<reshade::addon_event::reshade_finish_effects>(on_reshade_finish_effects);
        reshade::unregister_event<reshade::addon_event::reshade_overlay>(on_reshade_overlay);
        reshade::unregister_event<reshade::addon_event::destroy_effect_runtime>(on_destroy_effect_runtime);
        reshade::unregister_addon(g_self);
        g_registered = false;
    }
    if (g_shm) { UnmapViewOfFile(g_shm); g_shm = NULL; }
    if (g_shm_map) { CloseHandle(g_shm_map); g_shm_map = NULL; }
    g_shm_ok = false;
}

// Status for the C side (printed on F4): bit0=registered, bit1=shm attached,
// bit2=fx ready, bit3=fx failed. 0 = addon never registered.
extern "C" __declspec(dllexport) int hd2_addon_status()
{
    int st = 0;
    if (g_registered) st |= 1;
    if (g_shm_ok) st |= 2;
    if (g_fx_ready) st |= 4;
    if (g_fx_failed) st |= 8;
    return st;
}

// Last error details (fx init / shm attach) for the C side to print on F4.
// Returns "ok" when nothing failed. Never null.
extern "C" __declspec(dllexport) const char *hd2_addon_last_error()
{
    if (g_fx_failed && g_fx_errstr[0]) return g_fx_errstr;
    if (g_shm_errstr[0]) return g_shm_errstr;
    if (g_fx_failed) return "fx failed (no detail)";
    return "ok";
}
