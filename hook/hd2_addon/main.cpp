/*
 * HD2 Raycast HUD - ReShade addon
 * Reads shared memory written by hd2_raycast_hook.dll (game-thread Lua
 * scans) and draws an ImGui overlay (hit target info + scan box list).
 *
 * ReShade addon contract:
 *   - file named *.addon64 in the game directory
 *   - exports AddonInit(HMODULE, HMODULE) -> bool
 *   - optional metadata exports NAME/AUTHOR/DESCRIPTION/...
 */

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
    /* v4: component explorer */
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
};

static HANDLE g_shm_map = NULL;
static struct rc_shm_data *g_shm = NULL;
static bool g_connected = false;
static uint32_t g_snap_seq = 0;

// Snapshot taken under seq double-read (writer bumps seq after commit)
static struct rc_shm_data g_snap;
static bool g_snap_valid = false;

static void shm_attach()
{
    if (g_shm_map) return;
    // ALL_ACCESS: the menu issues write commands (comp_refresh / cmd_*) back
    // to the hook through the same mapping.
    g_shm_map = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, RC_SHM_NAME);
    if (!g_shm_map) return;
    g_shm = (struct rc_shm_data *)MapViewOfFile(g_shm_map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(struct rc_shm_data));
    if (!g_shm) { CloseHandle(g_shm_map); g_shm_map = NULL; return; }
    if (g_shm->magic != RC_SHM_MAGIC || g_shm->version != RC_SHM_VERSION) {
        g_connected = false;
        return;
    }
    g_connected = true;
    reshade::log::message(reshade::log::level::info, "HD2 HUD: shared memory attached (v4)");
}

static void shm_take_snapshot()
{
    if (!g_connected || !g_shm) return;
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

// ---- component explorer menu (v4) ----
static bool g_menu_open = false;
static bool g_key_prev_ctrl_m = false;
static int g_sel_unit_idx = -1;   // index into comp_units
static int g_sel_item_idx = -1;   // global index into comp_items
static uint32_t g_mem_base_off = 0; // byte offset into the component object
static int g_edit_row = -1;       // which dword row is being edited (-1 none)
static char g_edit_hex[32];
static char g_edit_flt[32];
static int g_edit_mode = 0;       // 0 hex u32, 1 float

static void menu_hotkey()
{
    bool cm = ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_M);
    if (cm && !g_key_prev_ctrl_m) {
        g_menu_open = !g_menu_open;
        if (g_menu_open && g_shm) g_shm->comp_refresh = 1; // fresh data on open
    }
    g_key_prev_ctrl_m = cm;
}

// SEH-protected read of 32 dwords at a game address (we are in the game proc).
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
    ImGui::Separator();

    // ---- unit list (left) + component table (right) ----
    float list_w = 210.0f;
    ImGui::BeginChild("unit_list", ImVec2(list_w, 0), true);
    for (uint32_t i = 0; i < s.comp_unit_count && i < RC_COMP_MAX_UNITS; i++) {
        // count components for this unit
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
        // header
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
                        char label[48];
                        snprintf(label, sizeof(label), "##m%02d", idx);
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
                            issue_write_u32(a, dv); // rewrite same (no-op sanity)
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
                                if (ImGui::SmallButton("float")) {
                                    g_edit_mode = 1;
                                }
                            } else {
                                ImGui::SetNextItemWidth(120);
                                if (ImGui::InputText("flt", g_edit_flt, sizeof(g_edit_flt),
                                        ImGuiInputTextFlags_CharsDecimal | ImGuiInputTextFlags_AutoSelectAll)) {
                                    float v = (float)atof(g_edit_flt);
                                    if (ImGui::IsItemDeactivatedAfterEdit()) { issue_write_f32(a, v); g_edit_row = -1; }
                                }
                                ImGui::SameLine();
                                if (ImGui::SmallButton("hex")) {
                                    g_edit_mode = 0;
                                }
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

// ---- overlay callback (called every frame inside ReShade's ImGui frame) ----
static void on_reshade_overlay(reshade::api::effect_runtime *runtime)
{
    shm_attach();
    if (!g_connected) {
        // Draw a tiny "no data" hint so the addon is visibly alive
        ImGui::GetBackgroundDrawList()->AddText(ImVec2(12, 12), IM_COL32(255, 255, 0, 200), "HD2 HUD: waiting for hook dll...");
        return;
    }
    shm_take_snapshot();
    if (!g_snap_valid) return;

    const struct rc_shm_data &s = g_snap;
    ImDrawList *dl = ImGui::GetBackgroundDrawList();

    // ---------- hit target panel (bottom-left) ----------
    if (s.flags & 1u) {
        char line[512];
        // Name / hash line
        snprintf(line, sizeof(line), "Target: %s", s.hit_name[0] ? s.hit_name : "(unknown)");
        ImVec2 tsz = ImGui::CalcTextSize(line);
        float w = tsz.x + 24.0f;
        float h = 108.0f;
        float x0 = 12.0f, y0 = ImGui::GetIO().DisplaySize.y - h - 12.0f;

        // background
        dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x0 + w, y0 + h), IM_COL32(0, 0, 0, 180), 6.0f);
        dl->AddRect(ImVec2(x0, y0), ImVec2(x0 + w, y0 + h), IM_COL32(0, 220, 0, 220), 6.0f, 0, 2.0f);

        float tx = x0 + 12.0f, ty = y0 + 10.0f;
        dl->AddText(ImVec2(tx, ty), IM_COL32(0, 255, 120, 255), line); ty += 20.0f;

        snprintf(line, sizeof(line), "hash: %016llX  thin:%08X",
            (unsigned long long)s.hit_hash64, s.hit_thin);
        dl->AddText(ImVec2(tx, ty), IM_COL32(220, 220, 220, 255), line); ty += 18.0f;

        snprintf(line, sizeof(line), "dist: %.1f m", s.hit_dist);
        dl->AddText(ImVec2(tx, ty), IM_COL32(255, 200, 0, 255), line); ty += 18.0f;

        snprintf(line, sizeof(line), "pos: (%.2f, %.2f, %.2f)", s.hit_x, s.hit_y, s.hit_z);
        dl->AddText(ImVec2(tx, ty), IM_COL32(180, 180, 180, 255), line); ty += 18.0f;

        snprintf(line, sizeof(line), "rn: %.60s", s.hit_rn);
        dl->AddText(ImVec2(tx, ty), IM_COL32(120, 120, 120, 255), line); ty += 18.0f;

        // green distance bar
        float bw = w - 24.0f;
        float frac = (s.hit_dist > 0.0f) ? (s.hit_dist < 100.0f ? s.hit_dist / 100.0f : 1.0f) : 0.0f;
        dl->AddRectFilled(ImVec2(tx, ty), ImVec2(tx + bw, ty + 6), IM_COL32(255, 255, 255, 40));
        dl->AddRectFilled(ImVec2(tx, ty), ImVec2(tx + bw * frac, ty + 6), IM_COL32(0, 255, 0, 220));
    }

    // ---------- scan box count (bottom-right) ----------
    if (s.flags & 2u) {
        char line[128];
        snprintf(line, sizeof(line), "entities: %u", s.box_count);
        ImVec2 tsz = ImGui::CalcTextSize(line);
        ImVec2 pos(ImGui::GetIO().DisplaySize.x - tsz.x - 16.0f, ImGui::GetIO().DisplaySize.y - 32.0f);
        dl->AddText(pos, IM_COL32(255, 220, 0, 220), line);
    }

    // ---------- camera debug (top-left, subtle) ----------
    {
        char line[128];
        snprintf(line, sizeof(line), "cam (%.1f, %.1f, %.1f)", s.cam_x, s.cam_y, s.cam_z);
        dl->AddText(ImVec2(12, 36), IM_COL32(120, 120, 120, 160), line);
    }

    // ---------- component explorer menu (Ctrl+M) ----------
    menu_render(s);
}

// ---- addon metadata ----
extern "C" __declspec(dllexport) const char *NAME = "HD2 Raycast HUD";
extern "C" __declspec(dllexport) const char *DESCRIPTION = "Shows hit-target info (name/hash/distance) and scanned entity count, fed by the HD2 Lua hook dll over shared memory.";
extern "C" __declspec(dllexport) const char *AUTHOR = "trae";
extern "C" __declspec(dllexport) const char *WEBSITE = "";
extern "C" __declspec(dllexport) const char *ISSUES = "";

// ---- addon entry points ----
extern "C" __declspec(dllexport) bool AddonInit(HMODULE addon_module, HMODULE reshade_module)
{
    if (!reshade::register_addon(addon_module, reshade_module))
        return false;

    reshade::register_event<reshade::addon_event::reshade_overlay>(on_reshade_overlay);

    reshade::log::message(reshade::log::level::info, "HD2 HUD: addon initialized");
    return true;
}

extern "C" __declspec(dllexport) void AddonUninit(HMODULE addon_module, HMODULE reshade_module)
{
    reshade::unregister_event<reshade::addon_event::reshade_overlay>(on_reshade_overlay);
    reshade::unregister_addon(addon_module, reshade_module);

    if (g_shm) { UnmapViewOfFile(g_shm); g_shm = NULL; }
    if (g_shm_map) { CloseHandle(g_shm_map); g_shm_map = NULL; }
}
