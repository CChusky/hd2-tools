/* shm_proto.h - HD2RaycastShm 共享内存协议（与 hd2_raycast_hook.c 严格同步）
 * 版本 v4 + v10.4 cmd_feedback
 * 必须在 hook DLL 与 overlay 之间保持字段顺序/大小完全一致。
 */
#ifndef HD2_SHM_PROTO_H
#define HD2_SHM_PROTO_H

#include <stdint.h>

#define RC_SHM_NAME      "Local\\HD2RaycastShm"
#define RC_SHM_MAGIC     0x52434432u
#define RC_SHM_VERSION   4
#define RC_SHM_BOXES_MAX 256
#define RC_COMP_MAX_UNITS 64
#define RC_COMP_MAX_PER_UNIT 24
#define RC_COMP_MAX_ITEMS (RC_COMP_MAX_UNITS * RC_COMP_MAX_PER_UNIT)
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
    float ui_mbox[4][8][2];
    /* v3: hit-entity real mesh outline (projected edge endpoints 2 per edge) */
    uint32_t ui_mesh_count;
    float ui_mesh[8192][2];
    /* v2: self-rendered text atlas (chars + per-char slots) */
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
    struct rc_comp_type {
        uint32_t type_id;
        char name[48];
    } comp_types[RC_COMP_MAX_TYPES];
    uint32_t comp_item_count;
    struct rc_comp_item {
        uint32_t unit;
        uint32_t type_id;
        uint32_t valid;
        uint32_t flags;
        uint64_t obj;
        char type_name[48];
    } comp_items[RC_COMP_MAX_ITEMS];
    /* v4b: live engine component-log ring */
    uint32_t comp_evt_count;
    char comp_evt[6][192];
    uint32_t hit_unit_id;
    /* command area (overlay/addon -> hook) */
    volatile uint32_t cmd_seq;
    uint32_t cmd_type;               /* 0 none, 1 write u32, 2 write f32, 3 refresh */
    uint64_t cmd_addr;
    uint32_t cmd_val32;
    float    cmd_valf;
    volatile uint32_t cmd_done;
    /* v10.4: command feedback text (UTF-8) */
    char cmd_feedback[128];
};

#endif /* HD2_SHM_PROTO_H */
