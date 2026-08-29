/* mock_shm.c - 模拟游戏端写入 HD2RaycastShm，用于 overlay 渲染验证
 * 用法: 运行 overlay.exe 后运行本程序，overlay 将显示模拟锁定数据
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "shm_proto.h"

int main(void) {
    HANDLE m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                  0, sizeof(struct rc_shm_data), RC_SHM_NAME);
    if (!m) { printf("CreateFileMapping fail err=%lu\n", GetLastError()); return 1; }
    struct rc_shm_data *s = (struct rc_shm_data *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(struct rc_shm_data));
    if (!s) { printf("MapViewOfFile fail err=%lu\n", GetLastError()); return 1; }
    memset(s, 0, sizeof(*s));

    s->magic = RC_SHM_MAGIC;
    s->version = RC_SHM_VERSION;
    s->flags = 1; /* hit valid */
    s->hit_x = 10.0f; s->hit_y = 0.0f; s->hit_z = 20.0f;
    s->hit_dist = 12.5f;
    s->hit_hash64 = 0x75f7e96af7dcd303ULL; /* SEAF支援载荷一 */
    s->hit_thin = 0xd3ebefb9u;
    strcpy(s->hit_name, "SEAF士兵-测试");
    strcpy(s->hit_rn, "content/characters/npc/seaf");
    s->hit_unit_id = 5551;

    /* 命中标记（屏幕中心） */
    s->ui_hit[0] = 0.5f; s->ui_hit[1] = 0.5f; s->ui_hit[2] = 1.0f;

    /* 三角形轮廓（3 条边 = 6 点，归一化 0..1） */
    static const float tri[6][2] = {
        {0.40f, 0.35f}, {0.55f, 0.30f},
        {0.55f, 0.30f}, {0.52f, 0.45f},
        {0.52f, 0.45f}, {0.40f, 0.35f}
    };
    memcpy(s->ui_mesh, tri, sizeof(tri));
    s->ui_mesh_count = 6;

    /* AABB 8 角（底 0-3 / 顶 4-7） */
    static const float box[8][2] = {
        {0.30f, 0.55f}, {0.42f, 0.55f}, {0.42f, 0.62f}, {0.30f, 0.62f},
        {0.30f, 0.50f}, {0.42f, 0.50f}, {0.42f, 0.57f}, {0.30f, 0.57f}
    };
    memcpy(s->ui_hitbox, box, sizeof(box));

    strcpy(s->cmd_feedback, "上车命令执行成功");

    printf("mock_shm running: writing Local\\HD2RaycastShm ... (Ctrl+C to stop)\n");
    uint32_t n = 0;
    while (1) {
        s->seq = ++n;
        Sleep(100);
    }
    return 0;
}
