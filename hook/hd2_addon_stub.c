// hd2_addon_stub.c - 纯数据采集版 hook 的 addon 空实现
// 用途：不链接 ReShade addon（hd2_addon_core.cpp）时提供同名函数，
// 让 hd2_raycast_hook.c 正常编译链接。渲染完全交给外部 overlay.exe。
// 构建: build_clean.bat（替代 build_v7.bat 的混合版）
#include <windows.h>

void hd2_addon_attach(HMODULE self_module) { (void)self_module; }
void hd2_addon_try_register(void) {}
void hd2_addon_detach(void) {}
int hd2_addon_status(void) { return 0; } /* 0 = none（无 addon） */
const char *hd2_addon_last_error(void) { return "no addon (pure data build)"; }
