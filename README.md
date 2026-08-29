# HD2 Tools

Helldivers 2 模组工具集：外部目标锁定覆盖层（overlay）+ 游戏内 hook。
Helldivers 2 modding tools: external target-lock overlay + in-game hook.

## 功能 Features

- **F4 射线锁定**：对准目标按 F4，实时识别实体（单位 / 载具 / 可交互物）
- **实时追踪**：锁定目标移动时，数据标签与模型轮廓线框实时跟随
- **外部透明覆盖层**：游戏内信息通过独立透明窗口显示（无需 ReShade / DebugView）
- **中英双语界面**：内置简体中文 / English，热键即时切换

- F4 ray-cast lock-on with real-time entity identification
- Real-time tracking: label + wireframe outline follow the target
- External transparent overlay (no ReShade / DebugView required)
- Bilingual UI (Simplified Chinese / English) with hotkey switch

## 目录结构 Layout

```
hd2-tools/
├── README.md
├── overlay/            # 外部透明覆盖层（用户界面）
│   ├── overlay.c       # 主程序：窗口 + 渲染 + 配置 + 本地化
│   ├── shm_proto.h     # 共享内存协议（与 hook 同步）
│   ├── mock_shm.c      # 模拟数据源（开发验证）
│   ├── config.ini      # 配置（语言 / 显示 / 缩放 / 显示器）
│   ├── lang_zh.ini     # 简体中文
│   ├── lang_en.ini     # English
│   └── build_overlay.bat
└── hook/               # 游戏内 hook（纯数据采集，不依赖 ReShade）
    ├── hd2_raycast_hook.c
    ├── hd2_addon_stub.c    # addon 空实现（纯数据版）
    ├── watcher.c           # 自动注入器（游戏启动时注入）
    ├── dll_injector.c      # 手动注入器
    └── build_clean.bat / build_watcher.bat
└── meshes/             # 离线 mesh 轮廓表（mesh_verts_<hash>.txt, 5668 表）
                        # 运行时按需加载到 D:\hd2_meshtables\（或 build_all2.py 重新生成）
```

## 版本说明 Versions

本项目有**两个版本**，显示方式不同，核心识别逻辑相同：

| | 外部窗口版（推荐） | ReShade 版（可选） |
|---|---|---|
| hook | 纯数据采集（只写共享内存） | 混合版（含游戏内渲染） |
| 显示 | `overlay.exe` 外部透明窗口 | ReShade 游戏内 HUD（准心/线框） |
| 依赖 | 无（不需要 ReShade/DebugView） | ReShade 运行时 |
| 适用 | 普通玩家，开箱即用 | 需要游戏内 HUD 的用户 |

- 外部窗口版：本仓库完整源码（`hook/` + `overlay/` + `meshes/`）
- ReShade 版：构建脚本 `build_v7.bat` + `hd2_addon/`（ReShade SDK），本地保留、未随仓库发布

## 版本切换 Switch

`watcher.exe` 注入固定文件名 `hd2_raycast_hook.dll`——**切换版本 = 替换这一个文件**：

1. **用外部窗口版**：`build_clean.bat` 产物重命名为 `hd2_raycast_hook.dll` → 运行 `overlay.exe` 看显示
2. **用 ReShade 版**：`build_v7.bat` 产物重命名为 `hd2_raycast_hook.dll` → 游戏内看 HUD（需 ReShade 环境），不开 overlay

两版共用同一 `watcher.exe` 注入器和 `meshes/` 轮廓表，切换后重启游戏注入即生效。

## 构建 Build

需要 Visual Studio 2022（MSVC x64）+ Windows SDK。

```
overlay:  hd2_overlay\build_overlay.bat   -> overlay.exe
hook:     build_clean.bat                 -> hd2_raycast_hook_clean.dll（纯数据版）
injector: build_watcher.bat               -> watcher.exe
```

## 使用 Usage

1. 将 `hd2_raycast_hook_clean.dll` 重命名为 `hd2_raycast_hook.dll`，放到 `watcher.exe` 同目录
2. 启动游戏，运行 `watcher.exe`（自动注入，纯数据采集）
3. 运行 `overlay.exe`（透明窗口显示锁定信息，自动跟随游戏所在屏幕）
4. 游戏内按 `F4` 锁定目标，overlay 面板实时显示

## 配置 Config (`overlay/config.ini`)

| Key | 说明 | 默认 |
|---|---|---|
| `lang` | 语言 zh / en | zh |
| `show_panel` | 信息面板 | 1 |
| `show_line` | 轮廓线框 | 1 |
| `show_mark` | 命中标记 | 1 |
| `scale` | 面板缩放 | 1.0 |
| `monitor` | -1 跟随游戏窗口 / 0 主屏 / N 指定屏 | -1 |

热键：`Ctrl+Shift+L` 切换语言，`Ctrl+Shift+H` 显示/隐藏。

## 数据通道 Data Channel

hook 与 overlay 通过共享内存 `Local\HD2RaycastShm`（v4）通信：
锁定目标（名称 / 哈希 / 距离）、相机参数、投影线框点、命令通道、反馈文本。

## 免责声明 Disclaimer

本工具用于学习和研究目的。使用模组可能违反游戏服务条款，请自行承担风险。
For educational/research purposes only. Modding may violate the game's ToS; use at your own risk.
