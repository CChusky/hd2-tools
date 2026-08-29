# HD2 Tools

Helldivers 2 模组工具集：外部目标锁定覆盖层 + 游戏内 hook。

[English](README.md)

## 功能

- **F4 射线锁定**：对准目标按 F4，实时识别实体（单位 / 载具 / 可交互物）
- **实时追踪**：锁定目标移动时，数据标签与模型轮廓线框实时跟随
- **外部透明覆盖层**：目标信息通过独立透明窗口显示（无需 ReShade / DebugView）
- **中英双语界面**：内置简体中文 / English，热键即时切换
- **多显示器支持**：overlay 自动跟随游戏窗口所在屏幕

## 目录结构

```
hd2-tools/
├── README.md            # English docs
├── README_zh.md         # 中文文档
├── overlay/             # 外部透明覆盖层（用户界面）
│   ├── overlay.c        # 主程序：窗口 + 渲染 + 配置 + 本地化
│   ├── shm_proto.h      # 共享内存协议（与 hook 同步）
│   ├── mock_shm.c       # 模拟数据源（开发验证）
│   ├── config.ini       # 配置（语言 / 显示 / 缩放 / 显示器）
│   ├── lang_zh.ini / lang_en.ini
│   └── build_overlay.bat
├── hook/                # 游戏内 hook（纯数据采集，不依赖 ReShade）
│   ├── hd2_raycast_hook.c
│   ├── hd2_addon_stub.c
│   ├── watcher.c        # 自动注入器（游戏启动时注入）
│   ├── dll_injector.c   # 手动注入器
│   └── build_clean.bat / build_watcher.bat
└── meshes/              # 离线 mesh 轮廓表（mesh_verts_<hash>.txt，共 5668 表）
                        # 按需加载，位置见下方"Mesh 数据库"
```

## Mesh 数据库

mesh 轮廓表按以下优先级加载：

1. 环境变量 `HD2_MESH_DIR`（指向任意存放表的文件夹）
2. hook DLL 同目录的 `meshes\`（仓库布局——clone 下来即可用）
3. 旧路径 `D:\hd2_meshtables`

重新生成表：`meshes/build_all2.py`。

## 名称对照表

`hash_table.txt` 把单位哈希映射为易读名称（F4 锁定标签 / Numpad1 扫描输出）。加载优先级：

1. 环境变量 `HD2_HASH_TABLE`（指向该文件）
2. hook DLL 同目录的 `hash_table.txt`

没有对照表时工具仍可工作，只是哈希显示为十六进制而非名称。

## 构建

需要 Visual Studio 2022（MSVC x64）+ Windows SDK。

```
overlay:  hd2_overlay\build_overlay.bat   -> overlay.exe
hook:     build_clean.bat                 -> hd2_raycast_hook.dll（纯数据版，仅 F4 + Numpad1）
injector: build_watcher.bat               -> watcher.exe
```

## 使用

1. 将编译产物 `hd2_raycast_hook.dll` 放到 `watcher.exe` 同目录
2. 启动游戏，运行 `watcher.exe`（自动注入，纯数据采集）
3. 运行 `overlay.exe`（透明窗口显示锁定信息，自动跟随游戏所在屏幕）
4. 游戏内按 `F4` 锁定目标，overlay 面板实时显示

## 配置（`overlay/config.ini`）

| Key | 说明 | 默认 |
|---|---|---|
| `lang` | 语言 zh / en | zh |
| `show_panel` | 信息面板 | 1 |
| `show_line` | 轮廓线框 | 1 |
| `show_mark` | 命中标记 | 1 |
| `scale` | 面板缩放 | 1.0 |
| `monitor` | -1 跟随游戏窗口 / 0 主屏 / N 指定屏 | -1 |

热键：`Ctrl+Shift+L` 切换语言，`Ctrl+Shift+H` 显示/隐藏，`Ctrl+Shift+Q` 退出。

## 数据通道

hook 与 overlay 通过共享内存 `Local\HD2RaycastShm`（v4）通信：
锁定目标（名称 / 哈希 / 距离）、相机参数、投影线框点、命令通道、反馈文本。

## 赞助

如果这个项目对你有帮助，可以请我喝杯咖啡：

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cchusky7680)

## 许可

[PolyForm Noncommercial License 1.0.0](LICENSE)——仅限非商业用途。
允许个人、研究及非商业组织使用；任何商业目的均需获得版权所有者许可。

## 免责声明

本工具用于学习和研究目的。使用模组可能违反游戏服务条款，请自行承担风险。
