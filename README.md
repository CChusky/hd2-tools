# HD2 Tools

Helldivers 2 modding tools: external target-lock overlay + in-game hook.

[简体中文](README_zh.md)

## Features

- **F4 ray-cast lock-on**: aim at a target, press F4 - identifies units / vehicles / interactables in real time
- **Real-time tracking**: label + wireframe outline follow the target as it moves
- **External transparent overlay**: target info shown in a standalone window (no ReShade / DebugView required)
- **Bilingual UI**: Simplified Chinese / English, hotkey switch
- **Multi-monitor aware**: overlay follows the monitor the game window is on

## Layout

```
hd2-tools/
├── README.md            # English docs
├── README_zh.md         # 中文文档
├── overlay/             # external transparent overlay (UI)
│   ├── overlay.c        # window + render + config + i18n
│   ├── shm_proto.h      # shared memory protocol (synced with hook)
│   ├── mock_shm.c       # mock data source (dev verification)
│   ├── config.ini       # config (language / display / scale / monitor)
│   ├── lang_zh.ini / lang_en.ini
│   └── build_overlay.bat
├── hook/                # in-game hook (pure data capture, no ReShade)
│   ├── hd2_raycast_hook.c
│   ├── hd2_addon_stub.c
│   ├── watcher.c        # auto injector
│   ├── dll_injector.c   # manual injector
│   └── build_clean.bat / build_watcher.bat
└── meshes/              # offline mesh outline tables (mesh_verts_<hash>.txt, 5668 tables)
                        # loaded on demand from D:\hd2_meshtables\ (or rebuilt with build_all2.py)
```

## Versions

Two builds exist; core recognition logic is identical, display differs:

| | External-window (recommended) | ReShade (optional) |
|---|---|---|
| hook | pure data capture (shared memory only) | mixed build (in-game rendering) |
| display | `overlay.exe` external transparent window | ReShade in-game HUD (crosshair / wireframe) |
| dependencies | none (no ReShade / DebugView) | ReShade runtime |
| audience | regular players, plug-and-play | users who want an in-game HUD |

- External-window build: full source in this repo (`hook/` + `overlay/` + `meshes/`)
- ReShade build: `build_v7.bat` + `hd2_addon/` (ReShade SDK), kept locally, not published here

## Switch Between Versions

`watcher.exe` always injects the fixed filename `hd2_raycast_hook.dll` - **switching = replacing that one file**:

1. **External-window**: rename `build_clean.bat` output to `hd2_raycast_hook.dll` -> run `overlay.exe`
2. **ReShade**: rename `build_v7.bat` output to `hd2_raycast_hook.dll` -> in-game HUD (needs ReShade), no overlay

Both share the same `watcher.exe` and `meshes/` tables. Restart the game after switching.

## Build

Requires Visual Studio 2022 (MSVC x64) + Windows SDK.

```
overlay:  hd2_overlay\build_overlay.bat   -> overlay.exe
hook:     build_clean.bat                 -> hd2_raycast_hook_clean.dll (pure data)
injector: build_watcher.bat               -> watcher.exe
```

## Usage

1. Rename `hd2_raycast_hook_clean.dll` to `hd2_raycast_hook.dll`, place next to `watcher.exe`
2. Start the game, run `watcher.exe` (auto-inject, pure data capture)
3. Run `overlay.exe` (transparent window, follows the game's monitor)
4. Press `F4` in-game to lock a target - overlay shows the info

## Config (`overlay/config.ini`)

| Key | Description | Default |
|---|---|---|
| `lang` | zh / en | zh |
| `show_panel` | info panel | 1 |
| `show_line` | wireframe outline | 1 |
| `show_mark` | hit marker | 1 |
| `scale` | panel scale | 1.0 |
| `monitor` | -1 follow game / 0 primary / N monitor index | -1 |

Hotkeys: `Ctrl+Shift+L` language, `Ctrl+Shift+H` show/hide, `Ctrl+Shift+Q` quit.

## Data Channel

hook <-> overlay via shared memory `Local\HD2RaycastShm` (v4):
locked target (name / hash / distance), camera params, projected wireframe points, command channel, feedback text.

## Disclaimer

For educational/research purposes only. Modding may violate the game's ToS; use at your own risk.
