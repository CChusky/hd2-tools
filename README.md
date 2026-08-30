# HD2 Tools

Helldivers 2 modding tools: external target-lock overlay + in-game hook.

[简体中文](README_zh.md)

## Features

- **F4 ray-cast lock-on**: aim at a target, press F4 - identifies units / vehicles / interactables in real time
- **Real-time tracking**: label + wireframe outline follow the target as it moves (same position source, anti-teleport)
- **Numpad1 proximity scan**: lists nearby entity candidate boxes; aim at a box then press F4 to lock that exact entity (box-pick)
- **External transparent overlay**: target info shown in a standalone window (no ReShade / DebugView required)
- **Bilingual UI**: Simplified Chinese / English, hotkey switch
- **Multi-monitor aware**: overlay follows the monitor the game window is on

## Support

If this project is useful to you, you can buy me a coffee:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cchusky7680)

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
                        # loaded on demand - see "Mesh Database" below
```

## Mesh Database

**Release packages include the full mesh outline tables (`meshes\`, ~427MB) - extract and it just works.**

Mesh outline tables are loaded on demand with this search order:

1. `HD2_MESH_DIR` environment variable (point it at any folder containing the tables)
2. `meshes\` next to `hd2_raycast_hook.dll` (included in release / repo layout - clone and it just works)
3. Legacy `D:\hd2_meshtables`

Rebuild the tables with `meshes/build_all2.py`.

## Name Lookup Table

`hash_table.txt` maps unit hashes to friendly names (F4 lock label / Numpad1 scan). Load order:

1. `HD2_HASH_TABLE` environment variable (point it at the file)
2. `hash_table.txt` next to `hd2_raycast_hook.dll`

Without it the tools still work - hashes are shown as raw hex instead of names.

## Build

Requires Visual Studio 2022 (MSVC x64) + Windows SDK.

```
overlay:  hd2_overlay\build_overlay.bat   -> overlay.exe
hook:     build_clean.bat                 -> hd2_raycast_hook.dll (pure data, F4 + Numpad1)
injector: build_watcher.bat               -> watcher.exe
```

## Usage

1. Use `hd2_raycast_hook.dll` (built by `build_clean.bat`), place next to `watcher.exe`
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

## License

[PolyForm Noncommercial License 1.0.0](LICENSE) - non-commercial use only.
Personal, research and noncommercial-organization use is permitted; any
commercial purpose requires permission from the licensor.

## Disclaimer

For educational/research purposes only. Modding may violate the game's ToS; use at your own risk.
