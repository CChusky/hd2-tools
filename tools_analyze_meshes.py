# analyze_meshes.py - 分析 mesh_verts_<hash>.txt 的顶点范围/规模，定位轮廓线缩放/旋转/错位根因
# 对比基准: 5556372446766824087（已验证正常：站立角色，Z-up 高度沿 local Z）
import os, sys

DIR = r"D:\hd2_meshtables"
TARGETS = [
    6809717710676698319,  # 缩放过大
    144519363866445884,   # 仅几条线段
    3052213771053613071,  # 缩放过小
    17408101098277716919, # 错位
    16337047661043181516, # 错位
    14854391647447189818, # 错位（舰船头部）
    1382421291876450740,  # 旋转出错
    10736668254598913375, # 错位+旋转+缩放过小
    17180855900042354034, # 旋转错误
    5556372446766824087,  # 基准：站立角色（已验证正常）
]

def load(hash):
    p = os.path.join(DIR, f"mesh_verts_{hash}.txt")
    if not os.path.exists(p):
        return None
    verts, edges = [], []
    with open(p) as f:
        first = f.readline().strip()
        for line in f:
            parts = line.split()
            if len(parts) == 3:
                try:
                    verts.append((float(parts[0]), float(parts[1]), float(parts[2])))
                except ValueError:
                    pass
            elif len(parts) == 2:
                try:
                    edges.append((int(parts[0]), int(parts[1])))
                except ValueError:
                    pass
    return first, verts, edges

print(f"{'hash':<22} {'nvert':>6} {'nedg':>6} {'minX':>9} {'maxX':>9} {'minY':>9} {'maxY':>9} {'minZ':>9} {'maxZ':>9} {'spanX':>8} {'spanY':>8} {'spanZ':>8}")
for h in TARGETS:
    r = load(h)
    if r is None:
        print(f"{h:<22} FILE NOT FOUND")
        continue
    first, verts, edges = r
    if not verts:
        print(f"{h:<22} header={first} NO VERTS parsed")
        continue
    xs = [v[0] for v in verts]; ys = [v[1] for v in verts]; zs = [v[2] for v in verts]
    mnx, mxx = min(xs), max(xs); mny, mxy = min(ys), max(ys); mnz, mxz = min(zs), max(zs)
    print(f"{h:<22} {len(verts):>6} {len(edges):>6} {mnx:>9.3f} {mxx:>9.3f} {mny:>9.3f} {mxy:>9.3f} {mnz:>9.3f} {mxz:>9.3f} {mxx-mnx:>8.3f} {mxy-mny:>8.3f} {mxz-mnz:>8.3f}")
