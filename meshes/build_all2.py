# Rebuild mesh tables with EDGES: format = header + verts + edges
#   line1: <hash> <nverts> <nedges>
#   then nverts lines: x y z (local space)
#   then nedges lines: ia ib (vertex index pair)
# Run with a pack name: python build_all2.py <pack>
import sys, os, types, importlib, struct, glob

# --- minimal mathutils mock ---
class _Mat:
    def __init__(self):
        self.rows = [[0.0]*4 for _ in range(4)]
        for i in range(4): self.rows[i][i] = 1.0
    def __setitem__(self, i, v): self.rows[i] = list(v)
    def __getitem__(self, i): return self.rows[i]
    def transpose(self):
        self.rows = [list(c) for c in zip(*self.rows)]
class _Vec:
    def __init__(self, xyz):
        self.x, self.y, self.z = float(xyz[0]), float(xyz[1]), float(xyz[2])
    def normalized(self):
        l = (self.x*self.x + self.y*self.y + self.z*self.z) ** 0.5
        if l < 1e-12: return _Vec((0.0, 0.0, 0.0))
        return _Vec((self.x/l, self.y/l, self.z/l))
    def to_tuple(self): return (self.x, self.y, self.z)
    def __getitem__(self, i): return (self.x, self.y, self.z)[i]
_mu = types.ModuleType('mathutils')
_mu.Matrix = types.SimpleNamespace(Identity=lambda n: _Mat())
_mu.Vector = _Vec
sys.modules['mathutils'] = _mu

fake_bpy = types.ModuleType('bpy')
class _App: version = (4, 0, 0)
fake_bpy.app = _App()
class _Settings:
    def __getattr__(self, name): return False
class _Scene:
    def __init__(self): self.Hd2ToolPanelSettings = _Settings()
fake_bpy.context = types.SimpleNamespace(scene=_Scene())
class _Mats:
    def get(self, n): return None
    def new(self, n): return None
    def __getitem__(self, n): return None
    def __contains__(self, n): return False
fake_bpy.data = types.SimpleNamespace(materials=_Mats())
fake_bpy.types = types.SimpleNamespace()
sys.modules['bpy'] = fake_bpy
sys.modules['bmesh'] = types.ModuleType('bmesh')

SDK = r'C:\Users\Administrator\AppData\Roaming\Blender Foundation\Blender\4.3\scripts\addons\HD2SDK-CommunityEdition'
DATA = r'D:\SteamLibrary\steamapps\common\Helldivers 2\data'
pkg = types.ModuleType('hd2sdk'); pkg.__path__ = [SDK]; sys.modules['hd2sdk'] = pkg
for sub in ('utils', 'stingray'):
    m = types.ModuleType('hd2sdk.' + sub); m.__path__ = [os.path.join(SDK, sub)]
    m.__package__ = 'hd2sdk.' + sub; sys.modules['hd2sdk.' + sub] = m
slim = importlib.import_module('hd2sdk.utils.slim')
unit_m = importlib.import_module('hd2sdk.stingray.unit')
comp_m = importlib.import_module('hd2sdk.stingray.composite_unit')
from hd2sdk.utils.memoryStream import MemoryStream

slim.slim_init(DATA)

UNIT_TYPE = 0xe0a48d0be9a7453f
COMPOSITE_TYPE = 0xc4f0f4be7fb0c8d6
OUT_DIR = r'D:\hd2_meshtables'
MAX_VERTS = 4096
MAX_EDGES = 8192

def parse_entries(pname):
    head = slim.get_package_toc(pname)
    if len(head) < 12: return None
    if int.from_bytes(head[0:4], 'little') != 4026531857: return None
    numTypes = int.from_bytes(head[4:8], 'little')
    numFiles = int.from_bytes(head[8:12], 'little')
    base = 12 + 60 + numTypes * 32
    entries = {}
    for i in range(numFiles):
        e = base + i * 80
        if e + 80 > len(head): break
        fid, tid = struct.unpack_from('<QQ', head, e)
        toc_off, stream_off, gpu_off = struct.unpack_from('<QQQ', head, e + 16)
        toc_sz = struct.unpack_from('<I', head, e + 56)[0]
        gpu_sz = struct.unpack_from('<I', head, e + 64)[0]
        entries[fid] = (tid, toc_off, toc_sz, gpu_off, gpu_sz)
    return entries

class EntryObj:
    def __init__(self, loader, fid, tid):
        self.loader = loader; self.FileID = fid; self.TypeID = tid
        self.LoadedData = None
    def Load(self, Reload=False):
        if self.LoadedData is not None: return
        e = self.loader.entries.get(self.FileID)
        if not e: return
        tid, toc_off, toc_sz, gpu_off, gpu_sz = e
        toc = self.loader.pkg[toc_off:toc_off+toc_sz]
        gpu = self.loader.gpu[gpu_off:gpu_off+gpu_sz] if self.loader.gpu else b''
        if not toc: return
        cm = comp_m.StingrayCompositeMesh()
        try:
            cm.Serialize(MemoryStream(toc), MemoryStream(gpu))
            self.LoadedData = cm
        except Exception:
            self.LoadedData = None

class GTM:
    def __init__(self, loader):
        self.loader = loader; self.cache = {}
    def GetEntry(self, h, t, SearchAll=False, IgnorePatch=False):
        e = self.loader.entries.get(h)
        if not e or e[0] != t: return None
        if h not in self.cache:
            self.cache[h] = EntryObj(self.loader, h, t)
        return self.cache[h]
    def Load(self, FileID, TypeID, Reload=False, SearchAll=False):
        ent = self.GetEntry(FileID, TypeID, SearchAll)
        if ent: ent.Load(Reload)

_FORCE = False

# Outline-edge selection. For every triangle edge we find its adjacent
# triangles:
#   - 1 adjacent triangle -> open boundary edge (silhouette of open surfaces)
#   - 2 adjacent triangles -> interior; keep it as a CREASE edge when the
#     dihedral angle between the two face normals exceeds ~30deg (the model's
#     structural ridges: wall outlines, armor seams, ship hull folds). Interior
#     edges on flat/smooth regions are dropped - they are the "dense wireframe"
#     noise that also made the screen-space pass slow.
# Result is capped (OUTLINE_MIN/MAX) and guaranteed to have a floor so smooth
# organic models still get enough lines to read as an outline.
OUTLINE_MIN = 150
OUTLINE_MAX = 1900          # v10.64: 600 -> 1900 (fx 3800pt / 1900-edge limit)
OUTLINE_COS = 0.87          # cos(30deg): keep edge if dihedral angle > 30deg

def _tri_normal(verts, t):
    try:
        ax, ay, az = verts[t[0]]; bx, by, bz = verts[t[1]]; cx, cy, cz = verts[t[2]]
    except Exception:
        return None
    ux, uy, uz = bx-ax, by-ay, bz-az
    vx, vy, vz = cx-ax, cy-ay, cz-az
    nx, ny, nz = uy*vz-uz*vy, uz*vx-ux*vz, ux*vy-uy*vx
    l = (nx*nx + ny*ny + nz*nz) ** 0.5
    if l < 1e-12: return None
    return (nx/l, ny/l, nz/l)

def select_outline_edges(verts, tris):
    edge_tris = {}
    for ti, (a, b, c) in enumerate(tris):
        for (p, q) in ((a, b), (b, c), (c, a)):
            if p == q: continue
            if p > q: p, q = q, p
            edge_tris.setdefault((p, q), []).append(ti)
    sel = set()
    for e, tl in edge_tris.items():
        if len(tl) == 1:
            sel.add(e)                       # open boundary edge
            continue
        if len(tl) != 2:
            continue                         # non-manifold: skip
        n0 = _tri_normal(verts, tris[tl[0]])
        n1 = _tri_normal(verts, tris[tl[1]])
        if n0 is None or n1 is None: continue
        cosv = n0[0]*n1[0] + n0[1]*n1[1] + n0[2]*n1[2]
        if cosv < OUTLINE_COS:
            sel.add(e)                       # crease (sharp fold)
    # floor: smooth/organic models with few creases still need enough lines
    if len(sel) < OUTLINE_MIN:
        extra = sorted(set(edge_tris.keys()) - sel)
        need = OUTLINE_MIN - len(sel)
        stride = max(1, len(extra) // max(need, 1))
        for i in range(0, len(extra), max(stride, 1)):
            if len(sel) >= OUTLINE_MIN: break
            sel.add(extra[i])
    # cap: keep the selection evenly sampled
    if len(sel) > OUTLINE_MAX:
        lst = sorted(sel)
        step = len(lst) / float(OUTLINE_MAX)
        sel = set(lst[int(i * step)] for i in range(OUTLINE_MAX))
    return sorted(sel)

def build_pack(pname):
    entries = parse_entries(pname)
    if not entries: return 0, 0, 0
    # v10.64: skip packs with no unit entries BEFORE unpacking the bundles -
    # reconstruct_package_from_bundles() reads hundreds of MB per pack and
    # most packs contain no units at all.
    if not any(t == UNIT_TYPE for t in entries.values()):
        return 0, 0, 0
    loader = types.SimpleNamespace(entries=entries)
    loader.pkg = slim.reconstruct_package_from_bundles(pname)
    loader.gpu = slim.reconstruct_package_from_bundles(pname + '.gpu_resources')
    gtm = GTM(loader)
    unit_m.Global_TocManager = gtm
    comp_m.Global_TocManager = gtm
    built = fail = 0
    for fid, (tid, toc_off, toc_sz, gpu_off, gpu_sz) in entries.items():
        if tid != UNIT_TYPE: continue
        dec = str(fid)
        out = os.path.join(OUT_DIR, 'mesh_verts_%s.txt' % dec)
        if os.path.exists(out) and not _FORCE:
            # Verify the NEW format (3-field header). Old tables (2-field
            # header, verts-only, no edges) are stale -> rebuild them so the
            # C side can render triangle-edge wireframes.
            try:
                with open(out) as f0:
                    hdr = f0.readline().split()
                if len(hdr) == 3 and hdr[0] == dec:
                    built += 1
                    continue
            except Exception:
                pass
        toc = loader.pkg[toc_off:toc_off+toc_sz]
        gpu = loader.gpu[gpu_off:gpu_off+gpu_sz] if loader.gpu else b''
        if len(toc) < 64: fail += 1; continue
        sm = unit_m.StingrayMeshFile()
        sm.NameHash = fid
        sm.LoadMaterialSlotNames = False
        try:
            sm.Serialize(MemoryStream(toc), MemoryStream(gpu), gtm)
            allv = []
            tris = []
            for mesh in sm.RawMeshes:
                # Keep only the base LOD (0) and always-present (-1) meshes.
                # Higher LOD indices are the SAME model at lower detail; if we
                # include them all, the wireframe draws the model several times
                # on top of itself -> scattered mess. (Matches the Blender
                # importer's AutoLods rule and unit.IsLod().)
                try:
                    miol = sm.MeshInfoArray[mesh.MeshInfoIndex]
                    lod = getattr(miol, 'LodIndex', 0)
                except Exception:
                    lod = 0
                if lod not in (0, -1):
                    continue
                # Per-mesh node transform: raw VertexPositions already live in
                # the SDK's Z-up frame (a standing character's height runs
                # along local Z, verified against unit 5556372446766824087 and
                # 16337047661043181516 - both raw meshes are Z-up). The C-side
                # mesh projection maps local Z -> world UP, so the transform's
                # ROTATION must NOT be baked in (doing so rotated Z-up models
                # onto their side). Only the translation offset is applied to
                # place sub-meshes that hang off the unit origin.
                tm = None
                try:
                    ti = miol.TransformIndex
                    if sm.TransformInfo and sm.TransformInfo.TransformMatrices and 0 <= ti < len(sm.TransformInfo.TransformMatrices):
                        cand = sm.TransformInfo.TransformMatrices[ti]
                        if getattr(cand, 'v', None):
                            tm = cand.v
                except Exception:
                    tm = None
                vbase = len(allv)
                if tm is not None:
                    t = tm
                    allv.extend((p[0] + t[12], p[1] + t[13], p[2] + t[14])
                                for p in mesh.VertexPositions)
                else:
                    allv.extend(mesh.VertexPositions)
                for tri in mesh.Indices:
                    if len(tri) >= 3:
                        tris.append((vbase + tri[0], vbase + tri[1], vbase + tri[2]))
            if not allv: fail += 1; continue
            # Outline-edge selection runs on the FULL mesh (no vertex
            # subsampling): stride-sampling a big mesh (e.g. the FRV, ~65k
            # verts) destroys triangle topology - almost no triangle keeps
            # all three sampled vertices, leaving a 3-edge table. Instead we
            # select the outline edges from the complete mesh, rank them by
            # length and keep the OUTLINE_MAX longest - the structural
            # silhouette. Only the vertices referenced by the kept edges are
            # written, so the C side's point budget is never exceeded.
            edges = select_outline_edges(allv, tris)
            if not edges:
                fail += 1; continue
            el = []
            for (p, q) in edges:
                dx = allv[p][0] - allv[q][0]
                dy = allv[p][1] - allv[q][1]
                dz = allv[p][2] - allv[q][2]
                el.append((dx*dx + dy*dy + dz*dz, p, q))
            el.sort(key=lambda t: t[0], reverse=True)
            nsel = min(len(el), OUTLINE_MAX)
            sel = el[:nsel]
            vused = set()
            for (l, p, q) in sel:
                vused.add(p); vused.add(q)
            vmap = {}
            newv = []
            for vi in sorted(vused):
                vmap[vi] = len(newv)
                newv.append(allv[vi])
            newedges = [(vmap[p], vmap[q]) for (l, p, q) in sel]
            with open(out, 'w') as f:
                f.write('%s %d %d\n' % (dec, len(newv), len(newedges)))
                for v in newv:
                    f.write('%.6f %.6f %.6f\n' % (v[0], v[1], v[2]))
                for (p, q) in newedges:
                    f.write('%d %d\n' % (p, q))
            built += 1
        except Exception as e:
            if fail < 2:
                print('FAIL %016x: %s' % (fid, e), flush=True)
            fail += 1
            continue
    return built, fail, len([1 for t in entries.values() if t[0] == UNIT_TYPE])

if __name__ == '__main__':
    args = sys.argv[1:]
    if '--force' in args:
        _FORCE = True
        args = [a for a in args if a != '--force']
    for p in args:
        b, f, u = build_pack(p)
        print('pack %s: units=%d built=%d fail=%d' % (p, u, b, f), flush=True)
