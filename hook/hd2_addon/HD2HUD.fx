/*
 * HD2 HUD - ReShade effect shader
 * Draws hit-target HUD in the render pipeline, fed per-frame by the
 * "hd2_raycast_hook" addon via uniforms. All coordinates are NORMALIZED
 * (0..1) and multiplied by BUFFER_SCREEN_SIZE here, so the HUD always
 * lands on the real render resolution regardless of the game's GUI
 * render resolution (which may differ, e.g. 1280x720 vs 1920x1080).
 */

#include "ReShade.fxh"

uniform float4 rc_hitmark < label = "hit mark"; >;      // nx,ny,on,size(0..1)
uniform float4 rc_hitbox[8] < label = "hit box"; >;     // 8 AABB corners nx,ny,on
uniform float4 rc_marks[64] < label = "scan marks"; >;  // nx,ny,on,size(0..1)
uniform float4 rc_scanbox[128] < label = "scan boxes"; >; // 16 boxes x 8 corners {nx,ny,on,box}
uniform float4 rc_mbox[32] < label = "method boxes"; >;    // 4 boxes x 8 corners {nx,ny,on,color}
uniform float4 rc_mesh[3072] < label = "mesh outline"; >;  // hit-entity real mesh edges {nx,ny,on,0}, 2 pts per edge.
// NOTE: 3072 entries keeps the effect's constant buffer at 3072+283=3355
// float4s, under the D3D11 limit of 4096. A larger array (8192) made the
// shader fail to compile (X8000: Constant buffer size exceeds allowed
// limit) and hung the game at startup. 3072 pts = 1536 triangle edges,
// which covers every model after the offline vertex subsample.
uniform float4 rc_mesh_cfg < >;   // {point_count, 0, 0, 0} - avoids a per-pixel count loop
uniform float4 rc_mesh_rect < >;  // {minx, miny, maxx, maxy} normalized AABB of the mesh

// ---- self-rendered text (glyph atlas fed by the addon via update_texture) ----
// Size MUST match the addon's ATLAS_CANVAS (1024) - ReShade update_texture
// rejects mismatched dimensions and the label would never render.
texture2D rc_atlas { Width = 1024; Height = 1024; Format = RGBA8; };
sampler2D rc_atlas_s
{
    Texture = rc_atlas;
    MagFilter = LINEAR;
    MinFilter = LINEAR;
    AddressU = CLAMP;
    AddressV = CLAMP;
};
uniform float4 rc_atlas_cfg < >;   // {tex_w, tex_h, cols, cell_px}
uniform float4 rc_slots[24] < >;   // per-char atlas slot index (-1 = end, -2 = newline), 4 slots per float4 (96 slots)
uniform float4 rc_label_w[24] < >; // per-char advance width in atlas px (0 for separators), 4 per float4
uniform float4 rc_label_cfg < >;   // {anchor_nx, anchor_ny(0..1), count, on}

float dist_seg(float2 p, float2 a, float2 b)
{
    float2 ab = b - a;
    float t = clamp(dot(p - a, ab) / max(dot(ab, ab), 1e-6), 0.0, 1.0);
    return length(p - (a + ab * t));
}

float4 PS_HD2HUD(float4 vpos : SV_Position, float2 texcoord : TEXCOORD) : SV_Target
{
    float2 px = vpos.xy;
    float4 col = 0;
    const float2 S = BUFFER_SCREEN_SIZE;

    // ---- crosshair at screen center (magenta): the detection ray direction ----
    {
        float2 c = S * 0.5;
        float ddx = abs(px.x - c.x);
        float ddy = abs(px.y - c.y);
        if ((ddx < 1.5 && ddy < 14.0) || (ddy < 1.5 && ddx < 14.0))
            col = float4(1.0, 0.0, 1.0, 0.9);
    }

    // ---- ray beam: from screen center to the hit point ----
    if (rc_hitmark.z > 0.5) {
        float2 c = S * 0.5;
        float2 hp = rc_hitmark.xy * S;
        float db = dist_seg(px, c, hp);
        if (db < 1.5)
            col = float4(1.0, 0.0, 1.0, 0.8);
    }

    // ---- hit mark (yellow box outline at projected hit point) ----
    if (rc_hitmark.z > 0.5) {
        float2 hc = rc_hitmark.xy * S;
        float hs = rc_hitmark.w * S.x;
        float dx0 = abs(px.x - (hc.x - hs)), dx1 = abs(px.x - (hc.x + hs));
        float dy0 = abs(px.y - (hc.y - hs)), dy1 = abs(px.y - (hc.y + hs));
        float ex = min(min(dx0, dx1), min(dy0, dy1));
        if (ex < 2.0 && px.x >= hc.x - hs - 2 && px.x <= hc.x + hs + 2 &&
            px.y >= hc.y - hs - 2 && px.y <= hc.y + hs + 2)
            col = float4(1.0, 1.0, 0.0, 0.95);
    }

    // ---- hit-entity real mesh edge count (computed first: when a real
    //      mesh wireframe exists, the coarse AABB hit box is hidden so they
    //      do not fight each other; other entities keep their boxes). The
    //      count comes from the addon (rc_mesh_cfg) - a per-pixel loop over
    //      all 3072 entries was a major source of the startup lag. ----
    int mcnt = (int)rc_mesh_cfg.x;
    if (mcnt > 3072) mcnt = 3072;

    // ---- hit box: 3D AABB wireframe (12 edges, yellow) ----
    // Skipped when the real mesh wireframe is present for the hit entity.
    if (mcnt < 4) {
        float4 hb[8];
        hb[0] = rc_hitbox[0]; hb[1] = rc_hitbox[1]; hb[2] = rc_hitbox[2]; hb[3] = rc_hitbox[3];
        hb[4] = rc_hitbox[4]; hb[5] = rc_hitbox[5]; hb[6] = rc_hitbox[6]; hb[7] = rc_hitbox[7];
        for (int e = 0; e < 12; e++) {
            int a = 0, b = 0;
            if (e == 0) { a = 0; b = 1; } else if (e == 1) { a = 1; b = 3; }
            else if (e == 2) { a = 3; b = 2; } else if (e == 3) { a = 2; b = 0; }
            else if (e == 4) { a = 4; b = 5; } else if (e == 5) { a = 5; b = 7; }
            else if (e == 6) { a = 7; b = 6; } else if (e == 7) { a = 6; b = 4; }
            else if (e == 8) { a = 0; b = 4; } else if (e == 9) { a = 1; b = 5; }
            else if (e == 10) { a = 2; b = 6; } else if (e == 11) { a = 3; b = 7; }
            if (hb[a].z > 0.5 && hb[b].z > 0.5) {
                float d = dist_seg(px, hb[a].xy * S, hb[b].xy * S);
                if (d < 2.6) col = float4(1.0, 1.0, 0.0, 0.95);
            }
        }
        // corner dots: 3x3 pixel markers at each corner, more visible than thin lines
        for (int c = 0; c < 8; c++) {
            if (hb[c].z > 0.5) {
                float2 cp = hb[c].xy * S;
                if (abs(px.x - cp.x) < 1.8 && abs(px.y - cp.y) < 1.8)
                    col = float4(1.0, 0.55, 0.0, 1.0);
            }
        }
    }

    // ---- hit-entity real mesh wireframe (cyan): each pair of consecutive
    //      points is one triangle edge projected to the screen. Two cheap
    //      gates keep the O(N) edge loop from being per-pixel expensive:
    //      first a screen AABB around the whole mesh, then a per-edge bbox
    //      before the distance computation. ----
    {
        int np = (mcnt / 2) * 2;
        if (np >= 4) {
            float2 rmin = rc_mesh_rect.xy * S;
            float2 rmax = rc_mesh_rect.zw * S;
            if (px.x >= rmin.x && px.x <= rmax.x && px.y >= rmin.y && px.y <= rmax.y) {
                for (int e = 0; e + 1 < np; e += 2) {
                    float2 a = rc_mesh[e].xy * S;
                    float2 b = rc_mesh[e + 1].xy * S;
                    float bminx = min(a.x, b.x) - 3.0;
                    float bmaxx = max(a.x, b.x) + 3.0;
                    float bminy = min(a.y, b.y) - 3.0;
                    float bmaxy = max(a.y, b.y) + 3.0;
                    if (px.x < bminx || px.x > bmaxx || px.y < bminy || px.y > bmaxy) continue;
                    float d = dist_seg(px, a, b);
                    if (d < 2.4) col = float4(0.2, 1.0, 0.6, 0.98);
                }
            }
        }
    }

    // ---- scan box wireframes: up to 16 boxes, 12 edges each (yellow) ----
    for (int b = 0; b < 16; b++) {
        int base = b * 8;
        if (rc_scanbox[base].z < 0.5) continue;
        float4 sb[8];
        sb[0] = rc_scanbox[base + 0]; sb[1] = rc_scanbox[base + 1];
        sb[2] = rc_scanbox[base + 2]; sb[3] = rc_scanbox[base + 3];
        sb[4] = rc_scanbox[base + 4]; sb[5] = rc_scanbox[base + 5];
        sb[6] = rc_scanbox[base + 6]; sb[7] = rc_scanbox[base + 7];
        for (int e = 0; e < 12; e++) {
            int a = 0, bb = 0;
            if (e == 0) { a = 0; bb = 1; } else if (e == 1) { a = 1; bb = 3; }
            else if (e == 2) { a = 3; bb = 2; } else if (e == 3) { a = 2; bb = 0; }
            else if (e == 4) { a = 4; bb = 5; } else if (e == 5) { a = 5; bb = 7; }
            else if (e == 6) { a = 7; bb = 6; } else if (e == 7) { a = 6; bb = 4; }
            else if (e == 8) { a = 0; bb = 4; } else if (e == 9) { a = 1; bb = 5; }
            else if (e == 10) { a = 2; bb = 6; } else if (e == 11) { a = 3; bb = 7; }
            if (sb[a].z > 0.5 && sb[bb].z > 0.5) {
                float2 pa = sb[a].xy * S;
                float2 pb = sb[bb].xy * S;
                float bminx = min(pa.x, pb.x) - 3.0;
                float bmaxx = max(pa.x, pb.x) + 3.0;
                float bminy = min(pa.y, pb.y) - 3.0;
                float bmaxy = max(pa.y, pb.y) + 3.0;
                if (px.x < bminx || px.x > bmaxx || px.y < bminy || px.y > bmaxy) continue;
                float d = dist_seg(px, pa, pb);
                if (d < 2.2) col = float4(1.0, 0.8, 0.2, 0.8);
            }
        }
        // corner dots for scan boxes
        for (int c = 0; c < 8; c++) {
            if (sb[c].z > 0.5) {
                float2 cp = sb[c].xy * S;
                if (abs(px.x - cp.x) < 1.5 && abs(px.y - cp.y) < 1.5)
                    col = float4(1.0, 0.7, 0.1, 0.9);
            }
        }
    }

    // ---- method-comparison boxes: DISABLED (debug only). The 4-color
    //      comparison frames are no longer needed now that the real mesh
    //      outline + world_position(u,1) path is in production. ----

    // ---- scan marks (yellow dots at projected box centers) ----
    for (int i = 0; i < 64; i++) {
        float4 m = rc_marks[i];
        if (m.z > 0.5) {
            float2 mc = m.xy * S;
            float ms = m.w * S.x;
            if (px.x >= mc.x - ms && px.x <= mc.x + ms &&
                px.y >= mc.y - ms && px.y <= mc.y + ms) {
                col = float4(1.0, 0.85, 0.0, 0.9);
            }
        }
    }

    // ---- self-rendered text label (white glyphs on a translucent black
    //      backdrop - readable on any background). Multi-line: slot -2 =
    //      newline, -1 = end. The anchor is the hit-box TOP-CENTER; the
    //      whole block is drawn ABOVE it (bottom edge 8px clear of the box)
    //      so the text never covers the mesh wireframe, and the glyph size
    //      is scaled for ~1/2 the previous height (S.y/2160). ----
    if (rc_label_cfg.w > 0.5 && rc_label_cfg.z > 0.5) {
        int n = (int)rc_label_cfg.z;
        if (n > 96) n = 96;
        float cw = rc_atlas_cfg.w;                     // cell px (atlas space)
        float ch = cw;
        float cols = rc_atlas_cfg.z;
        float tw = rc_atlas_cfg.x, th = rc_atlas_cfg.y;
        float scale = S.y / 2160.0;                    // half the old glyph height
        float scw = cw * scale, sch = ch * scale;
        float2 anchor = rc_label_cfg.xy * S;
        // pass 1: count rows + widest row (in screen px, using real advance
        // widths) so the block can be centered horizontally
        float maxrow = 0, crow = 0;
        int nrows = 1;
        for (int i = 0; i < n; i++) {
            int slot = (int)rc_slots[i >> 2][i & 3];
            float wc = rc_label_w[i >> 2][i & 3];
            if (slot == -2) { if (crow > maxrow) maxrow = crow; crow = 0; nrows++; }
            else if (slot >= 0) crow += wc * scale;
            else break;
        }
        if (crow > maxrow) maxrow = crow;
        float row_h = sch + 4.0;
        float block_h = nrows * sch + (nrows - 1) * 4.0;
        float x0 = anchor.x - maxrow * 0.5;
        float y0 = anchor.y - block_h - 8.0;           // above the box top edge
        float cx = x0, cy = y0;
        for (int i = 0; i < n; i++) {
            int slot = (int)rc_slots[i >> 2][i & 3];
            if (slot == -2) { cy += row_h; cx = x0; continue; }
            if (slot < 0) break;
            float wc = rc_label_w[i >> 2][i & 3];
            float cwid = wc * scale;
            if (px.x >= cx && px.x < cx + cwid && px.y >= cy && px.y < cy + sch) {
                float gx = (slot % (int)cols) * cw + (px.x - cx) / scale;
                float gy = floor(slot / cols) * ch + (px.y - cy) / scale;
                float2 uv = float2(gx, gy) / float2(tw, th);
                float a = tex2D(rc_atlas_s, uv).a;
                col = float4(0.0, 0.0, 0.0, 0.55);      // backdrop for readability
                if (a > 0.06)
                    col = float4(1.0, 1.0, 0.92, min(a * 1.25, 1.0)); // near-white glyph
            }
            cx += cwid;
        }
    }

    return col;
}

technique HD2HUD
{
    pass
    {
        VertexShader = PostProcessVS;
        PixelShader = PS_HD2HUD;
        BlendEnable = true;
        SrcBlend = SrcAlpha;
        DestBlend = InvSrcAlpha;
    }
}
