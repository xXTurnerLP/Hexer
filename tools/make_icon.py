"""Generate Hexer's app icon (stdlib only, no PIL).

Draws the icon with signed-distance shapes + supersampling (anti-aliased at every size; 16/24/32 px
use whole-pixel layouts so vertical strokes stay sharp), then writes:
  assets/icon/hexer-<N>.png      for N in SIZES (Linux hicolor theme / docs)
  assets/icon/hexer.ico          multi-size Windows icon (PNG-compressed entries)
  src/ui/icon_data.h             RGBA pixels for glfwSetWindowIcon (Linux/X11 window icon)

Run from the repo root:  python tools/make_icon.py
"""
import math
import os
import struct
import sys
import zlib

SIZES = [16, 24, 32, 48, 64, 128, 256]
HEADER_SIZES = [16, 32, 48, 64]  # embedded for the window icon

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---- tiny vector toolkit (unit square coordinates, y down) ------------------------------------

def clamp(x, a=0.0, b=1.0):
    return a if x < a else b if x > b else x


def mix(a, b, t):
    return tuple(a[i] + (b[i] - a[i]) * t for i in range(len(a)))


def hexc(s):
    s = s.lstrip("#")
    return tuple(int(s[i:i + 2], 16) / 255.0 for i in (0, 2, 4))


def sd_round_rect(px, py, cx, cy, hw, hh, r):
    qx = abs(px - cx) - hw + r
    qy = abs(py - cy) - hh + r
    ox, oy = max(qx, 0.0), max(qy, 0.0)
    return math.hypot(ox, oy) + min(max(qx, qy), 0.0) - r


def sd_hexagon(px, py, cx, cy, r):
    """Pointy-top regular hexagon with circumradius r (iq's exact SDF, rotated)."""
    kx, ky, kz = -0.866025404, 0.5, 0.577350269
    x, y = abs(py - cy), abs(px - cx)  # swap -> pointy top (vertical sides)
    d = 2.0 * min(kx * x + ky * y, 0.0)
    x -= d * kx
    y -= d * ky
    r_in = r * 0.866025404
    x -= clamp(x, -kz * r_in, kz * r_in)
    y -= r_in
    return math.hypot(x, y) * (1 if y > 0 else -1)


def sd_capsule_v(px, py, cx, y0, y1, r):
    y = clamp(py, y0, y1)
    return math.hypot(px - cx, py - y) - r


def sd_ellipse_ring(px, py, cx, cy, rx, ry, w):
    # approximate distance to an ellipse outline, scaled to keep stroke width uniform-ish
    nx, ny = (px - cx) / rx, (py - cy) / ry
    k = math.hypot(nx, ny)
    if k == 0:
        return min(rx, ry) - w / 2
    gx, gy = nx / rx, ny / ry
    grad = math.hypot(gx, gy) / k if k else 1.0
    d = (k - 1.0) / max(grad, 1e-6)
    return abs(d) - w / 2


# ---- the design --------------------------------------------------------------------------------

BG_TOP = hexc("#2c2f36")
BG_BOT = hexc("#15161a")
RIM = hexc("#4a4e57")
ACC_A = hexc("#3574f0")   # theme accent blue
ACC_B = hexc("#22d3c5")   # teal
INK = hexc("#eef1f5")
INK_DIM = hexc("#9aa3b2")

# Small sizes (16 / 24 / 32 px): the same anti-aliased vector design, but laid out in whole pixels
# so it stays crisp: the hexagon's vertical sides, the digit stems and the "0" ring sit exactly on
# pixel columns/rows (sharp), while the hexagon diagonals and rounded corners stay anti-aliased like
# the large sizes. All numbers below are in pixels of that size.
#   margin  tile inset            hex_hw  half width of the hexagon (centre line of its vertical sides)
#   hex_w   hexagon stroke        digits  ("1" | "0", x0, x1) boxes, rows y0..y1, stroke `stroke`
SMALL = {
    16: dict(margin=0, hex_hw=5.5, hex_w=1.0, y=(5, 11), stroke=1.0, zero_r=1.5,
             digits=[("1", 4, 5), ("0", 6, 10), ("1", 11, 12)]),
    24: dict(margin=1, hex_hw=7.5, hex_w=1.0, y=(9, 15), stroke=1.0, zero_r=1.5,
             digits=[("1", 8, 9), ("0", 10, 14), ("1", 15, 16)]),
    32: dict(margin=1, hex_hw=10.0, hex_w=2.0, y=(12, 20), stroke=1.5, zero_r=2.0,
             digits=[("1", 11, 12.5), ("0", 13.5, 18.5), ("1", 19.5, 21)]),
}


def hex_gradient(x, y):
    return mix(ACC_A, ACC_B, clamp((x + y - 0.45) / 1.1))


def tile_layers(x, y, px, bg_r, rad):
    """Background tile + rim. Returns (layers, d_bg) or (None, d_bg) outside the tile."""
    d_bg = sd_round_rect(x, y, 0.5, 0.5, bg_r, bg_r, rad)
    if d_bg > 0:
        return None, d_bg
    col = mix(BG_TOP, BG_BOT, clamp(y))
    g = clamp(1.0 - math.hypot(x - 0.5, y - 0.45) / 0.55)  # soft inner glow towards the centre
    col = mix(col, hexc("#23324f"), 0.35 * g * g)
    layers = [(col, d_bg)]
    rim_in, rim_w = max(0.012, 0.9 * px), max(0.006, 0.45 * px)
    layers.append((RIM, abs(d_bg + rim_in) - rim_w, 0.55))
    return layers, d_bg


def design_small(size):
    sp = SMALL[size]
    px = 1.0 / size
    bg_r = 0.5 - sp["margin"] * px
    rad = 0.21 / 0.47 * bg_r                      # same corner ratio as the vector tile
    hex_r = sp["hex_hw"] / 0.866025404 * px       # circumradius from the vertical sides' position
    hex_w = sp["hex_w"] * px
    y0, y1 = sp["y"]
    st = sp["stroke"]

    def shade(x, y):
        layers, d_bg = tile_layers(x, y, px, bg_r, rad)
        if layers is None:
            return None, d_bg
        layers.append((hex_gradient(x, y), abs(sd_hexagon(x, y, 0.5, 0.5, hex_r)) - hex_w / 2))
        X, Y = x * size, y * size
        for ch, x0, x1 in sp["digits"]:
            cx, hw, cy, hh = (x0 + x1) / 2, (x1 - x0) / 2, (y0 + y1) / 2, (y1 - y0) / 2
            if ch == "1":
                d = sd_round_rect(X, Y, cx, cy, hw, hh, 0.0)
            else:
                d = abs(sd_round_rect(X, Y, cx, cy, hw - st / 2, hh - st / 2, sp["zero_r"] - st / 2)) - st / 2
            layers.append((INK, d * px))
        return layers, d_bg

    return shade


def design(size):
    """Returns a function (x, y) -> (layers, d_bg) in unit coords, tuned per pixel size."""
    if size in SMALL:
        return design_small(size)
    px = 1.0 / size  # one pixel in unit space (for stroke minimums)
    bg_r, rad, hex_r, cy = 0.47, 0.21, 0.355, 0.5
    hex_w = max(0.052, 1.6 * px)
    glyphs = [("1", 0.355), ("0", 0.50), ("1", 0.645)]
    gh, gw, stroke = 0.125, 0.058, max(0.046, 1.3 * px)

    if size <= 48:
        # Pixel-fit: whole-pixel stroke widths, strokes centred so their edges land on pixel
        # boundaries -> crisp digits instead of grey smears.
        def snap_w(w):
            return max(1, round(w * size)) / size

        def snap_c(c, w):  # centre for a stroke of width w (already snapped)
            n = round(w * size)
            return (math.floor(c * size) + 0.5) / size if n % 2 else round(c * size) / size

        stroke = max(2.0 / size, snap_w(stroke))
        hex_w = snap_w(hex_w)
        glyphs = [(ch, snap_c(gx, stroke)) for ch, gx in glyphs]
        # ring half-width (centre line) so the ring's outer edges are on pixel boundaries
        outer = round((gw + stroke / 2) * size) / size
        gw = outer - stroke / 2
        top = round((cy - gh) * size) / size
        gh = cy - top

    def shade(x, y):
        layers, d_bg = tile_layers(x, y, px, bg_r, rad)
        if layers is None:
            return None, d_bg
        d_hex = abs(sd_hexagon(x, y, 0.5, cy, hex_r)) - hex_w / 2
        layers.append((hex_gradient(x, y), d_hex))
        for ch, gx in glyphs:
            if ch == "1":
                d = sd_capsule_v(x, y, gx, cy - gh + stroke / 2, cy + gh - stroke / 2, stroke / 2)
            else:
                d = sd_ellipse_ring(x, y, gx, cy, gw, gh - stroke / 2, stroke)
            layers.append((INK, d))
        return layers, d_bg

    return shade


def render(size, ss=6):
    shade = design(size)
    out = bytearray(size * size * 4)
    for j in range(size):
        for i in range(size):
            acc = [0.0, 0.0, 0.0, 0.0]
            for sj in range(ss):
                for si in range(ss):
                    x = (i + (si + 0.5) / ss) / size
                    y = (j + (sj + 0.5) / ss) / size
                    layers, d_bg = shade(x, y)
                    if layers is None:
                        continue
                    # composite layers (premultiplied-free simple over)
                    r, g, b = layers[0][0]
                    for layer in layers[1:]:
                        col, d = layer[0], layer[1]
                        op = layer[2] if len(layer) > 2 else 1.0
                        cov = clamp(0.5 - d * size * ss / 2.0) * op
                        r, g, b = r + (col[0] - r) * cov, g + (col[1] - g) * cov, b + (col[2] - b) * cov
                    a = clamp(0.5 - d_bg * size * ss / 2.0)
                    acc[0] += r * a
                    acc[1] += g * a
                    acc[2] += b * a
                    acc[3] += a
            a = acc[3] / (ss * ss)
            k = (j * size + i) * 4
            if a > 0:
                col = (acc[0] / acc[3], acc[1] / acc[3], acc[2] / acc[3])
                out[k + 0] = int(round(clamp(col[0]) * 255))
                out[k + 1] = int(round(clamp(col[1]) * 255))
                out[k + 2] = int(round(clamp(col[2]) * 255))
            out[k + 3] = int(round(a * 255))
    return bytes(out)


# ---- encoders ----------------------------------------------------------------------------------

def png_bytes(size, rgba):
    raw = b"".join(b"\0" + rgba[y * size * 4:(y + 1) * size * 4] for y in range(size))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def ico_bytes(images):
    """images: list of (size, png_bytes). PNG-compressed ICO entries (Vista+)."""
    header = struct.pack("<HHH", 0, 1, len(images))
    entries, data = b"", b""
    offset = 6 + 16 * len(images)
    for size, png in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset + len(data))
        data += png
    return header + entries + data


def header_text(icons):
    lines = ["// Generated by tools/make_icon.py - do not edit.",
             "// RGBA8 pixels of the Hexer icon for glfwSetWindowIcon.",
             "#pragma once", "#include <cstdint>", "", "namespace hx::icon {", ""]
    for size, rgba in icons:
        lines.append(f"inline constexpr int k{size}Size = {size};")
        lines.append(f"inline constexpr uint8_t k{size}[{len(rgba)}] = {{")
        for k in range(0, len(rgba), 24):
            lines.append("    " + ",".join(str(b) for b in rgba[k:k + 24]) + ",")
        lines.append("};")
        lines.append("")
    lines.append("}  // namespace hx::icon")
    return "\n".join(lines) + "\n"


def main():
    out_dir = os.path.join(ROOT, "assets", "icon")
    os.makedirs(out_dir, exist_ok=True)
    rendered = {}
    for s in SIZES:
        rendered[s] = render(s, ss=8 if s <= 48 else 4)
        with open(os.path.join(out_dir, f"hexer-{s}.png"), "wb") as f:
            f.write(png_bytes(s, rendered[s]))
        print(f"  {s}x{s}")
    with open(os.path.join(out_dir, "hexer.ico"), "wb") as f:
        f.write(ico_bytes([(s, png_bytes(s, rendered[s])) for s in SIZES]))
    with open(os.path.join(ROOT, "src", "ui", "icon_data.h"), "w", encoding="utf-8", newline="\n") as f:
        f.write(header_text([(s, rendered[s]) for s in HEADER_SIZES]))
    print("wrote assets/icon/*, src/ui/icon_data.h")


if __name__ == "__main__":
    sys.exit(main())
