"""Generate Hexer's app icon (stdlib only, no PIL).

Draws the icon with signed-distance shapes + supersampling so every size is crisp, then writes:
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
    """Flat-top regular hexagon with circumradius r (iq's exact SDF, rotated)."""
    kx, ky, kz = -0.866025404, 0.5, 0.577350269
    x, y = abs(py - cy), abs(px - cx)  # swap -> flat top
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


def design(size):
    """Returns a function (x, y) -> (r, g, b, a) in unit coords, tuned per pixel size."""
    small = size <= 24
    px = 1.0 / size  # one pixel in unit space (for stroke minimums)

    bg_r = 0.47
    rad = 0.21
    hex_r = 0.40 if small else 0.355
    hex_w = max(0.10 if small else 0.052, 1.6 * px)
    cy = 0.5

    # digits: "1 0 1" (>= 32 px) or "1 0" (small sizes)
    if small:
        glyphs = [("1", 0.37), ("0", 0.60)]
        gh, gw, stroke = 0.19, 0.12, 1.0 * px
    else:
        glyphs = [("1", 0.355), ("0", 0.50), ("1", 0.645)]
        gh, gw, stroke = 0.125, 0.058, max(0.046, 1.3 * px)

    if size <= 48:
        # Pixel-fit small sizes: whole-pixel stroke widths, strokes centred so their edges land on
        # pixel boundaries -> crisp digits instead of grey smears.
        def snap_w(w):
            return max(1, round(w * size)) / size

        def snap_c(c, w):  # centre for a stroke of width w (already snapped)
            n = round(w * size)
            return (math.floor(c * size) + 0.5) / size if n % 2 else round(c * size) / size

        stroke = snap_w(stroke) if small else max(2.0 / size, snap_w(stroke))
        hex_w = snap_w(hex_w)
        glyphs = [(ch, snap_c(gx, stroke)) for ch, gx in glyphs]
        # ring half-width (centre line) so the ring's outer edges are on pixel boundaries
        outer = round((gw + stroke / 2) * size) / size
        gw = outer - stroke / 2
        top = round((cy - gh) * size) / size
        gh = cy - top

    def shade(x, y):
        # background tile
        d_bg = sd_round_rect(x, y, 0.5, 0.5, bg_r, bg_r, rad)
        if d_bg > 0:
            return None, d_bg
        col = mix(BG_TOP, BG_BOT, clamp(y))
        # soft inner glow towards the centre
        g = clamp(1.0 - math.hypot(x - 0.5, y - 0.45) / 0.55)
        col = mix(col, hexc("#23324f"), 0.35 * g * g)
        layers = [(col, d_bg)]
        # rim highlight (1px-ish inside edge)
        layers.append((RIM, abs(d_bg + max(0.012, 0.9 * px)) - max(0.006, 0.45 * px), 0.55))
        # hexagon outline with diagonal gradient
        d_hex = abs(sd_hexagon(x, y, 0.5, cy, hex_r)) - hex_w / 2
        t = clamp((x + y - 0.45) / 1.1)
        layers.append((mix(ACC_A, ACC_B, t), d_hex))
        # glyphs
        for ch, gx in glyphs:
            if ch == "1":
                d = sd_capsule_v(x, y, gx, cy - gh + stroke / 2, cy + gh - stroke / 2, stroke / 2)
                layers.append((INK, d))
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
            n = ss * ss
            a = acc[3] / n
            k = (j * size + i) * 4
            if a > 0:
                out[k + 0] = int(round(clamp(acc[0] / acc[3]) * 255))
                out[k + 1] = int(round(clamp(acc[1] / acc[3]) * 255))
                out[k + 2] = int(round(clamp(acc[2] / acc[3]) * 255))
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
