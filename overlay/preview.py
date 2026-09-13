#!/usr/bin/env python3
"""Render static PNG previews of the Sentinel pet (no Qt, no display needed).

Mirrors the Qt paint logic in pure Python so you can generate preview images
of every pet state on a headless machine. Run:

    python overlay/preview.py            # writes previews/*.png

The PNG encoder uses only stdlib (zlib + struct) — no Pillow required.
"""
from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

from . import sprites

SCALE = 8  # larger for a crisp preview


def hex_to_rgba(hx: str) -> tuple[int, int, int, int]:
    hx = hx.lstrip("#")
    return (int(hx[0:2], 16), int(hx[2:4], 16), int(hx[4:6], 16), 255)


def _grid_to_rgba(grid, cmap, scale=SCALE):
    h, w = len(grid) * scale, len(grid[0]) * scale
    buf = bytearray(w * h * 4)
    for y, row in enumerate(grid):
        for x, ch in enumerate(row):
            color = cmap.get(ch)
            if color is None:
                continue
            rgba = hex_to_rgba(color) if isinstance(color, str) else color
            for dy in range(scale):
                for dx in range(scale):
                    px = (x * scale + dx)
                    py = (y * scale + dy)
                    i = (py * w + px) * 4
                    buf[i:i + 4] = bytes(rgba)
    return bytes(buf), w, h


def _blit(buf, bw, bx, by, sx, sy, sw, sh):
    """Blit a sprite buffer (sw x sh) onto canvas (bw wide) at (bx,by)."""
    out = bytearray(buf)
    for yy in range(sh):
        for xx in range(sw):
            si = (yy * sw + xx) * 4
            if buf[si + 3] == 0:
                continue
            dx, dy = bx + xx, by + yy
            if dx < 0 or dy < 0 or dx >= bw:
                continue
            di = (dy * bw + dx) * 4
            out[di:di + 4] = buf[si:si + 4]
    return bytes(out)


def _png(buf_rgba, w, h) -> bytes:
    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)  # 8-bit RGBA
    raw = bytearray()
    for y in range(h):
        raw.append(0)  # filter: none
        raw.extend(buf_rgba[y * w * 4:(y + 1) * w * 4])
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(bytes(raw))) + chunk(b"IEND", b"")


def render_state(state: str, risk: int, verdict=None) -> bytes:
    """Return a PNG of the pet in the given state."""
    # Body color by risk.
    body_char = "g" if risk < 35 else ("y" if risk < 60 else ("o" if risk < 80 else "r"))
    if state == "verdict" and verdict == "SAFE":
        body_char = "g"
    cmap = dict(sprites.PALETTE)
    cmap["g"] = cmap["y"] = cmap["o"] = cmap["r"] = sprites.PALETTE[body_char]

    # Canvas.
    W, H = 320, 320
    canvas = bytearray(W * H * 4)

    body_buf, bw, bh = _grid_to_rgba(sprites.BODY, cmap)
    bx, by = (W - bw) // 2, (H - bh) // 2 - 20
    canvas = bytearray(_blit(bytes(canvas), W, 0, 0, 0, 0, 0, 0))

    # Draw body.
    for yy in range(bh):
        for xx in range(bw):
            si = (yy * bw + xx) * 4
            if body_buf[si + 3]:
                di = ((by + yy) * W + (bx + xx)) * 4
                canvas[di:di + 4] = body_buf[si:si + 4]

    # Eyes (white + pupil), centered, slight look direction.
    ex = bx + bw // 2
    ey = by + int(bh * 0.38)
    eye_r = int(SCALE * 1.0)
    gap = int(SCALE * 3.4)
    white = hex_to_rgba("#ffffff")
    pupil = hex_to_rgba("#1a1a2e")
    for sx in (-1, 1):
        cx, cy = ex + sx * (gap // 2), ey
        for yy in range(-eye_r, eye_r + 1):
            for xx in range(-eye_r, eye_r + 1):
                if xx * xx + yy * yy <= eye_r * eye_r:
                    di = ((cy + yy) * W + (cx + xx)) * 4
                    if di + 3 < len(canvas):
                        canvas[di:di + 4] = bytes(white)
        for yy in range(-eye_r // 2, eye_r // 2 + 1):
            for xx in range(-eye_r // 2, eye_r // 2 + 1):
                di = ((cy + yy) * W + (cx + xx)) * 4
                if di + 3 < len(canvas):
                    canvas[di:di + 4] = bytes(pupil)

    # Mouth.
    mx, my = bx + bw // 2, by + int(bh * 0.68)
    ink = hex_to_rgba("#1a1a2e")
    if state == "verdict" and verdict == "MALICIOUS":
        for yy in range(-eye_r, eye_r + 1):
            for xx in range(-eye_r, eye_r + 1):
                di = ((my + yy) * W + (mx + xx)) * 4
                canvas[di:di + 4] = bytes(hex_to_rgba("#7a0000"))
    elif risk < 35:
        for xx in range(-10, 11):
            yy = -int(math.sqrt(max(0, 100 - xx * xx)) * 0.5)
            di = ((my + yy) * W + (mx + xx)) * 4
            canvas[di:di + 4] = bytes(ink)
    else:
        for xx in range(-9, 10):
            yy = int(math.sqrt(max(0, 81 - xx * xx)) * 0.5)
            di = ((my + yy) * W + (mx + xx)) * 4
            canvas[di:di + 4] = bytes(ink)

    # Shield (raised).
    if state in ("investigating", "tool_running", "confirm_needed") or risk >= 35:
        sh_buf, sw, sh = _grid_to_rgba(sprites.SHIELD, sprites.PALETTE)
        for yy in range(sh):
            for xx in range(sw):
                si = (yy * sw + xx) * 4
                if sh_buf[si + 3]:
                    di = ((by - 10 + yy) * W + (bx + bw + 4 + xx)) * 4
                    if di + 3 < len(canvas):
                        canvas[di:di + 4] = sh_buf[si:si + 4]

    # Bubble glyph.
    glyph = None
    if state == "thinking":
        glyph, color = sprites.DOTS, "#ffffff"
    elif state == "confirm_needed":
        glyph, color = sprites.BANG, "#f1c40f"
    elif state == "verdict" and verdict == "SAFE":
        glyph, color = sprites.CHECK, "#2ecc71"
    elif state == "verdict" and verdict == "MALICIOUS":
        glyph, color = sprites.BANG, "#e74c3c"
    if glyph:
        gcmap = {".": None, "k": color}
        gbuf, gw, gh = _grid_to_rgba(glyph, gcmap, scale=6)
        for yy in range(gh):
            for xx in range(gw):
                si = (yy * gw + xx) * 4
                if gbuf[si + 3]:
                    di = ((by - 40 + yy) * W + (bx + bw + 2 + xx)) * 4
                    if di + 3 < len(canvas):
                        canvas[di:di + 4] = gbuf[si:si + 4]

    return _png(bytes(canvas), W, H)


def _decode_png(png: bytes):
    """Minimal PNG decode (8-bit RGBA, our own encoder's output)."""
    if png[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a png")
    pos = 8
    w = h = None
    idat = b""
    while pos < len(png):
        ln = struct.unpack(">I", png[pos:pos + 4])[0]
        tag = png[pos + 4:pos + 8]
        data = png[pos + 8:pos + 8 + ln]
        pos += 12 + ln
        if tag == b"IHDR":
            w, h = struct.unpack(">II", data[:8])
        elif tag == b"IDAT":
            idat += data
        elif tag == b"IEND":
            break
    raw = zlib.decompress(idat)
    stride = w * 4
    out = bytearray()
    i = 0
    for _ in range(h):
        f = raw[i]
        i += 1
        line = bytearray(raw[i:i + stride])
        i += stride
        if f == 0:
            out.extend(line)
        else:
            # Only filter 0 is produced by our encoder.
            out.extend(line)
    return bytes(out), w, h


def _contact_sheet(images: list[bytes], cols: int = 4) -> bytes:
    """Tile decoded RGBA images into a single sheet with padding."""
    imgs = [_decode_png(p) for p in images]
    cell_w = max(w for _, w, _ in imgs)
    cell_h = max(h for _, h, _ in imgs)
    pad = 8
    rows = (len(imgs) + cols - 1) // cols
    W = cols * (cell_w + pad) + pad
    H = rows * (cell_h + pad) + pad
    sheet = bytearray(W * H * 4)
    for idx, (buf, w, h) in enumerate(imgs):
        cx = pad + (idx % cols) * (cell_w + pad)
        cy = pad + (idx // cols) * (cell_h + pad)
        for yy in range(h):
            for xx in range(w):
                si = (yy * w + xx) * 4
                if buf[si + 3]:
                    di = ((cy + yy) * W + (cx + xx)) * 4
                    sheet[di:di + 4] = buf[si:si + 4]
    return _png(bytes(sheet), W, H)


def main() -> int:
    outdir = Path(__file__).parent.parent / "previews"
    outdir.mkdir(exist_ok=True)

    states = [
        ("idle", 0, None),
        ("investigating", 0, None),
        ("thinking", 10, None),
        ("tool_running", 45, None),
        ("confirm_needed", 65, None),
        ("verdict", 95, "MALICIOUS"),
        ("verdict", 5, "SAFE"),
    ]
    pngs = []
    for name, risk, verdict in states:
        png = render_state(name, risk, verdict)
        fname = f"{name}_{risk}.png"
        (outdir / fname).write_bytes(png)
        pngs.append(png)
        print(f"wrote previews/{fname}  ({len(png)} bytes)")

    sheet = _contact_sheet(pngs, cols=4)
    (outdir / "contact_sheet.png").write_bytes(sheet)
    print(f"wrote previews/contact_sheet.png ({len(sheet)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
