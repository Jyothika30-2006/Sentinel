#!/usr/bin/env python3
"""Render the Sentinel working/architecture diagram as a PNG (no deps).

Pure-stdlib PNG encoder + a simple box/arrow drawing layer, so the diagram is
deterministic and accurate (mirrors docs/ARCHITECTURE.md exactly).

Run:  python3 -m overlay.diagram
Out:  previews/architecture.png
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path


# ---------------------------------------------------------------------------
# Tiny image canvas + PNG encoder
# ---------------------------------------------------------------------------
def _png(buf, w, h) -> bytes:
    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw.extend(buf[y * w * 4:(y + 1) * w * 4])
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw)))
            + chunk(b"IEND", b""))


class Canvas:
    def __init__(self, w, h, bg=(18, 18, 32)):
        self.w, self.h = w, h
        self.buf = bytearray(w * h * 4)
        self.fill_rect(0, 0, w, h, bg)

    def _px(self, x, y, c):
        if 0 <= x < self.w and 0 <= y < self.h:
            i = (y * self.w + x) * 4
            self.buf[i:i + 4] = c

    def fill_rect(self, x, y, w, h, c):
        c = bytes(c)
        x0 = max(0, x); y0 = max(0, y)
        x1 = min(self.w, x + w); y1 = min(self.h, y + h)
        row = c * (x1 - x0)
        for yy in range(y0, y1):
            i = (yy * self.w + x0) * 4
            self.buf[i:i + (x1 - x0) * 4] = row

    def rect(self, x, y, w, h, c, thickness=2):
        self.fill_rect(x, y, w, thickness, c)
        self.fill_rect(x, y + h - thickness, w, thickness, c)
        self.fill_rect(x, y, thickness, h, c)
        self.fill_rect(x + w - thickness, y, thickness, h, c)

    def line(self, x0, y0, x1, y1, c):
        steps = max(abs(x1 - x0), abs(y1 - y0), 1)
        for i in range(steps + 1):
            x = x0 + (x1 - x0) * i // steps
            y = y0 + (y1 - y0) * i // steps
            self._px(x, y, c)

    def arrow(self, x0, y0, x1, y1, c, head=8):
        self.line(x0, y0, x1, y1, c)
        # arrowhead
        import math
        ang = math.atan2(y1 - y0, x1 - x0)
        for a in (ang + 2.6, ang - 2.6):
            self.line(x1, y1, x1 - int(head * math.cos(a)), y1 - int(head * math.sin(a)), c)


# ---------------------------------------------------------------------------
# Bitmap font (5x7) for labels — a compact uppercase set we actually use
# ---------------------------------------------------------------------------
FONT = {
    'A': ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    'B': ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    'C': ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
    'D': ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    'E': ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    'F': ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
    'G': ["01111", "10000", "10000", "10111", "10001", "10001", "01111"],
    'H': ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    'I': ["11111", "00100", "00100", "00100", "00100", "00100", "11111"],
    'J': ["00111", "00010", "00010", "00010", "10010", "10010", "01100"],
    'K': ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    'L': ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    'M': ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    'N': ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
    'O': ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    'P': ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    'Q': ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
    'R': ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    'S': ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    'T': ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    'U': ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    'V': ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
    'W': ["10001", "10001", "10001", "10101", "10101", "10101", "01010"],
    'X': ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
    'Y': ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
    'Z': ["11111", "00001", "00010", "00100", "01000", "10000", "11111"],
    '0': ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
    '1': ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    '2': ["01110", "10001", "00001", "00110", "01000", "10000", "11111"],
    '3': ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
    '4': ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    '5': ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
    '6': ["01110", "10000", "10000", "11110", "10001", "10001", "01110"],
    '7': ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    '8': ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    '9': ["01110", "10001", "10001", "01111", "00001", "00001", "01110"],
    ' ': ["00000"] * 7, '-': ["00000", "00000", "11111", "00000", "00000", "00000", "00000"],
    '>': ["01000", "00100", "00010", "00001", "00010", "00100", "01000"],
    '<': ["00010", "00100", "01000", "10000", "01000", "00100", "00010"],
    '.': ["00000", "00000", "00000", "00000", "00000", "01100", "01100"],
    ':': ["00000", "01100", "01100", "00000", "01100", "01100", "00000"],
    '/': ["00001", "00010", "00010", "00100", "01000", "01000", "10000"],
    '_': ["00000"] * 6 + ["11111"],
    '[': ["01110", "01000", "01000", "01000", "01000", "01000", "01110"],
    ']': ["01110", "00010", "00010", "00010", "00010", "00010", "01110"],
    '=': ["00000", "11111", "00000", "11111", "00000", "00000", "00000"],
    '+': ["00000", "00100", "00100", "11111", "00100", "00100", "00000"],
    '*': ["00000", "10101", "01110", "11111", "01110", "10101", "00000"],
    ',': ["00000", "00000", "00000", "00000", "01100", "01100", "00100"],
    '(': ["00010", "00100", "01000", "01000", "01000", "00100", "00010"],
    ')': ["01000", "00100", "00010", "00010", "00010", "00100", "01000"],
}


def draw_text(c, text, x, y, color, scale=2):
    color = bytes(color)
    cx = x
    for ch in text:
        glyph = FONT.get(ch.upper(), FONT[' '])
        for gy, row in enumerate(glyph):
            for gx, bit in enumerate(row):
                if bit == '1':
                    for sy in range(scale):
                        yy = y + gy * scale + sy
                        i = (yy * c.w + cx + gx * scale) * 4
                        c.buf[i:i + scale * 4] = color * scale
        cx += 6 * scale


def text_width(text, scale=2):
    return len(text) * 6 * scale


def centered(c, text, cx, y, color, scale=2):
    w = text_width(text, scale)
    draw_text(c, text, cx - w // 2, y, color, scale)


# ---------------------------------------------------------------------------
# Diagram layout
# ---------------------------------------------------------------------------
C = {
    "bg": (18, 18, 32),
    "panel": (30, 30, 50),
    "border": (90, 90, 130),
    "ai": (52, 152, 219),       # blue
    "cyber": (46, 204, 113),    # green
    "chain": (155, 89, 182),    # purple
    "white": (230, 230, 240),
    "dim": (150, 150, 170),
    "warn": (241, 196, 15),
    "red": (231, 76, 60),
}


def box(c, x, y, w, h, title, color, subtitle=None, scale=2):
    c.fill_rect(x, y, w, h, C["panel"])
    c.rect(x, y, w, h, color, 2)
    centered(c, title, x + w // 2, y + 14, color, scale)
    if subtitle:
        centered(c, subtitle, x + w // 2, y + 14 + 7 * scale + 6, C["dim"], 1)


def build() -> bytes:
    W, H = 1100, 1500
    c = Canvas(W, H, C["bg"])

    # Title
    centered(c, "SENTINEL - WORKING ARCHITECTURE", W // 2, 24, C["white"], 3)
    centered(c, "AI + CYBERSECURITY + BLOCKCHAIN", W // 2, 62, C["dim"], 2)

    # 1. Operator
    box(c, 350, 110, 400, 60, "YOU (TERMINAL)", C["white"], "python run.py samples/phishing.eml")
    c.arrow(550, 170, 550, 210, C["white"])

    # 2. Agent controller
    box(c, 220, 210, 660, 130, "AGENT CONTROLLER", C["ai"],
        "THINK -> CHOOSE TOOL -> ACT -> OBSERVE -> UPDATE RISK")
    # LLM inside
    box(c, 250, 250, 270, 70, "LOCAL LLM (OLLAMA)", C["ai"], "llama3.1 / qwen2.5")
    c.arrow(550, 340, 550, 380, C["white"])

    # 3. Tool whitelist
    box(c, 300, 380, 500, 70, "TOOL WHITELIST", C["cyber"], "16 tools - name -> function (no shell)")
    c.arrow(550, 450, 550, 490, C["white"])

    # Three branches
    box(c, 60, 490, 300, 60, "PURE PYTHON", C["cyber"], "parse_headers / resolve_origin / extract_urls")
    box(c, 400, 490, 300, 60, "NETWORK TOOLS", C["cyber"], "geolocate_ip / tor / reputation / dns / whois")
    box(c, 740, 490, 300, 60, "FILE-TOUCHING", C["warn"], "static_scan + 7 forensic binaries")
    c.arrow(550, 490, 210, 490, C["cyber"])
    c.arrow(550, 490, 550, 490, C["cyber"])
    c.arrow(550, 490, 890, 490, C["warn"])

    # Sandbox (under file-touching)
    c.arrow(890, 550, 890, 590, C["warn"])
    box(c, 690, 590, 360, 90, "DOCKER SANDBOX", C["red"],
        "--network none / read-only / cap-drop ALL / destroyed per run")
    c.arrow(890, 680, 890, 720, C["warn"])

    # Risk score
    box(c, 300, 720, 500, 60, "RISK SCORE (0-100)", C["white"], "updated after every tool call")
    c.arrow(550, 780, 550, 820, C["white"])

    # Outputs
    box(c, 60, 820, 300, 90, "DESKTOP PET", C["ai"], "expressions / chat / mail / notify")
    box(c, 400, 820, 300, 90, "BLOCKCHAIN LEDGER", C["chain"], "hash-chain or Ganache (tamper-proof)")
    box(c, 740, 820, 300, 90, "FORENSIC REPORT", C["cyber"], "reports/*.md + evidence")
    c.arrow(550, 820, 210, 850, C["white"])
    c.arrow(550, 820, 550, 850, C["white"])
    c.arrow(550, 820, 890, 850, C["white"])

    # Pillar legend
    ly = 950
    centered(c, "THREE PILLARS", W // 2, ly, C["white"], 2)
    c.fill_rect(300, ly + 30, 20, 20, C["ai"])
    draw_text(c, "AI - local reasoning brain (Ollama tool-calling)", 335, ly + 30, C["dim"], 1)
    c.fill_rect(300, ly + 56, 20, 20, C["cyber"])
    draw_text(c, "CYBERSECURITY - 16 tools + sandbox + safety gates", 335, ly + 56, C["dim"], 1)
    c.fill_rect(300, ly + 82, 20, 20, C["chain"])
    draw_text(c, "BLOCKCHAIN - tamper-evident evidence ledger", 335, ly + 82, C["dim"], 1)

    # Safety strip
    sy = ly + 130
    centered(c, "SAFETY: tool whitelist | Docker sandbox | human confirm | 15s timeout | kill-switch | prompt-injection defense",
             W // 2, sy, C["warn"], 1)

    return _png(bytes(c.buf), W, H)


def main() -> int:
    outdir = Path(__file__).parent.parent / "previews"
    outdir.mkdir(exist_ok=True)
    out = outdir / "architecture.png"
    out.write_bytes(build())
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
