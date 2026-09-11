"""Generate the SENTINEL favicon set from the brand geometry.

Draws the shield mark (same shape as the UI brand SVG) on a blue-tinted
rounded tile, then writes:

    frontend/icons/favicon.ico          16 + 32 + 48 multi-res
    frontend/icons/favicon.svg          crisp vector for modern browsers
    frontend/icons/apple-touch-icon.png 180x180 (opaque, iOS home screen)
    frontend/icons/icon-192.png         PWA / Android
    frontend/icons/icon-512.png         PWA / store listing

Usage:  python scripts/make_icons.py
Committed outputs live in frontend/icons/ — rerun only when the brand changes.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "frontend" / "icons"

# brand tokens (see frontend/css/theme.css)
BG      = (10, 14, 20, 255)      # --bg
BLUE    = (56, 189, 248, 255)    # --bl-400 (center)
DEEP    = (2, 132, 199, 255)     # --bl-600
INK     = (4, 40, 63, 255)       # dark-blue ink used inside the mark

S = 512  # master render size


def rounded_tile(size: int, radius_frac: float = 0.22) -> Image.Image:
    """BG tile with rounded corners (radius as a fraction of size)."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    r = int(size * radius_frac)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=r, fill=BG)
    return img


def draw_shield(img: Image.Image) -> None:
    """The SENTINEL shield: outline + exclamation glyph, centered."""
    d = ImageDraw.Draw(img)
    s = img.size[0]
    # shield body (same proportions as the UI svg path)
    cx = s / 2
    top = s * 0.20
    bot = s * 0.80
    half = s * 0.235
    # superellipse-ish shield: rounded-corner polygon via arc segments
    body = [
        (cx - half, top + s * 0.06),
        (cx, top),
        (cx + half, top + s * 0.06),
        (cx + half, s * 0.52),
        (cx, bot),
        (cx - half, s * 0.52),
    ]
    d.polygon(body, outline=BLUE, width=max(6, s // 26))
    # exclamation mark
    lw = max(8, s // 22)
    d.line([(cx, s * 0.34), (cx, s * 0.52)], fill=BLUE, width=lw)
    r_dot = s * 0.035
    d.ellipse([cx - r_dot, s * 0.585 - r_dot, cx + r_dot, s * 0.585 + r_dot], fill=BLUE)


def master() -> Image.Image:
    img = rounded_tile(S)
    draw_shield(img)
    return img


def to_svg() -> str:
    """Vector twin of the raster mark (matches the UI brand SVG geometry)."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
        '<rect width="24" height="24" rx="5" fill="#0A0E14"/>'
        '<path d="M12 3.4l6.4 3.6v5.2c0 3.8-2.6 7.2-6.4 8.6-3.8-1.4-6.4-4.8-6.4-8.6V7z" '
        'fill="none" stroke="#38BDF8" stroke-width="1.7" stroke-linejoin="round"/>'
        '<path d="M12 7.2v4.6" stroke="#38BDF8" stroke-width="1.7" stroke-linecap="round"/>'
        '<circle cx="12" cy="14.9" r="1" fill="#38BDF8"/></svg>'
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    img = master()

    # multi-resolution .ico
    img.save(OUT / "favicon.ico", format="ICO", sizes=[(16, 16), (32, 32), (48, 48)])

    # apple touch + PWA (opaque: iOS renders transparency black anyway)
    opaque = Image.new("RGBA", (S, S), BG)
    opaque.alpha_composite(img)
    for name, px in (("apple-touch-icon.png", 180), ("icon-192.png", 192), ("icon-512.png", 512)):
        opaque.resize((px, px), Image.LANCZOS).convert("RGB").save(OUT / name, format="PNG")

    # vector favicon
    (OUT / "favicon.svg").write_text(to_svg(), encoding="utf-8")

    print(f"wrote {len(list(OUT.iterdir()))} icons -> {OUT}")


if __name__ == "__main__":
    main()
