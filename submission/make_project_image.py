"""Create a submission image from the recorded local revocation experiments."""

from __future__ import annotations

import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent / "project-image.png"
FONT_DIR = Path("C:/Windows/Fonts")


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    name = "segoeuib.ttf" if bold else "segoeui.ttf"
    return ImageFont.truetype(str(FONT_DIR / name), size)


def main() -> None:
    apc = json.loads((ROOT / "results/apc/audit.json").read_text(encoding="utf-8"))
    mandate = json.loads((ROOT / "results/apc/mandatekit_tree_comparator.json").read_text(encoding="utf-8"))
    behalf = json.loads((ROOT / "results/apc/behalf_comparator.json").read_text(encoding="utf-8"))["topology_fixture"]
    a = apc["branching_tree"]
    assert (a["total_envelopes"], a["unique_ids_total"], a["per_level"][-1]["denied_after_one_leaf_revocation"]) == (40, 4, 27)
    assert (mandate["total_envelopes"], mandate["unique_ids_total"], mandate["per_level"][-1]["denied_after_one_leaf_revocation"]) == (40, 40, 1)
    assert (behalf["tree_grants"], behalf["unique_tree_grant_ids"], behalf["after_one_leaf_revocation_tree_denied"]) == (40, 40, 1)

    W, H = 1800, 950
    background = "#F8FAFC"
    ink = "#182431"
    muted = "#516173"
    red = "#BC3B3B"
    green = "#2A8477"
    border = "#D5DDE5"
    im = Image.new("RGB", (W, H), background)
    draw = ImageDraw.Draw(im)
    draw.rounded_rectangle((55, 50, W - 55, H - 55), radius=28, fill="white", outline=border, width=3)
    draw.text((100, 85), "ONE LEAF REVOKED", fill=red, font=font(29, True))
    draw.text((100, 133), "How far does denial spread?", fill=ink, font=font(62, True))
    draw.text((102, 214), "Same 3-way, depth-3 delegation tree  ·  40 grants  ·  27 leaves", fill=muted, font=font(30))
    draw.line((100, 285, W - 100, 285), fill=border, width=3)

    rows = [
        ("APC reference", 4, 27, red),
        ("MandateKit 0.2.1", 40, 1, green),
        ("Behalf Python port", 40, 1, green),
    ]
    for row_idx, (label, unique_ids, denied, color) in enumerate(rows):
        y = 335 + row_idx * 161
        draw.text((100, y), label, fill=ink, font=font(37, True))
        draw.text((102, y + 55), f"{unique_ids} distinct grant IDs", fill=muted, font=font(25))
        draw.text((760, y - 1), f"{denied} / 27 leaves denied", fill=color, font=font(30, True))
        for i in range(27):
            x = 765 + (i % 9) * 91
            py = y + 54 + (i // 9) * 26
            draw.rounded_rectangle((x, py, x + 69, py + 17), radius=7,
                                   fill=red if i < denied else "#AEBBC8")
        if row_idx < 2:
            draw.line((100, y + 142, W - 100, y + 142), fill=border, width=2)

    draw.line((100, 830, W - 100, 830), fill=border, width=2)
    draw.text((102, 850), "Local synthetic authorization checks; each system's assumptions are described in the report.",
              fill=muted, font=font(20))
    im.save(OUT, optimize=True)
    print(OUT)


if __name__ == "__main__":
    main()
