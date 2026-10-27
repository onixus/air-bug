#!/usr/bin/env python3
"""Dependency-free Apex literal lint and WCAG contrast regression checks."""
import json
import math
import pathlib
import re

root = pathlib.Path(__file__).resolve().parents[1]
java = root / "app/src/main/java/dev/onixus/aircrack"
source = (java / "ApexTokens.java").read_text()
colors = re.findall(r"(\w+) = dark \? 0xff([0-9a-f]{6}) : 0xff([0-9a-f]{6})", source)
assert len(colors) == 16, "Unexpected semantic token table"
for path in java.glob("*.java"):
    if path.name != "ApexTokens.java":
        assert not re.search(r"0x[0-9a-fA-F]{6,8}|#[0-9a-fA-F]{6}\b|Color\.(?:rgb|argb|parseColor)", path.read_text()), f"Color outside token table: {path}"
assert "H1 = 24, H2 = 18, BODY = 14, BODY_SM = 13, CAPTION = 12, OVERLINE = 11" in source
for name in ("Inter", "JetBrainsMono"):
    assert (root / f"app/src/main/assets/fonts/{name}.ttf").stat().st_size > 100_000
    assert (root / f"app/src/main/assets/fonts/{name}-OFL.txt").is_file()

def rgb(value):
    return tuple(int(value[i:i+2], 16) for i in (0, 2, 4))

def luminance(value):
    channels = [x / 255 for x in value]
    linear = [x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4 for x in channels]
    return sum(x * weight for x, weight in zip(linear, (0.2126, 0.7152, 0.0722)))

def contrast(a, b):
    first, second = sorted((luminance(a), luminance(b)))
    return (second + 0.05) / (first + 0.05)

report = {}
for index, mode in ((1, "dark"), (2, "light")):
    tokens = {entry[0]: rgb(entry[index]) for entry in colors}
    for status in ("success", "warning", "danger"):
        tokens[status + "Subtle"] = tuple((a*94 + b*6)//100 for a, b in zip(tokens["surface"], tokens[status]))
    checks = []
    for ink in ("text", "secondary", "muted", "accent"):
        # Muted: overlines on canvas/surface and hints on field, never hover.
        for fill in (("canvas", "surface", "field") if ink == "muted" else ("canvas", "surface", "field", "hover")):
            checks.append((ink, fill, 4.5))
    for fill in ("surface", "field", "hover"):
        checks.extend((("control", fill, 3), ("focus", fill, 3)))
    checks.append(("onAccent", "accent", 4.5))
    for status in ("success", "warning", "danger"):
        checks.extend(((status, status+"Subtle", 4.5), ("text", status+"Subtle", 4.5), ("secondary", status+"Subtle", 4.5)))
    values = {}
    for ink, fill, minimum in checks:
        ratio = contrast(tokens[ink], tokens[fill])
        assert ratio >= minimum, f"{mode}: {ink}/{fill}: {ratio:.3f} < {minimum}"
        values[f"{ink}/{fill}"] = round(ratio, 3)
    report[mode] = values
print(json.dumps(report, indent=2))
print("APEX: centralized colors, local fonts, typography and contrast PASS")
