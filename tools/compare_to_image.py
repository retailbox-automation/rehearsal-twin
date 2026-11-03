"""Screenshot the page next to the reference image and score edge similarity.

Needs playwright, numpy, pillow and scipy (dev tooling, not a runtime dependency).
Usage: python tools/compare_to_image.py --url 'http://127.0.0.1:8701/?at=review' \
           --image UI-B.png --out round-1.png --chrome '<path to Chrome binary>'
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from PIL import Image
from scipy import ndimage


def screenshot(url: str, chrome: str | None, size: tuple[int, int], out: Path) -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        kwargs = {"executable_path": chrome} if chrome else {}
        browser = pw.chromium.launch(headless=True, **kwargs)
        page = browser.new_page(viewport={"width": size[0], "height": size[1]})
        page.goto(url, wait_until="networkidle")
        page.wait_for_timeout(800)
        page.screenshot(path=str(out))
        browser.close()


def edges(img: Image.Image, keep: float = 0.08) -> np.ndarray:
    """Boolean contour map: Sobel magnitude, strongest `keep` fraction of pixels."""
    gray = np.asarray(img.convert("L"), dtype=np.float32)
    gray = ndimage.gaussian_filter(gray, 1.0)
    mag = np.hypot(ndimage.sobel(gray, axis=0), ndimage.sobel(gray, axis=1))
    return mag >= np.quantile(mag, 1 - keep)


def edge_f1(a: np.ndarray, b: np.ndarray, tol: int = 3) -> dict:
    """F1 of contour overlap where a pixel matches if the other map has an edge within `tol` px."""
    near_b = ndimage.binary_dilation(b, iterations=tol)
    near_a = ndimage.binary_dilation(a, iterations=tol)
    precision = float((a & near_b).sum() / max(a.sum(), 1))
    recall = float((b & near_a).sum() / max(b.sum(), 1))
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    return {"f1": round(f1, 4), "precision": round(precision, 4), "recall": round(recall, 4)}


def side_by_side(ref: Image.Image, page: Image.Image, out: Path) -> None:
    gap = 16
    canvas = Image.new("RGB", (ref.width + page.width + gap, max(ref.height, page.height)), (255, 255, 255))
    canvas.paste(ref, (0, 0))
    canvas.paste(page, (ref.width + gap, 0))
    canvas.save(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", required=True)
    ap.add_argument("--image", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path, help="side-by-side PNG: reference | page")
    ap.add_argument("--chrome", help="path to a Chrome/Chromium binary")
    ap.add_argument("--shot", type=Path, help="where to keep the raw page screenshot")
    ap.add_argument("--tol", type=int, default=3)
    args = ap.parse_args()

    ref = Image.open(args.image).convert("RGB")
    shot = args.shot or args.out.with_suffix(".page.png")
    screenshot(args.url, args.chrome, ref.size, shot)
    page = Image.open(shot).convert("RGB")
    if page.size != ref.size:
        page = page.resize(ref.size)
    side_by_side(ref, page, args.out)
    result = edge_f1(edges(page), edges(ref), args.tol)
    result["image"] = str(args.out)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
