"""pydecomp - sealed blob classification.

When a packer seals its payload we cannot open it, but we can say something
true and useful about *what kind of sealed thing it is*.  Three measurements,
each of which is reproducible by hand:

* **entropy** - bits per byte.  A compressed or encrypted stream sits near 8.0;
  a marshalled or tabular structure sits well below it.
* **dominant byte ratio** - one byte value hogging the stream means structure,
  not ciphertext (location tables are full of repeated small varints).
* **self-coincidence** - ``blob[i] == blob[i + period]``.  A repeating-key XOR
  leaves a peak at the key length; a fixed-size record table leaves one at the
  record size.  The measurement cannot tell those apart, so the verdict says
  "data repeats at a stride", not "the key is n".

The verdict strings below are deliberately modest.  They describe the
measurement, never the plaintext: this module never claims a blob was opened.
"""
from __future__ import annotations

import math
from collections import Counter

PERIOD_LIMIT = 64
PERIOD_FLOOR = 0.35          # self-coincidence no table reaches by accident
BASELINE = 1 / 256           # coincidence of two unrelated uniform bytes
RATIO_FLOOR = 8.0            # ...or this many times baseline, for text
ENTROPY_LOW = 4.0            # below this a stream is clearly structured
ENTROPY_HIGH = 7.5           # above this it is compressed or encrypted


def entropy(blob: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not blob:
        return 0.0
    total = len(blob)
    return max(0.0, -sum((count / total) * math.log2(count / total)
                         for count in Counter(blob).values()))


def dominant(blob: bytes) -> tuple[int, float]:
    """The byte value that appears most often, and its share of the stream."""
    if not blob:
        return 0, 0.0
    value, count = Counter(blob).most_common(1)[0]
    return value, count / len(blob)


def period(blob: bytes, limit: int = PERIOD_LIMIT) -> tuple[int, float]:
    """Best repeating-key length by self-coincidence, and its raw score.

    A plain-text blob is skewed, so even an unrelated stride scores about 0.06
    (tens of times the 1/256 of uniform noise).  ``repeats()`` applies that
    reasoning; this function reports the raw measurement.
    """
    best_period, best_score = 0, 0.0
    for stride in range(1, min(limit, len(blob) - 1) + 1):
        matches = sum(1 for left, right in zip(blob, blob[stride:]) if left == right)
        score = matches / max(1, len(blob) - stride)
        if score > best_score:
            best_period, best_score = stride, score
    return best_period, best_score


def repeats(score: float) -> bool:
    """Is this self-coincidence more than a skewed table would give by chance?"""
    return score >= PERIOD_FLOOR or score / BASELINE >= RATIO_FLOOR


def classify(blob: bytes) -> dict:
    """Size, statistics and a modest verdict for one sealed constant."""
    bits = entropy(blob)
    value, share = dominant(blob)
    stride, score = period(blob)
    if bits < 2.0:
        kind = "structured"
        verdict = f"near-constant stream (entropy {bits:.2f} b/B) — padding or a table"
    elif repeats(score):
        kind = "cyclical"
        verdict = (f"data repeats at a stride of {stride} bytes (self-coincidence"
                   f" {score:.2f}) — a repeating-key XOR or a fixed-size record table;"
                   f" not opened")
    elif bits < ENTROPY_LOW:
        kind = "structured"
        verdict = "structured table, low entropy — probably not encrypted"
    elif bits >= ENTROPY_HIGH:
        kind = "high-entropy"
        verdict = "high-entropy stream — no repeating key, not opened"
    else:
        kind = "opaque"
        verdict = "no repeating key found, not opened"
    return {
        "kind": kind,
        "size": len(blob),
        "entropy": round(bits, 2),
        "dominant": f"0x{value:02x}",
        "dominant_share": round(share, 3),
        "period": stride if repeats(score) else 0,
        "period_score": round(score, 3),
        "period_ratio": round(score / BASELINE, 1),
        "verdict": verdict,
    }


def summary(entries: list[dict]) -> str:
    """One line for the panel: how many blobs, how many kinds."""
    if not entries:
        return ""
    kinds: dict[str, int] = {}
    for entry in entries:
        kinds[entry["kind"]] = kinds.get(entry["kind"], 0) + 1
    total = sum(entry["size"] for entry in entries)
    detail = ", ".join(f"{count}× {name}" for name, count in kinds.items())
    return f"{len(entries)} blob(s) {total:,} B — {detail}"


def render(entries: list[dict]) -> list[str]:
    """Markdown-ish lines for the intelligence file."""
    if not entries:
        return []
    lines = ["## sealed blobs", ""]
    for index, entry in enumerate(entries, 1):
        lines.append(f"  {index}. {entry['size']:,} B   entropy {entry['entropy']:.2f} b/B"
                     f"   dominant {entry['dominant']} ({entry['dominant_share']:.1%})"
                     + (f"   period {entry['period']} @ {entry['period_score']:.2f}"
                        if entry["period"] else ""))
        lines.append(f"     {entry['verdict']}")
    lines.append("")
    return lines
