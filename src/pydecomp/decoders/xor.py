"""pydecomp - xor."""
from __future__ import annotations

from collections import Counter
import warnings


_XOR_WEIGHT = {}

for _b in range(256):
    if _b == 32:
        _XOR_WEIGHT[_b] = 4.0
    elif _b in (9, 10, 13):
        _XOR_WEIGHT[_b] = 1.2
    elif 97 <= _b <= 122:
        _XOR_WEIGHT[_b] = 2.2
    elif 65 <= _b <= 90:
        _XOR_WEIGHT[_b] = 1.8
    elif 48 <= _b <= 57:
        _XOR_WEIGHT[_b] = 1.4
    elif 32 < _b < 127:
        _XOR_WEIGHT[_b] = 1.0
    else:
        _XOR_WEIGHT[_b] = -6.0

def _score_text(data):
    """How much does this look like readable text?  Mean character weight."""
    if not data:
        return 0.0
    total = 0.0
    for byte in data:
        total += _XOR_WEIGHT[byte]
    return total / len(data)

def _xor_with(data, key):
    size = len(key)
    return bytes(b ^ key[i % size] for i, b in enumerate(data))

def _key_score(data, key, python_bonus=True):
    plain = _xor_with(data, key)
    score = _score_text(plain)
    if python_bonus:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                compile(plain, "<xor>", "exec")
            score += 1.5
        except (SyntaxError, ValueError):
            pass
    return score

def xor_best(data, max_key=16, python_bonus=True):
    """Recover the most plausible repeating-XOR key by scoring the plaintext.

    Every candidate key length is attacked column by column (all 256 single-byte
    keys, scored from the column's byte counts).  The assembled key is then
    hill-climbed: each column may swap to its second- or third-best byte as long
    as the *whole* plaintext scores better, with a large bonus when the result
    parses as Python.  That last step is what rescues keys whose columns are too
    repetitive for frequency analysis alone.
    """
    data = bytes(data)
    if len(data) < 16 or len(data) > 65536:
        return None, None
    best = None
    limit = min(max_key, max(1, len(data) // 8))
    for size in range(1, limit + 1):
        options = []
        for pos in range(size):
            counts = Counter(data[pos::size])
            scored = []
            for candidate in range(256):
                total = 0.0
                for byte, count in counts.items():
                    total += count * _XOR_WEIGHT[byte ^ candidate]
                scored.append((total, candidate))
            scored.sort(reverse=True)
            options.append([candidate for _total, candidate in scored[:3]])

        key = bytearray(column[0] for column in options)
        penalty = 0.03 * size                          # prefer the shortest key
        score = _key_score(data, key, python_bonus) - penalty
        for _round in range(3):
            improved = False
            for pos in range(size):
                for candidate in options[pos][1:]:
                    trial = bytearray(key)
                    trial[pos] = candidate
                    trial_score = _key_score(data, trial, python_bonus) - penalty
                    if trial_score > score + 1e-9:
                        key, score, improved = trial, trial_score, True
            if not improved:
                break
        plain = _xor_with(data, key)
        if best is None or score > best[0] + 1e-9:
            best = (score, bytes(key), plain)
    if not best:
        return None, None
    score, key, plain = best
    if not any(key):
        return None, None
    if score < 1.6:
        return None, None
    return key, plain
