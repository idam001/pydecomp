"""pydecomp - iocs."""
from __future__ import annotations

import re


_IOC_PATTERNS = [
    ("url", re.compile(r"https?://[^\s'\"\)\]\}\,]{4,200}")),
    ("webhook", re.compile(r"https://(?:discord(?:app)?\.com/api/webhooks|ptb\.discord\.com)"
                           r"/[^\s'\"]{10,200}")),
    ("telegram", re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,40}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("domain", re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                          r"(?:com|net|org|ru|io|xyz|top|shop|info|biz|cn|tk|ml|ga|cf|gq|onion)\b",
                          re.I)),
    ("btc", re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")),
    ("eth", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("mutex", re.compile(r"(?:Global|Local)\[")),
]
