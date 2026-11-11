"""Indicator extraction that understands the layers it just removed.

Most tools grep the *original* file for URLs, so a sample that writes

    _ = lambda __: zlib.decompress(b64decode(__[::-1]))
    exec(_('eJxLzkzLyy9KBQA…'))

gives them nothing.  pydecomp runs the extractor over the recovered source
*and* over decode variants of every string literal (base64, base32, hex,
reversed, rot13) and over the printable runs carved from the raw input, so an
address that was one codec away is still reported.

Everything here is static: regexes, entropy, codecs.  No sample text is ever
imported or evaluated.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import math
import re

# --------------------------------------------------------------------------
# patterns: (label, regex, severity).  Severities are advisory ordering only,
# pydecomp never refuses to work because of what it finds.
# --------------------------------------------------------------------------
_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # --- command and control -------------------------------------------------
    ("discord-webhook",
     re.compile(r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/"
                r"[0-9]{1,25}/[A-Za-z0-9_\-]{1,120}"), "high"),
    ("slack-webhook",
     re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[A-Za-z0-9]+"), "high"),
    ("telegram-api",
     re.compile(r"https?://api\.telegram\.org/bot(?:\d{6,12}:[A-Za-z0-9_\-]{30,45})?"
                r"[A-Za-z0-9_\-/.]*"), "high"),
    ("telegram-bot",
     re.compile(r"\b\d{8,12}:[A-Za-z0-9_\-]{32,40}\b"), "high"),
    ("url", re.compile(r"https?://[^\s'\"\)\]\}\,>]{4,300}"), "info"),
    ("onion", re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.I), "high"),
    ("ftp", re.compile(r"\bftp://[^\s'\"]{4,200}", re.I), "medium"),
    ("db-uri", re.compile(r"\b(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp)://"
                          r"[^\s'\"\)]{4,200}", re.I), "medium"),
    # --- tokens and keys -----------------------------------------------------
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])"
                           r"[A-Z0-9]{16}\b"), "high"),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,90})\b"),
     "high"),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,40}\b"), "high"),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,60}\b"), "high"),
    ("stripe-key", re.compile(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,60}\b"), "high"),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("google-secret", re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{28}\b"), "high"),
    ("openai-key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,120}\b"), "high"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-+/=]{8,}\b"),
     "high"),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     "high"),
    ("discord-token", re.compile(r"\b(?:mfa\.[A-Za-z0-9_\-]{80,100}|"
                                 r"[A-Za-z0-9_\-]{24,26}\.[A-Za-z0-9_\-]{6}\."
                                 r"[A-Za-z0-9_\-]{25,110})\b"), "high"),
    # --- money ---------------------------------------------------------------
    ("btc", re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"), "medium"),
    ("eth", re.compile(r"\b0x[a-fA-F0-9]{40}\b"), "medium"),
    ("xmr", re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"), "medium"),
    # --- network -------------------------------------------------------------
    ("ipv4", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"), "info"),
    ("ipv6", re.compile(r"\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b", re.I), "info"),
    ("domain", re.compile(r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                          r"(?:com|net|org|ru|su|io|xyz|top|shop|store|site|online|club|"
                          r"icu|info|biz|cn|hk|tk|ml|ga|cf|gq|pw|cc|ws|me|ly|to|in|co|"
                          r"app|dev|link|click|fun|live|space|website|monster|rest)\b", re.I),
     "info"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]{2,64}@[A-Za-z0-9.\-]{2,255}\.[A-Za-z]{2,10}\b"),
     "info"),
    # --- host side -----------------------------------------------------------
    ("windows-path", re.compile(r"(?:[A-Za-z]:\\\\?|%[A-Za-z_]+%\\\\?|%[A-Za-z_]+%)"
                                r"(?:[\\/][^\\/:\*\?\"<>\|\r\n]{1,60}){1,8}"), "info"),
    ("browser-artifact", re.compile(r"(?:Login Data|Local State|leveldb|key[34]\.db|"
                                    r"cookies\.sqlite|wallet\.dat|tdata|MetaMask|Exodus|"
                                    r"Electrum|Phantom)", re.I), "medium"),
    ("exec-sink", re.compile(r"\b(?:os\.system|subprocess\.(?:run|Popen|call|check_output)|"
                             r"ctypes\.windll|WinExec|ShellExecute)\b"), "medium"),
    ("encoded-blob", re.compile(r"['\"]([A-Za-z0-9+/=_\-]{160,})['\"]"), "info"),
]

_BENIGN_DOMAINS = {
    "python.org", "pypi.org", "github.com", "raw.githubusercontent.com",
    "readthedocs.io", "w3.org", "json-schema.org", "example.com", "example.org",
    "localhost", "schemas.android.com", "opensource.org", "gnu.org",
    "creativecommons.org", "microsoft.com", "pythonhosted.org", "docs.python.org",
    # hosts whose full URL is the indicator; the bare domain only adds noise
    "discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com",
    "api.telegram.org", "hooks.slack.com", "telegram.org",
}
_BENIGN_HOSTS = {"127.0.0.1", "0.0.0.0", "8.8.8.8", "1.1.1.1", "255.255.255.255"}
_BENIGN_TOKENS = re.compile(r"(?:your[_-]?(?:api[_-]?)?(?:key|token|secret)|"
                            r"xxx+|placeholder|changeme|redacted|example|dummy|"
                            r"insert[_-]?|test[_-]?key)", re.I)
_SECRET_ASSIGN = re.compile(
    r"""(?ix)\b(api[_-]?key|apikey|secret|secret[_-]?key|token|access[_-]?token|
                auth[_-]?token|password|passwd|pwd)\b\s*[:=]\s*
        (?:[rbuf]{0,2})?['"]([^'"\n]{12,120})['"]""")
_HIGH_ENTROPY = 3.4

# Labels worth finding *inside* a decoded literal.  Branded tokens are excluded:
# a rot13 or base64 view of `ghp_...` is not a second indicator, it is noise.
_NETWORK_LABELS = {"url", "domain", "ipv4", "ipv6", "email", "onion", "ftp",
                   "db-uri", "telegram-api", "discord-webhook", "slack-webhook",
                   "windows-path"}

# Carved bytes are noisy: a binary blob will happily contain `131.0.0.0` and
# `%DL%\xf0\x00`.  So carving only accepts indicators that cannot be
# accidental - anything weaker is only reported when it comes from real source.
_STRONG_LABELS = {"url", "discord-webhook", "slack-webhook", "telegram-api",
                  "telegram-bot", "discord-token", "email", "onion", "db-uri",
                  "ftp", "aws-key", "github-token", "gitlab-token", "slack-token",
                  "stripe-key", "google-key", "google-secret", "openai-key", "jwt",
                  "private-key", "btc", "eth", "xmr", "browser-artifact"}


def defang(value: str) -> str:
    """Make an indicator safe to paste into a ticket."""
    url = re.match(r"^(https?)://([^/\s]+)(.*)$", value, re.S)
    if url:
        scheme, host, rest = url.groups()
        return f"{scheme.replace('http', 'hxxp')}://{host.replace('.', '[.]')}{rest}"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?", value):
        return value.replace(".", "[.]")
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,10}", value, re.I):
        return value.replace(".", "[.]")
    if re.fullmatch(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}", value):
        local, _, host = value.partition("@")
        return f"{local}[at]{host.replace('.', '[.]')}"
    return value


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _printable(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13))
    return good / len(data)


def _decode_variants(value: str) -> list[str]:
    """One more layer under a string literal: b64, b32, hex, reversed, rot13."""
    out: list[str] = []
    candidate = value.strip()
    if len(candidate) >= 12:
        compact = candidate.replace("\n", "").replace("\r", "")
        for attempt in (compact, compact[::-1]):
            if len(attempt) >= 12 and re.fullmatch(r"[A-Za-z0-9+/=_\-]+", attempt):
                padded = attempt + "=" * (-len(attempt) % 4)
                try:
                    raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"),
                                           validate=False)
                except (binascii.Error, ValueError):
                    raw = b""
                if len(raw) >= 8 and _printable(raw) > 0.85:
                    out.append(raw.decode("utf-8", "replace"))
        if len(compact) >= 16 and re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
            try:
                raw = bytes.fromhex(compact)
            except ValueError:
                raw = b""
            if len(raw) >= 8 and _printable(raw) > 0.85:
                out.append(raw.decode("utf-8", "replace"))
        if re.fullmatch(r"[A-Z2-7=]+", compact) and len(compact) >= 16:
            try:
                raw = base64.b32decode(compact + "=" * (-len(compact) % 8))
            except (binascii.Error, ValueError):
                raw = b""
            if len(raw) >= 8 and _printable(raw) > 0.85:
                out.append(raw.decode("utf-8", "replace"))
        if len(candidate) >= 8 and re.search(r"[A-Za-z]{4}", candidate):
            try:
                out.append(codecs.decode(candidate, "rot13"))
            except Exception:                          # noqa: BLE001
                pass
    return [text for text in out if text and text != value]


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4 or any(not part.isdigit() for part in parts):
        return False
    if any(int(part) > 255 for part in parts):
        return False
    return value not in _BENIGN_HOSTS and not value.startswith(("0.", "127.", "169.254."))


def _keep(label: str, value: str, text: str) -> bool:
    """Reject the look-alikes that make indicator lists useless."""
    if label == "ipv4":
        if value.endswith(".0.0.0") or value.endswith(".255.255.255"):
            return False
        return _valid_ipv4(value)
    if label == "ipv6":
        return value.count(":") >= 3 and value not in ("::1", "::")
    if label == "domain":
        lowered = value.lower()
        if lowered in _BENIGN_DOMAINS or lowered.endswith(".py"):
            return False
        # a file name with an extension is not a domain
        if re.search(r"\.(py|exe|dll|txt|json|log|db|dat|zip|png|jpg|so|pyd)$", lowered):
            return False
        # `k12.CN` is binary junk next to a real host, not a domain
        if value != lowered and value.rsplit(".", 1)[-1] != lowered.rsplit(".", 1)[-1]:
            return False
        return True
    if label == "email":
        return "@example." not in value.lower() and not value.lower().endswith(".png")
    if label in ("telegram-bot", "discord-token", "aws-key", "jwt"):
        return not _BENIGN_TOKENS.search(value)
    if label == "openai-key":
        return len(value) >= 24 and not _BENIGN_TOKENS.search(value)
    if label == "windows-path":
        if len(value) < 6 or ("\\" not in value and "%" not in value):
            return False
        if "\\x" in value or any(ord(char) < 32 for char in value):
            return False
        return bool(re.fullmatch(r"[\w%.:\\ /\-{}()*?]{6,200}", value))
    if label == "url":
        if re.search(r"\.(png|jpe?g|gif|css|js|svg|woff2?)(\?|$)", value, re.I):
            return False
        return "\\x" not in value and len(value) >= 12
    if label == "encoded-blob":
        return entropy(value) > 4.0
    return True


def _clean_url(value: str) -> str:
    """Cut the binary tail a carved URL picks up."""
    for marker in ("\\x", "\\u", "\\0"):
        cut = value.find(marker)
        if cut > 8:
            value = value[:cut]
    return value.strip().rstrip(',.;)]}"')


def _scan(text: str, found: dict[str, set], depth: int,
          only_labels: set[str] | None = None) -> None:
    for label, pattern, _severity in _PATTERNS:
        if only_labels is not None and label not in only_labels:
            continue
        for match in pattern.finditer(text):
            value = match.group(1) if label == "encoded-blob" and match.groups() else match.group(0)
            if label == "exec-sink":
                value = match.group(0)
            if label == "url":
                value = _clean_url(value)
            if not _keep(label, value, text):
                continue
            bucket = found.setdefault(label, set())
            if len(bucket) < 200:
                bucket.add(value)
    # a generic high-entropy assignment is a secret even without a brand prefix
    for match in _SECRET_ASSIGN.finditer(text):
        value = match.group(2)
        if _BENIGN_TOKENS.search(value) or len(value) < 16:
            continue
        if entropy(value) >= _HIGH_ENTROPY and not value.startswith(("http", "/", "C:")):
            bucket = found.setdefault("secret-literal", set())
            if len(bucket) < 200:
                bucket.add(value)
    # words that only make sense around an exfiltration channel
    if "api.telegram.org" in text or "sendDocument" in text:
        for match in re.finditer(r"(?<![\w-])-?\d{6,14}(?![\w-])", text):
            value = match.group(0)
            if len(value.lstrip("-")) >= 8:
                found.setdefault("telegram-chat", set()).add(value)
    if depth > 0:
        for literal in re.findall(r"'([^'\n]{12,4000})'|\"([^\"\n]{12,4000})\"", text):
            candidate = literal[0] or literal[1]
            for variant in _decode_variants(candidate):
                _scan(variant, found, depth - 1, only_labels=_NETWORK_LABELS)


def _carved_strings(data: bytes, minimum: int = 6, limit: int = 20000) -> str:
    """Printable runs in a binary payload, so a packed config still yields IOCs."""
    runs: list[str] = []
    for chunk in re.finditer(rb"[\x20-\x7e]{%d,400}" % minimum, data[:4_000_000]):
        runs.append(chunk.group(0).decode("ascii", "replace"))
        if len(runs) >= limit:
            break
    return "\n".join(runs)


def extract(source: str, raw: bytes | None = None) -> dict:
    """Return the indicator sheet for a recovered program (and its raw input)."""
    found: dict[str, set] = {}
    _scan(source, found, depth=2)
    from_recovered = {label: set(values) for label, values in found.items()}

    carved: dict[str, set] = {}
    if raw:
        haystack = _carved_strings(raw)
        if len(haystack) > len(source):
            _scan(haystack, carved, depth=1, only_labels=_STRONG_LABELS)

    iocs: dict[str, list[str]] = {}
    where: dict[str, str] = {}
    for label in sorted(set(from_recovered) | set(carved),
                        key=lambda item: (_SEVERITY_ORDER.get(_SEVERITY.get(item, "info"), 9),
                                          item)):
        values = set(from_recovered.get(label, set())) | set(carved.get(label, set()))
        if not values:
            continue
        ordered = sorted(values, key=lambda value: (-len(value), value))[:80]
        iocs[label] = ordered
        if values - from_recovered.get(label, set()):
            where[label] = "recovered+carved"
        else:
            where[label] = "recovered"
    counts = {label: len(values) for label, values in iocs.items()}
    return {"iocs": iocs, "counts": counts, "where": where,
            "defanged": {label: [defang(value) for value in values]
                         for label, values in iocs.items()}}


_SEVERITY = {label: severity for label, _pattern, severity in _PATTERNS}
_SEVERITY["secret-literal"] = "high"
_SEVERITY["telegram-chat"] = "high"
_SEVERITY_ORDER = {"high": 0, "medium": 1, "info": 2}


def summary(iocs: dict[str, list[str]]) -> str:
    """`3 url · 1 telegram-bot · 1 webhook` for the result panel."""
    if not iocs:
        return "none found"
    order = sorted(iocs, key=lambda label: (_SEVERITY_ORDER.get(_SEVERITY.get(label, "info"), 9),
                                            -len(iocs[label]), label))
    return " · ".join(f"{len(iocs[label])} {label}" for label in order)


def render_markdown(name: str, sheet: dict, digest: str = "") -> str:
    """The IOC sheet an analyst actually pastes into a ticket."""
    lines = [f"# Indicators — `{name}`", ""]
    if digest:
        lines += [f"- **sha256**: `{digest}`", ""]
    if not sheet["iocs"]:
        lines += ["No indicators recovered.", ""]
        return "\n".join(lines)
    lines += ["| severity | type | count |", "| --- | --- | --- |"]
    for label in sheet["iocs"]:
        severity = _SEVERITY.get(label, "info")
        lines.append(f"| {severity} | `{label}` | {sheet['counts'][label]} |")
    lines += ["", "Values below are defanged (`.` → `[.]`, `http` → `hxxp`); the JSON "
              "report keeps them raw.", ""]
    for label, values in sheet["iocs"].items():
        lines.append(f"## {label} ({_SEVERITY.get(label, 'info')})")
        lines.append("")
        lines += [f"- `{defang(value)}`" for value in values]
        lines.append("")
    return "\n".join(lines)
