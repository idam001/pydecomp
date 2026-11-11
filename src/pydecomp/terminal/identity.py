"""pydecomp - identity.

Who built this, and where is it running?

The banner shows the author and the machine the analysis is happening on: the
network the host is attached to and the country implied by its timezone.  All
of it is discovered **offline** — no sockets, no DNS, no HTTP, and no
subprocess.  That is a hard rule of this project: the analyser must work in an
air-gapped lab, so anything that would need the network is either read from the
local filesystem or overridden by the user.

Overrides, in order of precedence:

    PYDECOMP_AUTHOR    PYDECOMP_NETWORK    PYDECOMP_COUNTRY

so the banner can be branded for a fork without touching the code.
"""
from __future__ import annotations

import os
import pathlib
import platform

AUTHOR = "Idam Emmanuel"
TOOL = "PYDECOMP"
WELCOME = "WELCOME TO IDAM EMMANUEL TOOLS"
STATUS = "OPEN SOURCE"
HANDLE = "IDAM/EMMANUEL"
SIGNATURE = "#[ Deobfuscated by idam Emmanuel ] only through pydecomp"

# Timezone → country.  Only what pydecomp can see locally: an IANA zone from
# /etc/timezone, the TZ variable, or the /etc/localtime symlink.
ZONE_COUNTRY = {
    "africa/lagos": "Nigeria", "africa/accra": "Ghana", "africa/abuja": "Nigeria",
    "africa/nairobi": "Kenya", "africa/cairo": "Egypt", "africa/johannesburg": "South Africa",
    "africa/casablanca": "Morocco", "africa/algiers": "Algeria", "africa/tunis": "Tunisia",
    "africa/khartoum": "Sudan", "africa/addis_ababa": "Ethiopia", "africa/dar_es_salaam": "Tanzania",
    "africa/kinshasa": "DR Congo", "africa/douala": "Cameroon", "africa/abidjan": "Ivory Coast",
    "africa/dakar": "Senegal", "africa/lusaka": "Zambia", "africa/harare": "Zimbabwe",
    "africa/kampala": "Uganda", "africa/luanda": "Angola", "africa/maputo": "Mozambique",
    "europe/london": "United Kingdom", "europe/dublin": "Ireland", "europe/paris": "France",
    "europe/berlin": "Germany", "europe/madrid": "Spain", "europe/rome": "Italy",
    "europe/amsterdam": "Netherlands", "europe/brussels": "Belgium", "europe/lisbon": "Portugal",
    "europe/warsaw": "Poland", "europe/stockholm": "Sweden", "europe/oslo": "Norway",
    "europe/helsinki": "Finland", "europe/copenhagen": "Denmark", "europe/zurich": "Switzerland",
    "europe/vienna": "Austria", "europe/prague": "Czechia", "europe/budapest": "Hungary",
    "europe/athens": "Greece", "europe/bucharest": "Romania", "europe/kyiv": "Ukraine",
    "europe/moscow": "Russia", "europe/istanbul": "Turkey", "asia/jerusalem": "Israel",
    "asia/dubai": "United Arab Emirates", "asia/riyadh": "Saudi Arabia", "asia/qatar": "Qatar",
    "asia/kuwait": "Kuwait", "asia/tehran": "Iran", "asia/karachi": "Pakistan",
    "asia/kolkata": "India", "asia/calcutta": "India", "asia/dhaka": "Bangladesh",
    "asia/kathmandu": "Nepal", "asia/colombo": "Sri Lanka", "asia/bangkok": "Thailand",
    "asia/jakarta": "Indonesia", "asia/manila": "Philippines", "asia/kuala_lumpur": "Malaysia",
    "asia/singapore": "Singapore", "asia/hong_kong": "Hong Kong", "asia/shanghai": "China",
    "asia/tokyo": "Japan", "asia/seoul": "South Korea", "asia/taipei": "Taiwan",
    "australia/sydney": "Australia", "australia/perth": "Australia", "pacific/auckland": "New Zealand",
    "america/new_york": "United States", "america/chicago": "United States",
    "america/denver": "United States", "america/los_angeles": "United States",
    "america/toronto": "Canada", "america/vancouver": "Canada", "america/mexico_city": "Mexico",
    "america/sao_paulo": "Brazil", "america/argentina/buenos_aires": "Argentina",
    "america/bogota": "Colombia", "america/lima": "Peru", "america/santiago": "Chile",
}

# Clock abbreviations that are unambiguous enough to show as a country hint.
TZ_COUNTRY = {"wat": "Nigeria", "cat": "DR Congo", "eat": "Kenya", "sast": "South Africa",
              "gmt": "United Kingdom", "bst": "United Kingdom", "cet": "Central Europe",
              "cest": "Central Europe", "est": "United States", "edt": "United States",
              "cst": "United States", "pst": "United States", "ist": "India",
              "pkt": "Pakistan", "jst": "Japan", "aest": "Australia"}


def _read_text(path: str, limit: int = 4_000) -> str:
    try:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def zone() -> str:
    """The IANA timezone of this host, from whatever the OS exposes locally."""
    for candidate in (os.environ.get("TZ", "").lstrip(":"),
                      _read_text("/etc/timezone").strip(),
                      _localtime_target(),
                      _read_text("/proc/self/environ").split("TZ=")[-1].split("\x00")[0]):
        if candidate and "/" in candidate:
            return candidate.strip()
    return ""


def _localtime_target() -> str:
    try:
        target = os.readlink("/etc/localtime")
    except OSError:
        return ""
    for marker in ("/zoneinfo/", "/share/zoneinfo/"):
        if marker in target:
            return target.split(marker, 1)[1]
    return ""


def country() -> str:
    """Best offline guess at the country, or ``UNKNOWN``."""
    override = os.environ.get("PYDECOMP_COUNTRY", "").strip()
    if override:
        return override
    name = zone().lower()
    if name in ZONE_COUNTRY:
        return ZONE_COUNTRY[name]
    if name:
        # africa/lagos_2, europe/isle_of_man → try the first component match
        head = name.split("/", 1)[0]
        for key, value in ZONE_COUNTRY.items():
            if key.split("/", 1)[0] == head and key.rsplit("/", 1)[-1] in name:
                return value
    import time
    for stamp in time.tzname:
        hit = TZ_COUNTRY.get(str(stamp).lower())
        if hit:
            return hit
    return "UNKNOWN"


def country_label() -> str:
    """``country()`` plus the raw clock name when the guess is unknown."""
    guess = country()
    if guess != "UNKNOWN":
        return guess
    import time
    stamp = "/".join(dict.fromkeys(str(name) for name in time.tzname if name))
    return f"UNKNOWN ({stamp})" if stamp else "UNKNOWN"


def network() -> str:
    """The network this host is on: interface names, or a user override.

    Reads ``/sys/class/net`` so it works on Linux, Android/Termux and in a
    container; on other platforms it falls back to the hostname.  It never
    opens a socket — the banner must work in an air-gapped lab.
    """
    override = os.environ.get("PYDECOMP_NETWORK", "").strip()
    if override:
        return override
    try:
        interfaces = sorted(os.listdir("/sys/class/net"))
    except OSError:
        interfaces = []
    virtual = ("lo", "dummy", "veth", "docker", "br-", "virbr", "ifb", "zt",
               "wg", "tunl", "sit", "ip6tnl")
    usable = [name for name in interfaces
              if not name.startswith(virtual)]
    priority = ("rmnet", "ccmni", "pdp", "wlan", "wl", "en", "eth", "usb", "tun", "tap")
    named = sorted(usable, key=lambda name: next(
        (index for index, prefix in enumerate(priority) if name.startswith(prefix)), 99))
    if named:
        return ", ".join(named[:3]).upper()
    node = platform.node() or ""
    return node.upper() if node else "LOCAL LINK"


def signature() -> str:
    """The single line stamped on every recovered file."""
    return os.environ.get("PYDECOMP_SIGNATURE", "").strip() or SIGNATURE


def author() -> str:
    return os.environ.get("PYDECOMP_AUTHOR", "").strip() or AUTHOR


def card() -> list[tuple[str, str]]:
    """The ``[•] field : [value]`` block shown under the banner."""
    from ..limits import __version__
    return [
        ("Owner", author()),
        ("Tool", TOOL),
        ("Status", STATUS),
        ("Version", __version__),
    ]
