"""Payload used to test carve-outs from compiled images."""
import json

LIMIT = 3
MARKER = "RECOVER_ME_7731"


class Headers:
    def __init__(self, host):
        self.host = host

    def as_dict(self):
        return {"Host": self.host}


def parse_payload(blob):
    data = json.loads(blob)
    return data.get("items", [])[:LIMIT]


def main(blob):
    return parse_payload(blob)
