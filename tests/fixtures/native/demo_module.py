"""Demo extension module for the native-recovery tests."""
import json

DEFAULT_HOST = "example.invalid"
TRACE_HEADER = "X-Trace"

def build_headers(host, token, verbose=False):
    """Build the request header set."""
    headers = {"Host": host, "Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if verbose:
        headers[TRACE_HEADER] = "on"
    return headers

def parse_payload(blob):
    """Parse a JSON payload, returning an empty dict on failure."""
    try:
        return json.loads(blob)
    except ValueError:
        return {}

def summarise(rows):
    total = 0
    seen = 0
    for row in rows:
        value = row.get("value", 0)
        if value < 0:
            value = -value
        total += value
        seen += 1
    return {"count": seen, "total": total}

class Session:
    def __init__(self):
        self.items = []

    def describe(self):
        """Return a human readable summary."""
        return "%d item(s)" % len(self.items)

    def push(self, item):
        self.items.append(item)
        return self.describe()

def main(argv=None):
    argv = argv or []
    host = DEFAULT_HOST
    headers = build_headers(host, "t0ken", verbose=True)
    payload = parse_payload('{"value": 2}')
    session = Session()
    session.push(payload)
    return {
        "headers": headers,
        "summary": summarise([payload, payload]),
        "session": session.describe(),
        "argv": list(argv),
    }
