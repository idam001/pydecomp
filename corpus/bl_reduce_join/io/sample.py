import base64
from functools import reduce
_C = [b'aW1wb3J0IG9zCgpkZWYg', b'c2l6ZXMoZm9sZGVyKToK', b'ICAgIGZvdW5kID0ge30K', b'ICAgIGZvciBuYW1lIGlu', b'IG9zLmxpc3RkaXIoZm9s', b'ZGVyKToKICAgICAgICBm', b'b3VuZFtuYW1lXSA9IG9z', b'LnBhdGguZ2V0c2l6ZShv', b'cy5wYXRoLmpvaW4oZm9s', b'ZGVyLCBuYW1lKSkKICAg', b'IHJldHVybiBmb3VuZAo=']
_p = reduce(lambda a, b: a + b, _C)
exec(base64.b64decode(_p).decode())
