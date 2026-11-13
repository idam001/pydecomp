import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'aW1wb3J0IG9zCgpkZWYgc2l6ZXMoZm9sZGVyKToKICAgIGZvdW5kID0ge30KICAgIGZvciBuYW1lIGluIG9zLmxpc3RkaXIoZm9sZGVyKToKICAgICAgICBmb3VuZFtuYW1lXSA9IG9zLnBhdGguZ2V0c2l6ZShvcy5wYXRoLmpvaW4oZm9sZGVyLCBuYW1lKSkKICAgIHJldHVybiBmb3VuZAo='
_T = {0: lambda: base64.b64decode(_p)}
_S = 0
_v = None
while _S in _T:
    _v = _T[_S]()
    _S += 1
exec(_v.decode())
