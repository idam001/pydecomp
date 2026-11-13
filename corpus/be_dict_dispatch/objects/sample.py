import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'Y2xhc3MgU2Vzc2lvbjoKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBob3N0LCBwb3J0PTQ0Myk6CiAgICAgICAgc2VsZi5ob3N0ID0gaG9zdAogICAgICAgIHNlbGYucG9ydCA9IHBvcnQKCiAgICBkZWYgdXJsKHNlbGYpOgogICAgICAgIHJldHVybiBmJ2h0dHBzOi8ve3NlbGYuaG9zdH06e3NlbGYucG9ydH0vJwoKZGVmYXVsdCA9IFNlc3Npb24oJ2V4YW1wbGUuY29tJykK'
_T = {0: lambda: base64.b64decode(_p)}
_S = 0
_v = None
while _S in _T:
    _v = _T[_S]()
    _S += 1
exec(_v.decode())
