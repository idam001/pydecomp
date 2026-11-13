import base64
from functools import reduce
_C = [b'Y2xhc3MgU2Vzc2lvbjoK', b'ICAgIGRlZiBfX2luaXRf', b'XyhzZWxmLCBob3N0LCBw', b'b3J0PTQ0Myk6CiAgICAg', b'ICAgc2VsZi5ob3N0ID0g', b'aG9zdAogICAgICAgIHNl', b'bGYucG9ydCA9IHBvcnQK', b'CiAgICBkZWYgdXJsKHNl', b'bGYpOgogICAgICAgIHJl', b'dHVybiBmJ2h0dHBzOi8v', b'e3NlbGYuaG9zdH06e3Nl', b'bGYucG9ydH0vJwoKZGVm', b'YXVsdCA9IFNlc3Npb24o', b'J2V4YW1wbGUuY29tJykK']
_p = reduce(lambda a, b: a + b, _C)
exec(base64.b64decode(_p).decode())
