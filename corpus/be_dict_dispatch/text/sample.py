import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'aW1wb3J0IHJlCgpJUCA9IHJlLmNvbXBpbGUocidcYlxkezEsM30oXC5cZHsxLDN9KXszfVxiJykKCmRlZiBob3N0cyhibG9iKToKICAgIHJldHVybiBzb3J0ZWQoc2V0KElQLmZpbmRhbGwoYmxvYikpKQo='
_T = {0: lambda: base64.b64decode(_p)}
_S = 0
_v = None
while _S in _T:
    _v = _T[_S]()
    _S += 1
exec(_v.decode())
