import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'aW1wb3J0IHJlCgpJUCA9IHJlLmNvbXBpbGUocidcYlxkezEsM30oXC5cZHsxLDN9KXszfVxiJykKCmRlZiBob3N0cyhibG9iKToKICAgIHJldHVybiBzb3J0ZWQoc2V0KElQLmZpbmRhbGwoYmxvYikpKQo='
_code = compile(base64.b64decode(_p), '<payload>', 'exec')
