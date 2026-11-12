_t = [b'def area(width, height):', b'\n    if width <= 0 or he', b'ight <= 0:\n        raise', b" ValueError('positive on", b"ly')\n    return width * ", b'height\n\ntotal = 0\nfor si', b'de in [2, 3, 5]:\n    tot', b'al += area(side, side)\n']
exec(b''.join(_t).decode())
