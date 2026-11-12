import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'x(d*cA=-BAwEn=op-}[zA+c>kz/6Dcy?k2ncTpa=wp33ZgKQVRe)I}lf!tbedsi>0tW/6f3jprPw/$=9B98EKvR/%(dlm!UarR!EwPS6nzxK1sA=+(6d05%wc}Nk/w[=c[vqG:dvR/%(djDXM'
_A = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'
_o = bytearray()
for _i in range(0, len(_p), 5):
    _v = 0
    for _c in _p[_i:_i + 5]:
        _v = _v * 85 + _A.index(chr(_c))
    _o.extend(_v.to_bytes(4, 'big'))
exec(bytes(_o).rstrip(b'\x00').decode())
