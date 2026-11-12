import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'wmYu}vrb{/d0GxoBz9iFxK$)<xMLW:3lQDlazCBgCwgPfxDPA2ats{RAV/4bx>Ia3auR!ffGGK-arR^HarR!Evqf^]axz]!B.a0ZA=k$DcVB0Bx([6jwGU]ey<vxS3lQDlaAz4nB-IvxCwgPfxDO=ExK$)<xMKN*Bz(nfy->>-fBzAgAV/BqwmV($zxJdsefD-1at)B=3lQDlaARKzvqE5pjS[fNwNN0dx>g^aaAImcwHN@^'
_A = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'
_o = bytearray()
for _i in range(0, len(_p), 5):
    _v = 0
    for _c in _p[_i:_i + 5]:
        _v = _v * 85 + _A.index(chr(_c))
    _o.extend(_v.to_bytes(4, 'big'))
exec(bytes(_o).rstrip(b'\x00').decode())
