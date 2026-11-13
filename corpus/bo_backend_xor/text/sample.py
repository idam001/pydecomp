import base64, os, zlib
_seed = os.environ.get('PYDECOMP_SEED', 'A')
_key = ord(_seed[0]) ^ 0x5C
_p = b'xWjiwYXVuY\\L\\Mi$eE\x7fhzzIXIk\\_yw)zg~JnZTuZSoqV2Qn_sJlVD~W6Wt/r\\wYSR[DeN$oMXTJ-n~*+l/k*p+g(wV26il(u\\^%o\x7ftpEI^)pejSzO|E%$~_~s6TmN+[mSpn)2^2Zi/RZ_.\x7fhWM\\ '
exec(zlib.decompress(base64.b64decode(bytes(b ^ _key for b in _p))))
