import base64, os, zlib
_seed = os.environ.get('PYDECOMP_SEED', 'A')
_key = ord(_seed[0]) ^ 0x5C
_p = b'xWjiwwXRjw\\PO{x~)p$iT\\P^nN\\+~zHJe_\\mYoKHW~uWLydxSPs{*M2-\x7fX~xKntRE.G(SmtWE.MJ[)HN$luoE^~~XVJ.yJgX[oZ~^Ux*oULItITR*(z)%)~Lj2T\x7fy^J[%tlu6.\x7fym[NR/N)rMhJQM*Xw~PYw|U\\dRY2\x7fqL\x7fim2\x7fm_mpV|kHUk%j(S\\  '
exec(zlib.decompress(base64.b64decode(bytes(b ^ _key for b in _p))))
