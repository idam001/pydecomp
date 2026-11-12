import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'YEDS9E5LEQ44 YCND1$5AXW7ZKE+%5+3EM9ETVD455-/4PJCSVCX96-M6R45X%5SVCX96-M6:A5-M6PUBZ.45C16VC:+C59D QE5PE-JCT3EO95RC1Y24Q447$C6%EM-DVQE5LE  C5557$C84566AR.C0/DAECDUD-JCT3E795L85'
_A = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'
_n = 0
for _c in _p.decode():
    _n = _n * len(_A) + _A.index(_c)
exec(_n.to_bytes((_n.bit_length() + 7) // 8, 'big').decode())
