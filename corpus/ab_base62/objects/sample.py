import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'jSAv7flfOYh9wBeTja6MOEq9EJPiofi7GbTuDHTAFpc7V6kctkS99nU5N7usJd1ZrotUZsEeStqkEPOSIuxwhqab3w6y4Tfgylv2ErvHBOvtI00fymnhy6bg1jTvopKfUVqVfumwcqtRiQyImmFu9mTowF4o1uQqyodtc3NtLt7qb9vFt3JQ99KCzm4JOCNpNRuQBHc8tSCNKvXRD4UtSlzv4WTjklbDdL7OfgvbPy0yr6TUMfJ2aCJQDIPevW4QLkiloGWIb3rSN290DV8yoYoP5W'
_A = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
_n = 0
for _c in _p.decode():
    _n = _n * len(_A) + _A.index(_c)
exec(_n.to_bytes((_n.bit_length() + 7) // 8, 'big').decode())
