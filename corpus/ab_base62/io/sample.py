import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'1jiVx7vxVXYPmLIdaTCPZESC4dne0QDiFrGTbDFXNHjBCTgI5mu70zx3GzvBxxomJ6XpTFaOktY1cLxuGdiRhgG8HsviRvh8CRwGKMef3qUlDtcYKMnhcAY6YgvaB8p5ijA84ToqMynBxlsYqBjonPZhQu8wj51XAcNIjMVtpN4h6IEmExnZBk0P7Npv6ojF0FgSKaqYzNzCyFhEUn0QSUq2x30e2'
_A = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
_n = 0
for _c in _p.decode():
    _n = _n * len(_A) + _A.index(_c)
exec(_n.to_bytes((_n.bit_length() + 7) // 8, 'big').decode())
