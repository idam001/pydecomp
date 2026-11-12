import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'E7RhDbc5TNm54oWYo8EVKJK4JPzRG7HBMP9l7eYoziNEmSqXmb5PKpLcbvMSr670V5tBUsg4LwR0xdiilhVkSZ5xocVdkkVWSy0YVZxXQnf0dDNbZhwwBOirENvcNhw0pB5QdZFeo2bRV48T7ElHFJYzBana'
_A = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
_n = 0
for _c in _p.decode():
    _n = _n * len(_A) + _A.index(_c)
exec(_n.to_bytes((_n.bit_length() + 7) // 8, 'big').decode())
