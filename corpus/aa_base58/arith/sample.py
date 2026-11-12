import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'CuyKjKqDykTdBv1hBVyPHwJy6HewMqEbkCDyrjiPss9R9YML6eBrZCpAsYCiK4GtH8PdhqvjXcN5ZFmVm1fPEkB4FGwxxy7tXru5aLU7fYCQNf9siNXRvJjbSF5gqsjnYMBTUmhayhXq9tQP8eP2BeVj4aKVE3Z2VXMNgXo6qC6zP9ytGHKrwJ94Z8SxVgc7VaqwmFN74645G9iRKGuWHgHwxYC9T2d7DAao66sXQPgABs2GpEQDCsAoBw2sZP88WT7Pw'
_A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_n = 0
for _c in _p.decode():
    _n = _n * len(_A) + _A.index(_c)
exec(_n.to_bytes((_n.bit_length() + 7) // 8, 'big').decode())
