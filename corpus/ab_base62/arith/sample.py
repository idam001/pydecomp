import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'5BgP4y7SJEO3hvfskarIuE3KSprCpkrMYT19JqIPM5Ye7dR7D8v0ZkdMuJTzBUmMZJMrgCe1KS1HaraRykYbDnsBs6jqB7bsW5G7kMIvQzbDQ2bczS1XG3frrG5F59fbLIt4RYDTYkGe5cPwXfBzTeaURLMQ9opPgdq9OvG8lJmwSV0f2QkflgbixlOThHJnrC6qKLR2nDs7M6NQBm2IpHISXtjnswEWL6BTE6F89h2EuFrC3gux21Zuoqpw8WvXe'
_A = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
_n = 0
for _c in _p.decode():
    _n = _n * len(_A) + _A.index(_c)
exec(_n.to_bytes((_n.bit_length() + 7) // 8, 'big').decode())
