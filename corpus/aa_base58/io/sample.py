import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'MyLWLSB6iqVuNKSGfy5fJnHFPGnS8qkxViZ5T35sCxw7NXzmwXkVHzq9MQN3tQsndhbbuUa8HQqLkbM61wfQ3EP2urqhbfpBWg6Te6LKZnnT7QVoRhVmXvyzSx1N9TPhvDLm2Uw4aFzJFBoMM6kHmSZSeBJWZ7Bdjq5sR5RQwiLX3xQK4zZt5F3fbcGowNHFru2kWmLUnMfn9N5qZ4P3zucWN9SiShDT'
_A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_n = 0
for _c in _p.decode():
    _n = _n * len(_A) + _A.index(_c)
exec(_n.to_bytes((_n.bit_length() + 7) // 8, 'big').decode())
