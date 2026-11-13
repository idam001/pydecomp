import os
_columns = int(os.environ.get('PYDECOMP_COLUMNS', '7'))
_s = b'eI/VLJJNhIUyJcxWaY+K1IUJLmMdSSKeIh8bWQJgPqYJI1zy4oZSA8pSMnMzMJnyVmLVBLpkzI3IFa8wsIR1hIsw2SwAzRpqySKAKx+7VIBlC/dIoA=CyJx8t0VLNogQZl5gMsSj+=3CTK9O/bd1SktSQ60wriyb'
_rows = -(-len(_s) // _columns)
_short = _rows * _columns - len(_s)
_out = bytearray(len(_s))
_at = 0
for _c in range(_columns):
    _length = _rows - (1 if _c >= _columns - _short else 0)
    for _r in range(_length):
        _out[_r * _columns + _c] = _s[_at]
        _at += 1
exec(__import__('zlib').decompress(__import__('base64').b64decode(bytes(_out))))
