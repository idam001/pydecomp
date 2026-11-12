import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'x(d*cA=-BxA%-m+wO96ax)Kuic$WylwmY^giTM#LarUomB-7.jjS]913lQDlazbLjaz$R8wGUY8aA8rNy?W%jwnc6jw]zG@wPxjX3lQDlarR^HazbLmzE=%?vqPNYauZ&=B1RAuBz9ptwPS0cDsXHyB1RAuBz9pwz!T8qw]zG@wPxsAzEEx[djCPDarR!EwPS6nzxJLfB-7Z%'
_A = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'
_o = bytearray()
for _i in range(0, len(_p), 5):
    _v = 0
    for _c in _p[_i:_i + 5]:
        _v = _v * 85 + _A.index(chr(_c))
    _o.extend(_v.to_bytes(4, 'big'))
exec(bytes(_o).rstrip(b'\x00').decode())
