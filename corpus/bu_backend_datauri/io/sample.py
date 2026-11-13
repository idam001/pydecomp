import os
_one = int(os.environ.get('PYDECOMP_ONE', '1'))
_u = 'data:application/octet-stream;base64,eJzLzC3ILypRyC/m4kpJTVMozqxKLdZIy89JSS3StOJSAIK0/NK8FAVbhepaKLdIIS8xN1UhMw+oSy8ns7gkJbMIVQtcWzRIZSxQM1BlQWJJhl56agnICg0YPys/Mw+qVwdsrKYm2ISi1JLSojyIIVwA+bU1BA=='
_body = _u.split(',', 1)[_one]
exec(__import__('zlib').decompress(__import__('base64').b64decode(_body)))
