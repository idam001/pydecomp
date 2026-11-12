import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'S6/4/x77HBli+xzV0Xl6fmAb/Z95HuV7+Px6eh7hh9FhM7GHz+GPJzZottlpG4R7EhwCBGYSADybeBwUgIsXFoA7ZjhvaAd7Vh9jAGNWclF6tW1JWTr7OT4rDBgMADyZZDRfn5UV67eR56HhkQ+7Em8zyoYGNw=='
exec(zlib.decompress(bytes(b ^ 0x33 for b in base64.b64decode(_p))))
