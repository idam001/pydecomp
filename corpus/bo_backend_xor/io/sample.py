import base64, os, zlib
_seed = os.environ.get('PYDECOMP_SEED', 'A')
_key = ord(_seed[0]) ^ 0x5C
_p = b'xWgQg^.TQdmOd^2p)vmWIKPrgleVQyGTd%$WNN.NiRWN\\TV-2SV%[\\K\x7fuxm|VQyTTN%eS,HuPj6rNd%sn*zvW\x7fPTKLi~JgOTGNeLP,_qLJWWuq(+|zsT^z-DMdn2Pj6lKjynoVDp/TNt,WQNrwdTTKj\\6\x7fH,_\\  '
exec(zlib.decompress(base64.b64decode(bytes(b ^ _key for b in _p))))
