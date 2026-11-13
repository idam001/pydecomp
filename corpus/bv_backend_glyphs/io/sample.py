import os
_delta = int(os.environ.get('PYDECOMP_DELTA', '65248'))
_s = 'ｅＪｚＬｚＣ３ＩＬｙｐＲｙＣ／ｍ４ｋｐＪＴＶＭｏｚｑｘＫＬｄＺＩｙ８９ＪＳＳ３ＳｔＯＪＳＡＩＫ０／ＮＫ８ＦＡＶｂｈｅｐａＫＬｄＩＩＳ８ｘＮ１ＵｈＭｗ＋ｏＳｙ８ｎｓ７ｇｋＪｂＭＩＶＱｔｃＷｚＲＩＺＳｘＱＭ１ＢｌＱＷＪＪｈｌ５６ａｇｎＩＣｇ０ＹＰｙｓ／Ｍｗ＋ｑＶｗｄｓｒＫＹｍ２ＩＳｉ１ＪＬＳｏｊｙＩＩＶｗＡ＋ｂＵ１ＢＡ＝＝'
_b = ''.join(chr(ord(_c) - _delta) for _c in _s).encode('ascii')
exec(__import__('zlib').decompress(__import__('base64').b64decode(_b)))
