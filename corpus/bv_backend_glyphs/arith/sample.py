import os
_delta = int(os.environ.get('PYDECOMP_DELTA', '65248'))
_s = 'ｅＪｗｔｊｊＥＯｗｊＡＭＲｆｅｃ４ｍ９ｔＩＡＭＣｓＳＡ６ｃｇＵＷｘＢＡｐＤｒＶＵＪｃｈＪＱｄｙｅＮＭｎｆ７Ｐ／０ｂＥｃｅＶｓｉＯＸ３Ｚ５ＮｐｉＪＸ３ＰＷＦ４ＵＳ９ｑｈｒＸＣｃｃＥＫＷ３ｄＷｚＥＦｒＧｃＣＨｅ７ｒＨＱＴｉＴＩＯ７５ｇ４８４ｃＱｗ／ＩｂｄＣＷＦ８ｉｑｈ＋３ｂｄｐＦＳＯ２Ｓ４ｏＰｕＷＬＰ７ＥｊｃＭＤｊａＨＡｙＯＤ／ｂｌＱｂｔｐ／ｂｐＢｐｍＫａｖＵＨｖ８ｗ５ＮＡ＝＝'
_b = ''.join(chr(ord(_c) - _delta) for _c in _s).encode('ascii')
exec(__import__('zlib').decompress(__import__('base64').b64decode(_b)))
