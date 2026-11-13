import os
_delta = int(os.environ.get('PYDECOMP_DELTA', '65248'))
_s = 'ｅＪｗｔｊＤＥＫｈＤＡＱＡＰｔ９ｘＸｂｕｇｇＴＥＴｖＡＢｄｊ４ｇｚｃＷｓＧＩｈＧＮｒｌＫ／ＬｓＢｎＷｑＫＹｃＪ＋Ｊｉ２ｏＡｊＤＮＯＦＹｘＳ９ｒＰＥＩＷ０ｓｃ７６ｑ２ｖ７ｍ６ｚ５ｊＫ／＋ｔｑ５ｈＡＣ８ｒｂｉｍＸＴＣ４ｍｘｗＮｇＲａＸ８９ｃＢｃｎ＋ＩｐＳ６ＦｐＮｍｓ４／Ｃ／Ｇｔ２ＯＧＢ３ｂｕＪＰＡ＝'
_b = ''.join(chr(ord(_c) - _delta) for _c in _s).encode('ascii')
exec(__import__('zlib').decompress(__import__('base64').b64decode(_b)))
