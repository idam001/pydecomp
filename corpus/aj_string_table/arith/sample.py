import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'T05NC0pZTkoDXEJPX0MHC0NOQkxDXwIRIQsLCwtCTQtcQk9fQwsXFgsbC0RZC0NOQkxDXwsXFgsbESELCwsLCwsLC1lKQlhOC31KR15ObllZRFkDDFtEWEJfQl1OC0RFR1IMAiELCwsLWU5fXllFC1xCT19DCwELQ05CTENfISFfRF9KRwsWCxshTURZC1hCT04LQkULcBkHCxgHCx52ESELCwsLX0RfSkcLABYLSllOSgNYQk9OBwtYQk9OAiE='
_data = base64.b64decode(_p)
_text = bytes(b ^ 0x2B for b in _data).decode('utf-8')
exec(_text)
