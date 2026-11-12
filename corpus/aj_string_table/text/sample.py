import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'QkZbRFlfC1lOISFiewsWC1lOBUhERltCR04DWQx3SXdPUBoHGFYDdwV3T1AaBxhWAlAYVndJDAIhIU9OTQtDRFhfWANJR0RJAhEhCwsLC1lOX15ZRQtYRFlfTk8DWE5fA2J7BU1CRU9KR0cDSUdESQICAiE='
_data = base64.b64decode(_p)
_text = bytes(b ^ 0x2B for b in _data).decode('utf-8')
exec(_text)
