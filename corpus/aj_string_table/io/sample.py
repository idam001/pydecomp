import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'QkZbRFlfC0RYISFPTk0LWEJRTlgDTURHT05ZAhEhCwsLC01EXkVPCxYLUFYhCwsLC01EWQtFSkZOC0JFC0RYBUdCWF9PQlkDTURHT05ZAhEhCwsLCwsLCwtNRF5FT3BFSkZOdgsWC0RYBVtKX0MFTE5fWEJRTgNEWAVbSl9DBUFEQkUDTURHT05ZBwtFSkZOAgIhCwsLC1lOX15ZRQtNRF5FTyE='
_data = base64.b64decode(_p)
_text = bytes(b ^ 0x2B for b in _data).decode('utf-8')
exec(_text)
