import base64
from functools import reduce
_C = [b'aW1wb3J0IHJlCgpJUCA9', b'IHJlLmNvbXBpbGUocidc', b'YlxkezEsM30oXC5cZHsx', b'LDN9KXszfVxiJykKCmRl', b'ZiBob3N0cyhibG9iKToK', b'ICAgIHJldHVybiBzb3J0', b'ZWQoc2V0KElQLmZpbmRh', b'bGwoYmxvYikpKQo=']
_p = reduce(lambda a, b: a + b, _C)
exec(base64.b64decode(_p).decode())
