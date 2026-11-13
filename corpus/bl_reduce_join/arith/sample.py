import base64
from functools import reduce
_C = [b'ZGVmIGFyZWEod2lkdGgs', b'IGhlaWdodCk6CiAgICBp', b'ZiB3aWR0aCA8PSAwIG9y', b'IGhlaWdodCA8PSAwOgog', b'ICAgICAgIHJhaXNlIFZh', b'bHVlRXJyb3IoJ3Bvc2l0', b'aXZlIG9ubHknKQogICAg', b'cmV0dXJuIHdpZHRoICog', b'aGVpZ2h0Cgp0b3RhbCA9', b'IDAKZm9yIHNpZGUgaW4g', b'WzIsIDMsIDVdOgogICAg', b'dG90YWwgKz0gYXJlYShz', b'aWRlLCBzaWRlKQo=']
_p = reduce(lambda a, b: a + b, _C)
exec(base64.b64decode(_p).decode())
