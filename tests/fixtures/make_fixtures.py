import base64, bz2, gzip, lzma, zlib, pathlib

OUT = pathlib.Path(__file__).parent
PAYLOAD = '''import os
KEY = "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
def go(uid):
    for pw in ("123456", "12345678"):
        print(uid, pw)
    os.system("xdg-open https://t.me/example")
'''

def w(name, text):
    (OUT / name).write_text(text)
    print("wrote", name, len(text))

b = PAYLOAD.encode()
b64 = base64.b64encode(zlib.compress(b)).decode()

# 1. classic
w("t1_b64_zlib.py", 'import base64,zlib\nexec(zlib.decompress(base64.b64decode("%s")))\n' % b64)
# 2. reversed + lambda loader
rev = base64.b64encode(b64.encode()[::-1]).decode()  # nonsense, use simple reverse instead
revblob = b64[::-1]
w("t2_lambda_reverse.py",
  '_ = lambda __ : __import__("zlib").decompress(__import__("base64").b64decode(__[::-1]))\n'
  'exec((_)(b\'%s\'))\n' % revblob)
# 3. bz2 + aliased imports
w("t3_bz2_alias.py",
  "from bz2 import decompress as dz\nfrom base64 import b32decode as d32\n"
  "p = d32('%s')\n" % base64.b32encode(bz2.compress(b)).decode() +
  "exec(dz(p))\n")
# 4. lzma + compile
w("t4_lzma_compile.py",
  "import lzma, base64, builtins\nbuiltins.compile(lzma.decompress(base64.b16decode('%s')).decode(), '<s>', 'exec')\n"
  % base64.b16encode(lzma.compress(b)).decode())
# 5. nested 3 layers
inner = 'import base64,zlib\nexec(zlib.decompress(base64.b64decode("%s")))\n' % b64
l2 = base64.b64encode(zlib.compress(inner.encode())).decode()
l3 = base64.b64encode(zlib.compress(('import base64,zlib\nexec(zlib.decompress(base64.b64decode("%s")))\n' % l2).encode())).decode()
w("t5_nested3.py", 'import base64,zlib\nexec(zlib.decompress(base64.b64decode("%s")))\n' % l3)
# 6. hex + join + rot13
w("t6_hex_join.py",
  "import binascii\ncode = ''.join(['%s','%s'])\nexec(bytearray.fromhex(code).decode())\n"
  % (b.hex()[:20], b.hex()[20:]))
# 7. gzip + reversed whole source
_rev = base64.b64encode(gzip.compress(b)).decode()[::-1]
w("t7_gzip_rev.py",
  "import gzip,base64\nexec(gzip.decompress(base64.b64decode('%s'[::-1])))\n" % _rev)
# 8. plain source, no layers
w("t8_plain.py", PAYLOAD)
# 9. marshal loader (should stop cleanly, not run)
import marshal
w("t9_marshal.py",
  "import base64,marshal\nexec(marshal.loads(base64.b64decode('%s')))\n"
  % base64.b64encode(marshal.dumps(compile(PAYLOAD, '<s>', 'exec'))).decode())

# 10. codecs rot13 + split concatenation + replace
import codecs
rot = codecs.encode(PAYLOAD, "rot13")
half = len(rot)//2
w("t10_rot13_concat.py",
  "import codecs\n"
  'a = %r\n' % rot[:half] +
  'b = %r\n' % rot[half:] +
  "src = (a + b).replace('@@@','')\n"
  "exec(codecs.decode(src, 'rot13'))\n")
