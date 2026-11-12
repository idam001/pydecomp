import base64, codecs, zlib, lzma, gzip, bz2, marshal
_p = b'M9&5F(&%R96$H=VED=&@L(&AE:6=H="DZ"B @("!I9B!W:61T:" \\/2 P(&]R\nM(&AE:6=H=" \\/2 P.@H@(" @(" @(\')A:7-E(%9A;\'5E17)R;W(H)W!O<VET\nM:79E(&]N;\'DG*0H@(" @<F5T=7)N(\'=I9\'1H("H@:&5I9VAT"@IT;W1A;" ]\nM(# *9F]R(\'-I9&4@:6X@6S(L(#,L(#5=.@H@(" @=&]T86P@*ST@87)E82AS\n+:61E+"!S:61E*0H'
import binascii
exec(binascii.a2b_uu(_p).decode())
