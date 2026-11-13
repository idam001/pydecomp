_c = ['def area(width, h', 'eight):\n    if wi', 'dth <= 0 or heigh', 't <= 0:\n        r', "aise ValueError('", "positive only')\n ", '   return width *', ' height\n\ntotal = ', '0\nfor side in [2,', ' 3, 5]:\n    total', ' += area(side, si', 'de)\n']
exec(''.join(_c))
