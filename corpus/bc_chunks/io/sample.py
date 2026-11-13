_c = ['import os\n\ndef si', 'zes(folder):\n    ', 'found = {}\n    fo', 'r name in os.list', 'dir(folder):\n    ', '    found[name] =', ' os.path.getsize(', 'os.path.join(fold', 'er, name))\n    re', 'turn found\n']
exec(''.join(_c))
