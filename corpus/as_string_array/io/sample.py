_t = [b'import os\n\ndef sizes(fol', b'der):\n    found = {}\n   ', b' for name in os.listdir(', b'folder):\n        found[n', b'ame] = os.path.getsize(o', b's.path.join(folder, name', b'))\n    return found\n']
exec(b''.join(_t).decode())
