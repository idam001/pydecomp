_t = [b'import re\n\nIP = re.compi', b"le(r'\\b\\d{1,3}(\\.\\d{1,3}", b"){3}\\b')\n\ndef hosts(blob", b'):\n    return sorted(set', b'(IP.findall(blob)))\n']
exec(b''.join(_t).decode())
