_c = ['class Session:\n  ', '  def __init__(se', 'lf, host, port=44', '3):\n        self.', 'host = host\n     ', '   self.port = po', 'rt\n\n    def url(s', 'elf):\n        ret', "urn f'https://{se", 'lf.host}:{self.po', "rt}/'\n\ndefault = ", "Session('example.", "com')\n"]
exec(''.join(_c))
