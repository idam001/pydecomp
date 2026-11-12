_t = [b'class Session:\n    def _', b'_init__(self, host, port', b'=443):\n        self.host', b' = host\n        self.por', b't = port\n\n    def url(se', b"lf):\n        return f'ht", b'tps://{self.host}:{self.', b"port}/'\n\ndefault = Sessi", b"on('example.com')\n"]
exec(b''.join(_t).decode())
