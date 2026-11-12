class Session:
    def __init__(self, host, port=443):
        self.host = host
        self.port = port

    def url(self):
        return f'https://{self.host}:{self.port}/'

default = Session('example.com')
