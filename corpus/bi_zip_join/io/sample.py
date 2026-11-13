import base64
_x = b'a1bJI9CpZYclZMZ9ZVKoIAIZd5I0e0IAIZcBY1IlI9LxcRaIZ9ZVKoIAIAIBbVZtY1XAI9LBdgZVclZhc5YRLpa4Z9ZVLBY1KkIAIJdVbBbVZo'
_y = b'Ww30GzgkWg26XomsGyTKCgGvWkDg3KCgGviuWlGuGzmp3kXomsGyTKCgCgCm3uFuWlS9GznhGu2026SvywXomvWomsGyCuWlSKCgHlHyim3uA='
_p = b''.join(bytes([a, b]) for a, b in zip(_x, _y + b'\x00'))
exec(base64.b64decode(_p.rstrip(b'\x00')).decode())
