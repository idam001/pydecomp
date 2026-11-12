def area(width, height):
    if width <= 0 or height <= 0:
        raise ValueError('positive only')
    return width * height

total = 0
for side in [2, 3, 5]:
    total += area(side, side)
