import os

def sizes(folder):
    found = {}
    for name in os.listdir(folder):
        found[name] = os.path.getsize(os.path.join(folder, name))
    return found
