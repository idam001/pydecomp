import re

IP = re.compile(r'\b\d{1,3}(\.\d{1,3}){3}\b')

def hosts(blob):
    return sorted(set(IP.findall(blob)))
