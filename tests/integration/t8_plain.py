import os
KEY = "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
def go(uid):
    for pw in ("123456", "12345678"):
        print(uid, pw)
    os.system("xdg-open https://t.me/example")
