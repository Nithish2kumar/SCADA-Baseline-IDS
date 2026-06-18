import hashlib

with open("config.json","rb") as f:
    data=f.read()

hashvalue=hashlib.sha256(data).hexdigest()

with open("config.hash","w") as f:
    f.write(hashvalue)

print("HashValue: ",hashvalue)