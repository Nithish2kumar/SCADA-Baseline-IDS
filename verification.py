import hashlib

def verify():
    with open("config.json","rb") as f:
        data=f.read()

    hashVal=hashlib.sha256(data).hexdigest()

    with open("config.hash", "r") as f:
        storedhash=f.read().strip()

        if hashVal==storedhash:
            print("true")
        else:
            print("false")

    return hashVal==storedhash
