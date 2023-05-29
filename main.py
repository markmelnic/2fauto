import pyotp
from base64 import b32encode

from decoder import decode
from extractor import extract

if __name__ == "__main__":
    data = extract("test.jpg")
    items = decode(data)

    totp = pyotp.TOTP(
        b32encode(items[0].secret),
        issuer=items[0].issuer,
        name=items[0].name,
    )
    print(totp.now())
