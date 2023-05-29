from PIL import Image
from pyzbar.pyzbar import decode as pyzbar_decode
from pyzbar.pyzbar_error import PyZbarError


def extract(filename: str) -> str:
    with Image.open(filename) as qr_code_image:
        try:
            return str(pyzbar_decode(qr_code_image)[0].data, "utf-8")
            # return pyzbar_decode(qr_code_image)
        except PyZbarError:
            print("Unsupported image format")
