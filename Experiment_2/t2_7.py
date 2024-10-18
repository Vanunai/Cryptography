import random
from Crypto.Util.number import getRandomInteger, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import base64

def PKCS_7_pad(s, blocksize = AES.block_size):
    padding_len = blocksize - len(s)%blocksize
    return s + bytes([padding_len]) * padding_len

def PKCS_7_unpad(s, blocksize = AES.block_size):
    padding_len = s[-1]
    try:
        assert s[-padding_len:] == bytes([padding_len]) * padding_len
        return s[:-padding_len]
    except:
        raise ValueError("PKCS#7 padding is incorrect.")


if __name__ == "__main__":
    s1 = b"ICE ICE BABY\x04\x04\x04\x04"
    s2 = b"ICE ICE BABY\x05\x05\x05\x05"
    s3 = b"ICE ICE BABY\x01\x02\x03\x04"
    print(PKCS_7_unpad(s1))
    try:
        print(PKCS_7_unpad(s2))
    except:
        print("PKCS#7 padding is incorrect.")
    try:
        print(PKCS_7_unpad(s3))
    except:
        print("PKCS#7 padding is incorrect.")