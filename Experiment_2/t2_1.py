from Crypto.Cipher.AES import *
from Crypto.Util.Padding import pad


def PKCS_7(msg: bytes, BLOCKSIZE=16) -> bytes:
    return msg + bytes([BLOCKSIZE-(len(msg)%BLOCKSIZE)])*(BLOCKSIZE-(len(msg)%BLOCKSIZE))

if __name__ == "__main__":
    s = b"YELLOW SUBMARINE"
    print(PKCS_7(s, 20))
    print(pad(s,20))
    assert PKCS_7(s, 20) == pad(s,20)