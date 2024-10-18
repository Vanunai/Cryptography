from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import base64

def AES_encrypt(plain: bytes, key: bytes) -> bytes:
    enc = AES.new(key, AES.MODE_ECB)
    return enc.encrypt(plain)

def AES_decrypt(cipher: bytes, key: bytes) -> bytes:
    dec = AES.new(key, AES.MODE_ECB)
    return dec.decrypt(cipher)

def cbc_encrypt(plain: bytes, key: bytes, iv: bytes) -> bytes:
    plaintxt = pad(plain, AES.block_size)
    blocks = [plaintxt[i*AES.block_size: (i+1)*AES.block_size] for i in range(len(plaintxt)//AES.block_size)] 
    cipher = [AES_encrypt(strxor(blocks[0],iv), key)]
    for i in range(1, len(blocks)):
        cipher.append(AES_encrypt(strxor(blocks[i], cipher[-1]), key))
    return b"".join(cipher)
        
def cbc_decrypt(cipher: bytes, key: bytes, iv: bytes):
    blocks = [cipher[i*AES.block_size: (i+1)*AES.block_size] for i in range(len(cipher)//AES.block_size)] 
    plain = []
    for i in range(len(blocks)-1,0,-1):
        plain.append(strxor(AES_decrypt(blocks[i], key),blocks[i-1]))
    plain.append(strxor(AES_decrypt(blocks[0], key), iv))
    return unpad(b"".join(reversed(plain)), AES.block_size)

if __name__ == "__main__":
    key = b"YELLOW SUBMARINE"
    iv = bytes([0x00]*16)
    cipher = base64.b64decode(open(r"F:\crypto\Experiment_2\t2_2.txt","r").read())
    plain = cbc_decrypt(cipher, key, iv)
    print(plain.decode())
    assert cbc_encrypt(plain, key, iv) == cipher