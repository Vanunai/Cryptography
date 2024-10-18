import random
from Crypto.Util.number import getRandomInteger, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import base64
#from functions import cbc_encrypt, cbc_decrypt


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

def cbc_decrypt(cipher: bytes, key: bytes, iv: bytes) -> bytes:
    blocks = [cipher[i*AES.block_size: (i+1)*AES.block_size] for i in range(len(cipher)//AES.block_size)] 
    plain = []
    for i in range(len(blocks)-1,0,-1):
        plain.append(strxor(AES_decrypt(blocks[i], key),blocks[i-1]))
    plain.append(strxor(AES_decrypt(blocks[0], key), iv))
    return unpad(b"".join(reversed(plain)), AES.block_size)

key = bytes([random.randint(0,2**8-1) for _ in range(16)])
iv = bytes([random.randint(0,2**8-1) for _ in range(16)])
predata = b"comment1=cooking%20MCs;userdata="
suffixdata = b";comment2=%20like%20a%20pound%20of%20bacon"
goal_msg = b";admin=true;"  
def account_encrypt(data=b""):
    if goal_msg in data:
        raise ValueError
    plaintxt = pad(predata + data + suffixdata, AES.block_size)
    return cbc_encrypt(plaintxt, key, iv)

def check_admin(cipher: bytes):
    plain = cbc_decrypt(cipher, key, iv)
    print(plain)
    return goal_msg in plain

if __name__ == "__main__":
    pre_len = len(predata)             
    suf_len = len(suffixdata)
    blocksize = AES.block_size
    attack_msg = b";admin=truE;".ljust(blocksize, b' ')
    cipher = account_encrypt(attack_msg)
    tmp = cipher[blocksize:2*blocksize]
    after_enc = strxor(tmp, attack_msg) 
    replace_cipher = strxor(after_enc, goal_msg.ljust(blocksize, b' '))
    check_admin(cipher[:blocksize]+replace_cipher+cipher[2*blocksize:])
    