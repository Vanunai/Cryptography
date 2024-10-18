import random
from Crypto.Util.number import getRandomInteger, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import string
import base64

def AES_encrypt(plain: bytes, key: bytes) -> bytes:
    enc = AES.new(key, AES.MODE_ECB)
    return enc.encrypt(plain)

def ecb_encrypt(plain: bytes, key: bytes) -> bytes:
    plaintxt = pad(plain, AES.block_size)
    blocks = [plaintxt[i*AES.block_size: (i+1)*AES.block_size] for i in range(len(plaintxt)//AES.block_size)] 
    cipher = b""
    for i in range(len(blocks)):
        cipher += AES_encrypt(blocks[i], key)
    return cipher

def cbc_encrypt(plain: bytes, key: bytes, iv: bytes) -> bytes:
    plaintxt = pad(plain, AES.block_size)
    blocks = [plaintxt[i*AES.block_size: (i+1)*AES.block_size] for i in range(len(plaintxt)//AES.block_size)] 
    cipher = [AES_encrypt(strxor(blocks[0],iv), key)]
    for i in range(1, len(blocks)):
        cipher.append(AES_encrypt(strxor(blocks[i], cipher[-1]), key))
    return b"".join(cipher)

def encryption_oracle(plaintext, key, iv=b""):
    flag = 0
    if flag:
        encrypted = cbc_encrypt(plaintext, key, iv)
        return (encrypted, "CBC")
    else:
        encrypted = ecb_encrypt(plaintext, key)
        return (encrypted, "ECB")

if __name__ == "__main__":
    key = long_to_bytes((128)).ljust(16)
    plain = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
    plain = base64.b64decode(plain)
    my_string, cnt = "A", 1
    base_cipher = encryption_oracle(plain, key)[0]
    
    while True:
        cnt += 1
        my_string += "A"
        encrypted, answer = encryption_oracle(my_string.encode()+plain, key)
        blocksize = cnt//2
        if encrypted[:blocksize] == encrypted[blocksize:2*blocksize]:
            print(f"Block length: {blocksize}")
            break
    cnt = 0
    ans = b"A"*(blocksize-1)
    while True:
        if len(ans)-blocksize+1 >= len(base_cipher):
            break
        prefix = ans[cnt: cnt+blocksize-1]
        encrypted, _ = encryption_oracle(b"A"*(blocksize-1-(cnt%blocksize))+plain, key)
        index = cnt//blocksize
        cipher = encrypted[index*blocksize:(index+1)*blocksize]
        try:
            for c in string.printable:
                if encryption_oracle(prefix+c.encode(), key)[0][:blocksize] == cipher:
                    ans_c = c
                    break
            ans += ans_c.encode()
            cnt += 1
        except:
            break
    print(ans[blocksize-1:])