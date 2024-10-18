import random
from Crypto.Util.number import getRandomInteger, long_to_bytes
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

def ecb_encrypt(plain: bytes, key: bytes) -> bytes:
    plaintxt = pad(plain, AES.block_size)
    blocks = [plaintxt[i*AES.block_size: (i+1)*AES.block_size] for i in range(len(plaintxt)//AES.block_size)] 
    cipher = b""
    for i in range(len(blocks)):
        cipher += AES_encrypt(blocks[i], key)
    return cipher
    
def ecb_decrypt(cipher: bytes, key: bytes) -> bytes:
    blocks = [cipher[i*AES.block_size: (i+1)*AES.block_size] for i in range(len(cipher)//AES.block_size)] 
    plain = b""
    for i in range(len(blocks)):
        plain += AES_decrypt(blocks[i], key)
    return unpad(plain)

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

def encryption_oracle(input_):
    key = long_to_bytes(getRandomInteger(128)).ljust(16)
    iv = long_to_bytes(getRandomInteger(128)).ljust(16)
    prefix = long_to_bytes(getRandomInteger(random.randint(5, 10)*8))
    suffix = long_to_bytes(getRandomInteger(random.randint(5, 10)*8))
    plaintext = prefix + input_ + suffix
    flag = random.randint(0,1)
    if flag:
        encrypted = cbc_encrypt(plaintext, key, iv)
        return (encrypted, "CBC")
    else:
        encrypted = ecb_encrypt(plaintext, key)
        return (encrypted, "ECB")

def guess_blockmode(oracle):
    input_ = bytes([0x42] * 200)
    encrypted, answer = oracle(input_)
    blocks = [encrypted[i*AES.block_size: (i+1)*AES.block_size] for i in range(len(encrypted)//AES.block_size)]
    unique_blocks = len(set(blocks))
    guess = "ECB" if unique_blocks != len(blocks) else "CBC"
    return guess == answer

if __name__ == "__main__":
    correct_guesses = 0
    num_trials = 100
    for i in range(num_trials):
        if guess_blockmode(encryption_oracle):
            correct_guesses += 1
    accuracy = (correct_guesses / num_trials) * 100
    print(f"Accuracy: {accuracy:.2f}%")
