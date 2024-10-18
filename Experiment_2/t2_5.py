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
    return unpad(plain, AES.block_size)

def sanitize(s):
    return s.replace('&', '').replace('=', '')

def profile_for(email):
    profile = [('email', email), ('uid', '10'), ('role', 'user')]
    encoded = [k + '=' + sanitize(v) for k, v in profile]
    return '&'.join(encoded)

def parse_profile(encoded):
    fields = encoded.split('&')
    items = [tuple(field.split('=')) for field in fields]
    profile = {key: value for key, value in items}
    return profile

def oracle(email):
    return ecb_encrypt(profile_for(email).encode(), key)

def check_log_in(token):
    decrypted = ecb_decrypt(token, key)
    profile = parse_profile(decrypted.decode())
    print(profile)
    return profile['role'] == 'admin'

key=bytes([random.randint(0,2**8-1) for _ in range(16)])

if __name__ == "__main__":
    admin_encrypted = oracle('aaaaaaaaaaadmin' + '\x0b' * 11)
    assert(len(admin_encrypted) == 4 * 16)
    admin_block = admin_encrypted[16:32]

    normal_blocks = oracle('aaaaaaaaaaaaa')
    assert(len(normal_blocks) == 3 * 16)

    crafted = normal_blocks[:32] + admin_block

    logged = check_log_in(crafted)
    print("Logged: %s" % str(logged))
    assert(logged)
