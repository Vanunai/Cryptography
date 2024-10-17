import base64

def calculate_frequency_score(text):
    letter_frequency = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06966, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([letter_frequency.get(chr(byte), 0) for byte in text.lower()])

def xor_single_byte(input_bytes, key):
    return bytes([byte ^ key for byte in input_bytes])

def break_single_byte_xor(ciphertext):
    candidates = []
    for key_candidate in range(256):
        decrypted_text = xor_single_byte(ciphertext, key_candidate)
        score = calculate_frequency_score(decrypted_text)
        candidates.append({
            'key': key_candidate,
            'decrypted_text': decrypted_text,
            'score': score
        })
    best_candidate = max(candidates, key=lambda x: x['score'])
    return best_candidate

def hamming_distance(bytes1, bytes2):
    distance = 0
    for byte1, byte2 in zip(bytes1, bytes2):
        xor_result = byte1 ^ byte2
        distance += bin(xor_result).count('1')
    return distance

def guess_key_length(ciphertext, min_keysize=2, max_keysize=40):
    keysize_scores = []
    for keysize in range(min_keysize, max_keysize + 1):
        chunks = [ciphertext[i:i + keysize] for i in range(0, len(ciphertext), keysize)]
        distances = []
        for i in range(len(chunks) - 1):
            distance = hamming_distance(chunks[i], chunks[i + 1])
            distances.append(distance / keysize)
        avg_distance = sum(distances) / len(distances)
        keysize_scores.append((keysize, avg_distance))
    return min(keysize_scores, key=lambda x: x[1])[0]

def repeating_key_xor_decrypt(ciphertext, key):
    return bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])

def break_repeating_key_xor(ciphertext):
    keysize = guess_key_length(ciphertext)
    key = b''
    
    for i in range(keysize):
        block = bytes([ciphertext[j] for j in range(i, len(ciphertext), keysize)])
        key += bytes([break_single_byte_xor(block)['key']])

    decrypted_message = repeating_key_xor_decrypt(ciphertext, key)
    return decrypted_message, key

if __name__ == '__main__':
    with open(r"F:\crypto\1\ciphertext.txt", "r") as file:
        ciphertext_base64 = file.read()
        ciphertext = base64.b64decode(ciphertext_base64)

    decrypted_message, key = break_repeating_key_xor(ciphertext)
    
    print("Decrypted Message:", decrypted_message.decode('utf-8'))
    print("Key:", key.decode('utf-8'))
