def generate_required_chars():
    required_chars = [chr(32), chr(33), chr(34), chr(44), chr(45), chr(46), chr(58), chr(63), chr(95)]
    required_chars += [chr(x) for x in range(65, 91)]  
    required_chars += [chr(x) for x in range(97, 123)]  
    return required_chars

def find_keys(sub_arr, required_chars):
    all_keys = list(range(0x00, 0xff + 1)) 
    res_keys = all_keys.copy()
    
    for i in all_keys:
        for s in sub_arr:
            if chr(s ^ i) not in required_chars:
                res_keys.remove(i)
                break
    return res_keys

def convert_ciphertext_to_array(ciphertext):
    return [int(ciphertext[x:x + 2], 16) for x in range(0, len(ciphertext), 2)]

def analyze_key_lengths(arr, max_key_length=13):
    required_chars = generate_required_chars()
    for key_length in range(1, max_key_length + 1):
        for class_number in range(key_length):
            sub_arr = arr[class_number::key_length]
            res_keys = find_keys(sub_arr, required_chars)
            print(f'key_length= {key_length}, class_number= {class_number}, keys= {res_keys}')

def decrypt_text(arr, keys):
    plaintext = ""
    for i in range(len(arr)):
        plaintext += chr(arr[i] ^ keys[i % len(keys)])
    return plaintext

ciphertext = "F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923C\
AB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF\
5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84C\
C931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D96\
3FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47E\
FD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5\
923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA\
36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63C\
ED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A8\
5A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250\
C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794"

arr = convert_ciphertext_to_array(ciphertext)

analyze_key_lengths(arr)

keys1 = [186, 29, 145, 178, 83, 205, 62]
plaintext1 = decrypt_text(arr, keys1)
print("Decrypted Text1:", plaintext1)

keys2 = [186, 31, 145, 178, 83, 205, 62]
plaintext2 = decrypt_text(arr, keys2)
print("Decrypted Text2", plaintext2)
