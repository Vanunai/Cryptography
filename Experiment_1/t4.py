import hashlib
import itertools
import datetime

target_hash = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

char_sets = [['Q', 'q'], ['W', 'w'], ['%', '5'], ['8', '('], ['=', '0'], ['I', 'i'], ['*', '+'], ['n', 'N']]

def generate_passwords(char_sets):
   
    for combination in itertools.product(*char_sets):
        
        for permutation in itertools.permutations(combination):
            yield ''.join(permutation)

def sha1_encrypt(input_str):
    hash_obj = hashlib.sha1()
    hash_obj.update(input_str.encode('utf-8'))
    return hash_obj.hexdigest()

def find_password(target_hash, char_sets):
    start_time = datetime.datetime.now()

    for password in generate_passwords(char_sets):
        encrypted_password = sha1_encrypt(password)
        if encrypted_password == target_hash:
            end_time = datetime.datetime.now()
            print(f"Password found: {password}")
            print(f"Time taken: {end_time - start_time}")
            return

    print("Password not found.")

if __name__ == '__main__':
    find_password(target_hash, char_sets)
