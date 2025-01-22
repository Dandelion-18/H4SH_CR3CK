import hashlib
import os

def load_wordlist(wordlist_path):
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        print(f"[-] File {wordlist_path} not found.")
        return[]    
    
def crack_hash(hash_to_crack, hash_type, wordlist):
    for word in wordlist:
        encoded_word = word.encode()
        if hash_type == 'md5':
            generated_hash = hashlib.md5(encoded_word).hexdigest()
        elif hash_type == 'sha1':
            generated_hash = hashlib.sha1(encoded_word).hexdigest()
        elif hash_type == 'sha256':
            generated_hash = hashlib.sha256(encoded_word).hexdigest()
        elif hash_type == 'sha512':
            generated_hash = hashlib.sha512(encoded_word).hexdigest()
        else:
            print(f"[-] Hash type {hash_type} not allowed.")
            return None 

        if generated_hash == hash_to_crack:
            return word

    return None


def main():
    print("===Crack_Hash===")
    hash_to_crack = input("[!!] Print hash to crack ==> ").strip()
    hash_type = input("[!!] Print hash type (md5, sha1, sha256, sha512) ==> ").strip().lower()
    wordlist_path = input("[!!] Print PATH to wordlist ==> ").strip()


    if not os.path.exists(wordlist_path):
        print(f"[-] Wordlist file {wordlist_path} no true.")
        return
    
    print("[+] Download wordlist...")
    wordlist = load_wordlist(wordlist_path)
    if not wordlist:
        print("[-] Wordlist is empty or not found.")
        return
    
    print("[+] Search password...")
    password = crack_hash(hash_to_crack, hash_type, wordlist)
    if password:
        print(f"[SUCCESS] Password to hash: {password}")
    else:
        print(f"[-] Password not found in wordlist")


if __name__ == "__main__":
    main()



