import re
import hashlib
import sys

def basic_hash_identifier(hash_str):
    hash_str = hash_str.strip().lower()
    if not re.fullmatch(r'[0-9a-f]+', hash_str):
        return "unknown"
    length = len(hash_str)
    if length == 32:
        return "md5"
    elif length == 40:
        return "sha1"
    elif length == 64:
        return "sha256"
    else:
        return "unknown"

def advanced_hash_identifier(hash_str):
    try:
        import hashid
    except ImportError:
        print("hashid module is not installed. Please install it by running:\n\npip install hashid\n")
        sys.exit(1)

    hashid_obj = hashid.HashID()
    results = hashid_obj.identifyHash(hash_str)
    if results:
        for res in results:
            name = res.name.lower()
            if 'md5' in name:
                return 'md5'
            elif 'sha1' in name:
                return 'sha1'
            elif 'sha256' in name:
                return 'sha256'
        return None  # no suitable match found
    else:
        return None  # no matches found

def hash_password(password, hash_type):
    password = password.strip().encode()
    if hash_type == "md5":
        return hashlib.md5(password).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(password).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(password).hexdigest()
    else:
        raise ValueError("Unsupported hash type for cracking.")

def crack_hash(leaked_hash, hash_type, dictionary_file, debug=False):
    print(f"Starting dictionary attack with hash type: {hash_type}")
    found_any = False
    try:
        with open(dictionary_file, 'r', encoding='latin-1') as f:
            for line in f:
                guess = line.strip()
                hashed_guess = hash_password(guess, hash_type)
                if debug:
                    print(f"Trying: {guess} -> {hashed_guess}")
                if hashed_guess == leaked_hash.lower():
                    print(f"[+] Password found: {guess}")
                    found_any = True
        if not found_any:
            print("[-] Password not found in dictionary.")
    except FileNotFoundError:
        print(f"Dictionary file '{dictionary_file}' not found.")
        print("Please download 'rockyou.txt' and place it in the script folder.")

def ask_yes_no(prompt):
    while True:
        choice = input(prompt).strip().lower()
        if choice in ('yes', 'no'):
            return choice
        else:
            print("Please enter 'yes' or 'no'.")

def main():
    dictionary_file = "rockyou.txt"
    print("Password Cracker - dictionary attack (MD5, SHA1, SHA256)")
    print("Type 'exit' anytime to quit.")
    while True:
        leaked_hash = input("\nEnter the leaked hash (or type 'exit' to quit): ").strip()
        if leaked_hash.lower() == "exit":
            print("Exiting...")
            break

        hash_type = advanced_hash_identifier(leaked_hash)
        if hash_type is None:
            print("Advanced hashid detection found no suitable hash type.")
            choice = ask_yes_no("Do you want to try basic detection instead? (yes/no): ")
            if choice == 'yes':
                hash_type = basic_hash_identifier(leaked_hash)
            else:
                print("Skipping this hash.")
                continue

        if hash_type == "unknown" or hash_type is None:
            print("Could not identify hash type or unsupported hash type.")
            continue

        print(f"Identified hash type: {hash_type}")
        print(f"Using dictionary file: {dictionary_file}")

        crack_hash(leaked_hash, hash_type, dictionary_file)

if __name__ == "__main__":
    main()
