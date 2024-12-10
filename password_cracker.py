import hashlib

def crack_sha1_hash(hash, use_salts=False):
    # Load passwords
    with open("top-10000-passwords.txt", "r") as password_file:
        passwords = password_file.read().splitlines()
    
    # Load salts if use_salts is True
    salts = []
    if use_salts:
        with open("known-salts.txt", "r") as salts_file:
            salts = salts_file.read().splitlines()

    # Hash and compare passwords
    for password in passwords:
        # If salts are not used, directly hash the password
        if not use_salts:
            hashed_password = hashlib.sha1(password.encode()).hexdigest()
            if hashed_password == hash:
                return password
        else:
            # If salts are used, hash with all combinations of salts
            for salt in salts:
                # Salt prepended
                hashed_password = hashlib.sha1((salt + password).encode()).hexdigest()
                if hashed_password == hash:
                    return password
                # Salt appended
                hashed_password = hashlib.sha1((password + salt).encode()).hexdigest()
                if hashed_password == hash:
                    return password

    # If no password matches the hash
    return "PASSWORD NOT IN DATABASE"
