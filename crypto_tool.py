from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib
import base64
import os


# ---------- AES ----------
def aes_encryption():
    message = input("Enter your message: ")

    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(message.encode())

    print("\n--- AES Encryption ---")
    print("Key:", base64.b64encode(key).decode())
    print("Encrypted:", base64.b64encode(ciphertext).decode())

    # Decryption
    cipher2 = AES.new(key, AES.MODE_EAX, cipher.nonce)
    decrypted = cipher2.decrypt_and_verify(ciphertext, tag)

    print("Decrypted:", decrypted.decode())


# ---------- RSA ----------
def rsa_encryption():
    message = input("Enter your message: ")

    key = RSA.generate(2048)
    public_key = key.publickey()

    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode())

    print("\n--- RSA Encryption ---")
    print("Encrypted message:", base64.b64encode(encrypted).decode())

    # Decryption
    cipher = PKCS1_OAEP.new(key)
    decrypted = cipher.decrypt(encrypted)

    print("Decrypted message:", decrypted.decode())


# ---------- SHA-256 ----------
def sha_hash():
    message = input("Enter your message: ")

    hash_value = hashlib.sha256(message.encode()).hexdigest()

    print("\n--- SHA-256 Hash ---")
    print("Hash Value:", hash_value)


# ---------- Caesar Cipher ----------
def caesar_cipher():
    message = input("Enter your message: ")
    shift = int(input("Enter shift value: "))

    encrypted = ""

    for char in message:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted += chr((ord(char) - base + shift) % 26 + base)
        else:
            encrypted += char

    print("\n--- Caesar Cipher ---")
    print("Encrypted:", encrypted)

    decrypted = ""

    for char in encrypted:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            decrypted += chr((ord(char) - base - shift) % 26 + base)
        else:
            decrypted += char

    print("Decrypted:", decrypted)


# ---------- Playfair Cipher ----------
def create_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = ""

    for char in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char.isalpha() and char not in matrix:
            matrix += char

    return [matrix[i:i + 5] for i in range(0, 25, 5)]


def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col


def playfair_encrypt_pair(a, b, matrix):
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    if r1 == r2:
        return matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]

    elif c1 == c2:
        return matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]

    else:
        return matrix[r1][c2] + matrix[r2][c1]


def playfair_cipher():
    key = input("Enter key: ")
    message = input("Enter message: ")

    matrix = create_matrix(key)

    message = message.upper().replace("J", "I")
    message = "".join(c for c in message if c.isalpha())

    prepared = ""
    i = 0

    while i < len(message):
        a = message[i]

        if i + 1 < len(message):
            b = message[i + 1]

            if a == b:
                prepared += a + "X"
                i += 1
            else:
                prepared += a + b
                i += 2
        else:
            prepared += a + "X"
            i += 1

    encrypted = ""

    for i in range(0, len(prepared), 2):
        encrypted += playfair_encrypt_pair(
            prepared[i],
            prepared[i + 1],
            matrix
        )

    print("\n--- Playfair Cipher ---")
    print("Encrypted:", encrypted)


# ---------- Diffie-Hellman ----------
def diffie_hellman():

    p = 23
    g = 9

    print("The value of P is : %d" % (p))
    print("The value of G is : %d" % (g))

    a = 5
    print("Secret number for Alice is : %d" % (a))

    x = int(pow(g, a, p))

    b = 3
    print("Secret number for Bob is : %d" % (b))

    y = int(pow(g, b, p))

    ka = int(pow(y, a, p))
    kb = int(pow(x, b, p))

    print("Secret number for Alice is : %d" % (ka))
    print("Secret number for Bob is : %d" % (kb))



# ---------- Digital Signature ----------
def digital_signature():
    message = input("Enter message: ")

    key = RSA.generate(2048)

    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)

    print("\n--- Digital Signature ---")
    print("Signature:", base64.b64encode(signature).decode())

    # Verification
    h2 = SHA256.new(message.encode())

    try:
        pkcs1_15.new(key.publickey()).verify(h2, signature)
        print("Signature verified successfully!")
    except ValueError:
        print("Signature verification failed!")


# ---------- Password Hashing ----------
def password_hashing():
    password = input("Enter password: ")

    salt = os.urandom(16)

    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100000
    )

    print("\n--- Password Hashing ---")
    print("Salt:", base64.b64encode(salt).decode())
    print("Password Hash:", base64.b64encode(hashed).decode())


# ---------- File Encryption ----------
def file_encryption():
    filename = input("Enter file name: ")

    if not os.path.exists(filename):
        print("File not found!")
        return

    key = get_random_bytes(16)

    with open(filename, "rb") as file:
        data = file.read()

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    output_file = filename + ".enc"

    with open(output_file, "wb") as file:
        file.write(cipher.nonce)
        file.write(tag)
        file.write(ciphertext)

    print("\n--- File Encryption ---")
    print("Encrypted file:", output_file)
    print("Key:", base64.b64encode(key).decode())


# ---------- Main Menu ----------
while True:

    print("\n╔════════════════════════════════════════════╗")
    print("║           CRYPTOGRAPHY TOOLKIT             ║")
    print("╠════════════════════════════════════════════╣")
    print("║ 1. AES Encryption & Decryption             ║")
    print("║ 2. RSA Encryption & Decryption             ║")
    print("║ 3. SHA-256 Hash                            ║")
    print("║ 4. Caesar Cipher                           ║")
    print("║ 5. Playfair Cipher                         ║")
    print("║ 6. Diffie-Hellman Key Exchange             ║")
    print("║ 7. Digital Signature                       ║")
    print("║ 8. Password Hashing                        ║")
    print("║ 9. File Encryption                         ║")
    print("║ 10. Exit                                   ║")
    print("╚════════════════════════════════════════════╝")

    choice = input("Enter choice: ")

    if choice == "1":
        aes_encryption()

    elif choice == "2":
        rsa_encryption()

    elif choice == "3":
        sha_hash()

    elif choice == "4":
        caesar_cipher()

    elif choice == "5":
        playfair_cipher()

    elif choice == "6":
        diffie_hellman()

    elif choice == "7":
        digital_signature()

    elif choice == "8":
        password_hashing()

    elif choice == "9":
        file_encryption()

    elif choice == "10":
        print("Program exited.")
        break

    else:
        print("Invalid choice!")