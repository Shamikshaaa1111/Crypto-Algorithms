from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib
import base64


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
    decrypted = cipher2.decrypt(ciphertext)

    print("Decrypted:", decrypted.decode())


# ---------- RSA ----------
def rsa_encryption():
    message = input("Enter your message : ")

    key = RSA.generate(2048)
    public_key = key.publickey()

    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode())

    print("\n--- RSA Encryption ---")
    print("Encrypted message :", base64.b64encode(encrypted).decode())

    # Decryption
    cipher = PKCS1_OAEP.new(key)
    decrypted = cipher.decrypt(encrypted)

    print("Decrypted message :", decrypted.decode())


# ---------- SHA-256 ----------
def sha_hash():
    message = input("Enter your message : ")

    hash_value = hashlib.sha256(message.encode()).hexdigest()

    print("\n--- SHA-256 Hash ---")
    print("Hash Value :", hash_value)


# ---------- Main Menu ----------
while True:
    print("\n==== CRYPTOGRAPHY TOOL ====")
    print("1. AES Encryption & Decryption")
    print("2. RSA Encryption & Decryption")
    print("3. SHA-256 Hash")
    print("4. Exit")

    choice = input("Enter choice: ")

    if choice == "1":
        aes_encryption()

    elif choice == "2":
        rsa_encryption()

    elif choice == "3":
        sha_hash()

    elif choice == "4":
        print("Program exited")
        break

    else:
        print("Invalid choice!")