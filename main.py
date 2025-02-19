import os
import time
import product_cipher as PC
import rsa as RSA
import aes as AES
from math import gcd


def pause():
    input("\n\nPress Enter to continue...\n\n")

def save_key(filename, key_data):
    """Save key data to a text file."""
    with open(filename, "w") as f:
        f.write(str(key_data))

def is_valid_affine_key(a):
    """Check if a is coprime with 26 (must have gcd(a, 26) == 1)."""
    return gcd(a, 26) == 1

def main():
    while True:
        print(" ------------------------------------")
        print("|       FILE ENCRYPTION TOOLS        |")
        print(" ------------------------------------")
        print("Choose an encryption method:")
        print("1. Affine Cipher + Columnar Transposition Cipher (Classical)")
        print("2. RSA Key Exchange (Asymmetric Cipher)")
        print("3. AES Encryption (Modern Symmetric Cipher)")
        print("4. Any other number to exit.")

        choice = input("Enter your choice (1/2/3/4): ")

        if choice == "1":
            Affine_Columnar()
        elif choice == "2":
            RSA_ENC()
        elif choice == "3":
            AES_ENC() 
        else:
            print("Bye!")
            exit()

def Affine_Columnar():
    plaintext = input("\n\nEnter the plaintext: ")

    # For Affine Cipher: Validate 'a' is coprime with 26
    while True:
        a = int(input("Enter the value of a (Affine cipher key part, coprime with 26): "))
        if is_valid_affine_key(a):
            break
        else:
            print("Invalid value for 'a'. It must be coprime with 26. Try again.")

    # For Affine Cipher: 'b' can be any integer
    b = int(input("Enter the value of b (Affine cipher key part): "))

    # For Columnar Transposition Cipher: Ensure the key is not empty
    while True:
        key = input("Enter the key for the Columnar Transposition Cipher: ").strip()
        if len(key) > 0:
            break
        else:
            print("Key cannot be empty. Please enter a valid key.")

    # Measure encryption time with higher precision
    start_time = time.perf_counter()
    encrypted = PC.encrypt_product_cipher(plaintext, a, b, key)
    end_time = time.perf_counter()
    encryption_time = end_time - start_time

    # Measure decryption time with higher precision
    start_time = time.perf_counter()
    decrypted = PC.decrypt_product_cipher(encrypted, a, b, key)
    end_time = time.perf_counter()
    decryption_time = end_time - start_time

    # Display results
    print(f"\nEncrypted text: {encrypted[:50]}...")  # Display first 50 chars of the encrypted text
    print(f"Decrypted text: {decrypted[:50]}...")  # Display first 50 chars of the decrypted text
    print(f"Encryption time: {encryption_time} seconds")
    print(f"Decryption time: {decryption_time} seconds\n\n")

def RSA_ENC():
    # [1] 
    print("\n\n[1] ----- KEY PAIRS GENERATION -----")
    answer = (input("=> Do you want to generate Asymmetric Key Pairs for Alice and Bob? (Yes/ No):").lower())
    if(answer == 'yes'):
        alice_n, alice_d = RSA.generate_asymkeys()
        save_key("Alice/AlicePublic.txt", hex(alice_n)[2:])  
        save_key("Alice/AlicePrivate.txt", hex(alice_d)[2:])  

        bob_n, bob_d = RSA.generate_asymkeys()
        save_key("Bob/BobPublic.txt", hex(bob_n)[2:])  
        save_key("Bob/BobPrivate.txt", hex(bob_d)[2:])  

        print("=> Key Pairs Generation Done.")
    else:
        print("=> Key Pairs will not be generated")

    pause()

    # [2]
    print("[2] ----- SYMMETRIC KEY GENERATION -----")
    # Check File exist or not
    if not (os.path.exists("Alice/AlicePublic.txt") and 
        os.path.exists("Alice/AlicePrivate.txt") and 
        os.path.exists("Bob/BobPublic.txt") and 
        os.path.exists("Bob/BobPrivate.txt")):
        print("=> Key Pairs Not Found or Not Complete ! \n\n\n")
        return
    
    print("=> Alice is generating a symmetric Key to communicate with Bob")
    key_size = int(input("=> Enter Preffered key size (128, 192, or 256): "))
    while(key_size not in [128, 192, 256]):
        key_size = int(input("=> Key size must be in (128, 192, or 256): "))
    symmetric_key = AES.generate_symmetric_key(key_size)
    hex_key = symmetric_key.hex()
    save_key("Alice/secret_key.txt", hex_key)  
    print("=> Symmetric Key Generation Done.")
    
    pause()

    # [3]
    print("[3] ----- RSA ENCRYPTION -----")
    print("=> Alice encrypted the symmetric key using Bob's Public key with RSA method")
    print("=> Encrypted symmetric key saved as 'ENC_symmetric_key'")
    RSA.encrypt_with_public_key("Alice/secret_key.txt", "Bob/BobPublic.txt", "ENC_symmetric_key")

    pause()

    # [4]
    print("[4] ----- RSA DECRYPTION -----")
    print("=> Bob decrypted the 'ENC_symmetric_key' using his own Private Key with RSA method")
    RSA.decrypt_with_private_key("ENC_symmetric_key", "Bob/BobPrivate.txt", "Bob/BobPublic.txt", "Bob/secret_key.txt")
    print("=> Bob successfully get the symmetric key from Alice!")
    print("=> Key Exchange Process is Done using RSA!")

    pause()

def AES_ENC():
    # [1] 
    print("\n\n[1] ----- AES ENCRYPTION -----")
    print("=> Alice encrypting the message with the Shared Symmetric Key...")

    message_file = "Alice/message.txt"
    # Check File exist or not
    if not os.path.exists("Alice/secret_key.txt"):
        print("=> Symmetric Key Not Found!")
        return
    elif not os.path.exists(message_file):
        print("=> File to be Encrypted Not Found!")
        return
    
    # Validation on Key Size
    with open("Alice/secret_key.txt", "r") as f:
        secret_key = f.read().strip()  # Read hex key and remove whitespace
    key_bytes = len(secret_key) // 2  # Each byte = 2 hex characters
    key_size = key_bytes * 8  # Convert bytes to bits
    if(key_size not in [128, 192, 256]):
        print(f"=> Key Size Error: {key_size}")
        return
    secret_key = bytes.fromhex(secret_key)

    # Read the message to be encrypted
    with open(message_file, "rb") as f:
        plaintext = f.read()

    # Encrypt and Save the File
    ciphertext = AES.encrypt(plaintext, secret_key, key_size)
    with open("ENC_message", "wb") as f:
        f.write(ciphertext)

    print("=> Alice has successfully encrypted the message!")

    pause()

    # [2] 
    print("[2] ----- AES DECRYPTION -----")
    print("Bob decrypting the message with the Shared Symmetric Key...")
    # Check File exist or not
    if not os.path.exists("Bob/secret_key.txt"):
        print("=> Symmetric Key Not Found!")
        return
    if not os.path.exists("ENC_message"):
        print("=> No Encrypted File Found")
        return
    
    with open("Bob/secret_key.txt", "r") as f:
        secret_key = f.read().strip()  # Read hex key and remove whitespace
        secret_key = bytes.fromhex(secret_key)

    #Read the Encrypted File
    with open("ENC_message", "rb") as f:
        encrypted_data = f.read()

    # Decrypt and Save the File
    decrypted_text = AES.decrypt(encrypted_data, secret_key, key_size)
    with open("Bob/message.txt", "wb") as f:
        f.write(decrypted_text)

    print("=> Bob has successfully decrypted the message!")
    print("=> Encryption and decryption completed successfully.")

    pause()

if __name__ == "__main__":
    main()