import os
import time
from affine_cipher import affine_encrypt, affine_decrypt, validate_affine_key
from columnar_transposition import columnar_encrypt, columnar_decrypt
from aes_cipher import aes_encrypt, aes_decrypt
from triple_des_cipher import triple_des_encrypt, triple_des_decrypt
from rsa_key_exchange import generate_rsa_keypair, rsa_encrypt, rsa_decrypt

def introduce_bit_error(ciphertext):
    """Introduce a bit error in the ciphertext."""
    corrupted_ciphertext = bytearray(ciphertext)
    corrupted_ciphertext[0] ^= 0x01  # Flip the first bit
    return bytes(corrupted_ciphertext)

def main():
    while True:
        print("\n" + "=" * 40)
        print("Choose an encryption method:")
        print("1. Affine Cipher + Columnar Transposition Cipher (Classical)")
        print("2. AES Encryption (Modern Symmetric Cipher)")
        print("3. Triple DES Encryption (Modern Symmetric Cipher)")
        print("4. RSA Key Exchange (Asymmetric Cipher)")
        print("Any other number to exit.")
        
        choice = input("Enter your choice (1/2/3/4): ")
        
        if choice == "1":
            # Classical Ciphers: Affine + Columnar Transposition
            print("\n--- Affine Cipher + Columnar Transposition ---")
            plaintext = input("Enter plaintext: ")
            
            # Validate 'a' for Affine Cipher
            while True:
                a = int(input("Enter 'a' (must be coprime with 26): "))
                if validate_affine_key(a):
                    break
                else:
                    print(f"'a' must be coprime with 26. {a} is invalid. Try again.")
            
            b = int(input("Enter 'b': "))
            key_columnar = input("Enter key for Columnar Transposition: ")
            
            # Measure Affine Encryption Time
            start_time = time.time()
            affine_encrypted = affine_encrypt(plaintext, a, b)
            affine_encryption_time = time.time() - start_time
            
            # Measure Columnar Encryption Time
            start_time = time.time()
            columnar_encrypted = columnar_encrypt(affine_encrypted, key_columnar)
            columnar_encryption_time = time.time() - start_time
            
            # Total Encryption Time
            total_encryption_time = affine_encryption_time + columnar_encryption_time
            
            print("\n--- Result ---")
            print(f"Affine Encrypted Text: {affine_encrypted}")
            print(f"Columnar Encrypted Text: {columnar_encrypted}")
            print(f"Total Encryption Time: {total_encryption_time:.6f} seconds")
            
            # Decrypt in reverse order: Columnar -> Affine
            columnar_decrypted = columnar_decrypt(columnar_encrypted, key_columnar)
            final_decrypted = affine_decrypt(columnar_decrypted, a, b)
            
            print("\n--- Decrypted Result ---")
            print(f"Columnar Decrypted Text: {columnar_decrypted}")
            print(f"Final Decrypted Text: {final_decrypted}")
        
        elif choice == "2":
            # AES Encryption
            print("\n--- AES Encryption ---")
            plaintext = input("Enter plaintext: ")
            key = os.urandom(16)  # Randomly generate a 16-byte key
            
            start_time = time.time()
            iv, encrypted_text = aes_encrypt(key, plaintext)
            encryption_time = time.time() - start_time
            
            # Introduce a bit error in the ciphertext for demonstration
            corrupted_ciphertext = introduce_bit_error(encrypted_text)
            
            try:
                decrypted_text_with_error = aes_decrypt(key, iv, corrupted_ciphertext)
                print(f"Decrypted Text with Bit Error: {decrypted_text_with_error}")
            except Exception as e:
                print(f"Decryption failed due to bit error: {e}")

            start_time = time.time()
            decrypted_text = aes_decrypt(key, iv, encrypted_text)
            decryption_time = time.time() - start_time
            
            print("\n--- Result ---")
            print(f"Encrypted Text (in bytes): {encrypted_text}")
            print(f"Decrypted Text: {decrypted_text}")
            print(f"Encryption Time: {encryption_time:.6f} seconds")
            print(f"Decryption Time: {decryption_time:.6f} seconds")
        
        elif choice == "3":
            # Triple DES Encryption
            print("\n--- Triple DES Encryption ---")
            plaintext = input("Enter plaintext: ")
            
            key = os.urandom(24)  # Randomly generate a 24-byte key for Triple DES
            
            start_time = time.time()
            iv, encrypted_text = triple_des_encrypt(key, plaintext)
            encryption_time = time.time() - start_time
            
            start_time = time.time()
            decrypted_text = triple_des_decrypt(key, iv, encrypted_text)
            decryption_time = time.time() - start_time
            
            print("\n--- Result ---")
            print(f"Encrypted Text (in bytes): {encrypted_text}")
            print(f"Decrypted Text: {decrypted_text}")
            print(f"Encryption Time: {encryption_time:.6f} seconds")
            print(f"Decryption Time: {decryption_time:.6f} seconds")
        
        elif choice == "4":
           # RSA Key Exchange
           print("\n--- RSA Key Exchange ---")
           
           private_key, public_key = generate_rsa_keypair()
           
           secret_message = input("Enter secret message to encrypt: ").encode()
           
           start_time = time.time()
           encrypted_message = rsa_encrypt(public_key, secret_message)
           encryption_time = time.time() - start_time
           
           start_time = time.time()
           decrypted_message = rsa_decrypt(private_key, encrypted_message)
           decryption_time = time.time() - start_time
           
           print("\n--- Result ---")
           print(f"Encrypted Message (in bytes): {encrypted_message}")
           print(f"Decrypted Message: {decrypted_message.decode()}")
           print(f"Encryption Time: {encryption_time:.6f} seconds")
           print(f"Decryption Time: {decryption_time:.6f} seconds")
        
        else:
           # Exit the program
           print("\nExiting the program.")
           break

if __name__ == "__main__":
    main()
