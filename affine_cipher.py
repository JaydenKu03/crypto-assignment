def affine_encrypt(plaintext, a, b):
    """Encrypts plaintext using the Affine Cipher."""
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            # Convert character to a number (0-25)
            num = ord(char.lower()) - ord('a')
            # Apply Affine transformation: E(x) = (ax + b) % 26
            encrypted_num = (a * num + b) % 26
            # Convert the number back to a letter
            ciphertext += chr(encrypted_num + ord('a'))
        else:
            # Non-alphabet characters remain unchanged
            ciphertext += char
    return ciphertext

def affine_decrypt(ciphertext, a, b):
    """Decrypts ciphertext using the Affine Cipher."""
    # Calculate modular inverse of a modulo 26
    a_inv = mod_inverse(a, 26)
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            # Convert character to a number (0-25)
            num = ord(char.lower()) - ord('a')
            # Apply inverse Affine transformation: D(x) = a_inv(x - b) % 26
            decrypted_num = (a_inv * (num - b)) % 26
            # Convert the number back to a letter
            plaintext += chr(decrypted_num + ord('a'))
        else:
            # Non-alphabet characters remain unchanged
            plaintext += char
    return plaintext

def mod_inverse(a, m):
    """Returns the modular inverse of a under modulo m."""
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None
