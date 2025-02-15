from math import gcd

def affine_encrypt(plaintext, a, b):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shift = (a * (ord(char.lower()) - ord('a')) + b) % 26
            ciphertext += chr(shift + ord('a'))
        else:
            ciphertext += char
    return ciphertext

def affine_decrypt(ciphertext, a, b):
    a_inv = pow(a, -1, 26)  # Modular multiplicative inverse of a mod 26
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            shift = (a_inv * (ord(char.lower()) - ord('a') - b)) % 26
            plaintext += chr(shift + ord('a'))
        else:
            plaintext += char
    return plaintext

def validate_affine_key(a):
    return gcd(a, 26) == 1
