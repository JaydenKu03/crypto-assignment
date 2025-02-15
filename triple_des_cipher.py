from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import os

def triple_des_encrypt(key, plaintext):
    cipher = DES3.new(key, DES3.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), DES3.block_size))
    return cipher.iv, ct_bytes

def triple_des_decrypt(key, iv, ciphertext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return pt.decode()
