from affine_cipher import affine_encrypt, affine_decrypt
from columnar_transposition import columnar_transposition_encrypt, columnar_transposition_decrypt

def encrypt_product_cipher(plaintext, a, b, key):
    """Encrypts plaintext using the combined Affine Cipher and Columnar Transposition Cipher."""
    # First apply the Affine Cipher
    affine_encrypted = affine_encrypt(plaintext, a, b)
    # Then apply the Columnar Transposition Cipher
    transposition_encrypted = columnar_transposition_encrypt(affine_encrypted, key)
    return transposition_encrypted

def decrypt_product_cipher(ciphertext, a, b, key):
    """Decrypts ciphertext using the combined Affine Cipher and Columnar Transposition Cipher."""
    # First apply the Columnar Transposition Cipher
    transposition_decrypted = columnar_transposition_decrypt(ciphertext, key)
    # Then apply the Affine Cipher
    affine_decrypted = affine_decrypt(transposition_decrypted, a, b)
    return affine_decrypted
