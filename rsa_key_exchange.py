from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    return rsa_cipher.encrypt(message)

def rsa_decrypt(private_key, ciphertext):
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    return rsa_cipher.decrypt(ciphertext)
