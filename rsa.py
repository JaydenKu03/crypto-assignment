import random

def is_prime(n, k=5):
    """Check if a number is prime using the Miller-Rabin test."""
    if n <= 1:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Miller-Rabin test
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits=1024):
    """Generate a large prime number of given bit size."""
    while True:
        num = random.getrandbits(bits) | (1 << bits - 1) | 1  # Ensure odd and correct bit length
        if is_prime(num):
            return num

def gcd(a, b):
    """Compute the Greatest Common Divisor using Euclidean Algorithm."""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """Compute modular inverse of e mod phi using Extended Euclidean Algorithm."""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return g, x, y

    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("No modular inverse exists")
    return x % phi

def generate_asymkeys():
    # Step 1: Generate two large prime numbers
    p = generate_large_prime(1024)
    q = generate_large_prime(1024)

    # Step 2: Compute modulus n and Euler's totient function phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Step 3: Choose a public exponent e
    e = 65537  # Common choice
    while gcd(e, phi) != 1:  # Ensure e is coprime to phi
        e += 2  # Pick next odd number

    # Step 4: Compute private exponent d
    d = mod_inverse(e, phi)

    # Return only n and d (no e)
    return (n, d)


def encrypt_with_public_key(input_file, public_key_file, output_file):
    """Encrypts a file using Bob's public key and saves the encrypted content"""
    # Read Bob's public key (n, e)
    with open(public_key_file, "r") as f:
        n = int(f.read(), 16)  # Convert hex to int

    e = 65537  # Common public exponent

    # Read the secret key from Alice's file
    with open(input_file, "rb") as f:
        secret_key = f.read()

    # Convert secret key to integer
    secret_key_int = int.from_bytes(secret_key, byteorder='big')

    if secret_key_int >= n:
        raise ValueError("Secret key is too large for RSA encryption.")

    # Encrypt using RSA: C = M^e mod n
    encrypted_key = pow(secret_key_int, e, n)

    # Convert encrypted key to bytes
    key_length = (n.bit_length() + 7) // 8  # Get byte length
    encrypted_key_bytes = encrypted_key.to_bytes(key_length, byteorder='big')

    # Save encrypted key in binary format
    with open(output_file, "wb") as f:
        f.write(encrypted_key_bytes)


def decrypt_with_private_key(input_file, private_key_file, public_key_file, output_file):
    """Decrypts using Bob's private key and saves the decrypted content."""
    # Read Bob's private key (n, d)
    with open(private_key_file, "r") as f:
        d = int(f.read(), 16)  # Convert hex to int

    # Read Bob's public modulus (n)
    with open(public_key_file, "r") as f:
        n = int(f.read(), 16)  # Convert hex to int

    # Read encrypted data in binary
    with open(input_file, "rb") as f:
        encrypted_key_bytes = f.read()

    # Convert encrypted bytes to integer
    encrypted_key_int = int.from_bytes(encrypted_key_bytes, byteorder='big')

    # Decrypt using RSA: M = C^d mod n
    decrypted_key_int = pow(encrypted_key_int, d, n)

    # Convert back to bytes
    key_length = (decrypted_key_int.bit_length() + 7) // 8  # Get byte length
    decrypted_key_bytes = decrypted_key_int.to_bytes(key_length, byteorder='big')

    # Save decrypted key in binary format
    with open(output_file, "wb") as f:
        f.write(decrypted_key_bytes)