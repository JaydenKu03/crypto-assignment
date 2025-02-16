def columnar_transposition_encrypt(plaintext, key):
    """Encrypts plaintext using Columnar Transposition Cipher."""
    # Remove spaces from the key
    key = ''.join(key.split())
    num_columns = len(key)
    num_rows = len(plaintext) // num_columns + (1 if len(plaintext) % num_columns != 0 else 0)
    
    # Create a table to hold characters
    table = ['' for _ in range(num_rows)]
    
    # Fill the table row by row
    for i in range(len(plaintext)):
        row = i // num_columns
        col = i % num_columns
        table[row] += plaintext[i]

    # Ensure the table is filled correctly
    while len(table[-1]) < num_columns:
        table[-1] += ' '  # Fill last row with space if necessary

    # Sort the key to determine the column order
    key_order = sorted(range(len(key)), key=lambda x: key[x])

    # Reconstruct ciphertext by reading columns in the sorted order of the key
    ciphertext = ''.join(''.join(table[row][col] for row in range(num_rows)) for col in key_order)
    
    return ciphertext

def columnar_transposition_decrypt(ciphertext, key):
    """Decrypts ciphertext using Columnar Transposition Cipher."""
    # Remove spaces from the key
    key = ''.join(key.split())
    num_columns = len(key)
    num_rows = len(ciphertext) // num_columns
    table = ['' for _ in range(num_rows)]
    
    # Distribute ciphertext into columns according to the sorted key
    key_order = sorted(range(len(key)), key=lambda x: key[x])
    cols = ['' for _ in range(num_columns)]
    
    for i, col in enumerate(key_order):
        cols[col] = ciphertext[i * num_rows:(i + 1) * num_rows]
    
    # Rebuild the plaintext by reading the table in row order
    plaintext = ''.join(cols[col][row] for row in range(num_rows) for col in range(num_columns))
    
    return plaintext
