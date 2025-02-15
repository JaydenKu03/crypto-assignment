import math

def columnar_encrypt(plaintext, key):
    num_cols = len(key)
    num_rows = math.ceil(len(plaintext) / num_cols)
    
    # Fill the grid with empty strings
    grid = [''] * num_cols

    # Fill the grid column-wise
    for i, char in enumerate(plaintext):
        grid[i % num_cols] += char

    # Sort key and prepare for encryption
    sorted_key = sorted((char, i) for i, char in enumerate(key))
    
    # Create the ciphertext by reading columns in order of sorted key
    ciphertext = ''.join(grid[i[1]] for i in sorted_key)

    return ciphertext

def columnar_decrypt(ciphertext, key):
    num_cols = len(key)
    num_rows = math.ceil(len(ciphertext) / num_cols)
    
    # Sort key to determine the order of columns
    sorted_key = sorted((char, i) for i, char in enumerate(key))
    
    # Create a grid to hold the columns
    grid = [''] * num_cols
    index = 0

    # Fill the grid with characters from the ciphertext column-wise
    for _, col_index in sorted_key:
        grid[col_index] = ciphertext[index:index + num_rows]
        index += num_rows

    # Read the plaintext row-wise from the filled grid
    plaintext = ''.join(grid[i % num_cols][i // num_cols] for i in range(len(ciphertext)))
    
    return plaintext
