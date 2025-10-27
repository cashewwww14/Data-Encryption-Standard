# Tabel Permutasi Initial Permutation (IP)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation (FP) - inverse dari IP
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion Permutation (E)
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# Permutation P setelah S-boxes
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# S-boxes (8 S-boxes, masing-masing 4x16)
S = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 5, 10, 3, 13, 8, 15, 6],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Permuted Choice 1 (PC1) untuk key scheduling
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Permuted Choice 2 (PC2)
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Jadwal rotasi untuk setiap round
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def string_to_bits(text):
    bits = []
    for char in text:
        byte = ord(char)
        for i in range(8):
            bits.append((byte >> (7-i)) & 1)
    return bits


def bits_to_string(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i+j < len(bits):
                byte = (byte << 1) | bits[i+j]
        chars.append(chr(byte))
    return ''.join(chars)


def bits_to_hex(bits):
    hex_str = ""
    for i in range(0, len(bits), 4):
        nibble = 0
        for j in range(4):
            if i+j < len(bits):
                nibble = (nibble << 1) | bits[i+j]
        hex_str += format(nibble, 'x')
    return hex_str


def hex_to_bits(hex_str):
    bits = []
    for char in hex_str:
        nibble = int(char, 16)
        for i in range(4):
            bits.append((nibble >> (3-i)) & 1)
    return bits


def bits_to_custom_format(bits):
    """
    Konversi bits ke format custom yang lebih unik
    Format: [DES]<base64_encoded_data>[/DES]
    """
    import base64
    # Konversi bits ke bytes
    bytes_data = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i+j < len(bits):
                byte = (byte << 1) | bits[i+j]
        bytes_data.append(byte)
    
    # Encode ke Base64
    b64_str = base64.b64encode(bytes(bytes_data)).decode('ascii')
    
    # Tambahkan marker khusus
    return f"[DES]{b64_str}[/DES]"


def custom_format_to_bits(custom_str):
    """
    Konversi format custom kembali ke bits
    """
    import base64
    
    # Extract base64 dari marker
    if custom_str.startswith("[DES]") and custom_str.endswith("[/DES]"):
        b64_str = custom_str[5:-6]  # Hilangkan [DES] dan [/DES]
    else:
        b64_str = custom_str
    
    bytes_data = base64.b64decode(b64_str)
    bits = []
    for byte in bytes_data:
        for i in range(8):
            bits.append((byte >> (7-i)) & 1)
    return bits


def bits_to_base64(bits):
    """Konversi bits ke Base64 (mengandung huruf, angka, dan simbol +, /, =)"""
    import base64
    # Konversi bits ke bytes
    bytes_data = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i+j < len(bits):
                byte = (byte << 1) | bits[i+j]
        bytes_data.append(byte)
    # Encode ke Base64
    return base64.b64encode(bytes(bytes_data)).decode('ascii')


def base64_to_bits(b64_str):
    """Konversi Base64 kembali ke bits"""
    import base64
    bytes_data = base64.b64decode(b64_str)
    bits = []
    for byte in bytes_data:
        for i in range(8):
            bits.append((byte >> (7-i)) & 1)
    return bits


def bits_to_custom_encoding(bits):
    """Konversi bits ke encoding custom dengan banyak simbol"""
    # Character set dengan huruf, angka, dan simbol
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
    
    result = ""
    # Konversi setiap 7 bits ke karakter (7 bits = 128 kemungkinan, cukup untuk charset)
    for i in range(0, len(bits), 7):
        value = 0
        for j in range(7):
            if i+j < len(bits):
                value = (value << 1) | bits[i+j]
        # Pastikan value dalam range charset
        result += charset[value % len(charset)]
    
    return result


def permute(bits, table):
    return [bits[i-1] for i in table]


def left_shift(bits, n):
    return bits[n:] + bits[:n]


def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]


def generate_subkeys(key_bits):
    # PC1 permutation
    key = permute(key_bits, PC1)
    
    # Split menjadi C dan D (masing-masing 28 bits)
    C = key[:28]
    D = key[28:]
    
    subkeys = []
    for i in range(16):
        # Left shift
        C = left_shift(C, SHIFT[i])
        D = left_shift(D, SHIFT[i])
        
        # Gabungkan dan PC2 permutation
        CD = C + D
        subkey = permute(CD, PC2)
        subkeys.append(subkey)
    
    return subkeys


def f_function(R, subkey):
    # Expansion
    expanded = permute(R, E)
    
    # XOR dengan subkey
    xored = xor(expanded, subkey)
    
    # S-boxes
    output = []
    for i in range(8):
        # Ambil 6 bits untuk S-box ke-i
        block = xored[i*6:(i+1)*6]
        
        # Row: bit pertama dan terakhir
        row = (block[0] << 1) | block[5]
        
        # Column: 4 bits tengah
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        
        # S-box lookup
        val = S[i][row][col]
        
        # Konversi ke 4 bits
        for j in range(4):
            output.append((val >> (3-j)) & 1)
    
    # Permutation P
    return permute(output, P)


def des_encrypt(plaintext_bits, key_bits):
    # Generate subkeys
    subkeys = generate_subkeys(key_bits)
    
    # Initial Permutation
    bits = permute(plaintext_bits, IP)
    
    # Split menjadi L dan R
    L = bits[:32]
    R = bits[32:]
    
    # 16 rounds
    for i in range(16):
        L_new = R
        R_new = xor(L, f_function(R, subkeys[i]))
        L = L_new
        R = R_new
    
    # Gabungkan R dan L (reversed)
    combined = R + L
    
    # Final Permutation
    return permute(combined, FP)


def des_decrypt(ciphertext_bits, key_bits):
    # Generate subkeys (reversed order)
    subkeys = generate_subkeys(key_bits)
    subkeys.reverse()
    
    # Initial Permutation
    bits = permute(ciphertext_bits, IP)
    
    # Split menjadi L dan R
    L = bits[:32]
    R = bits[32:]
    
    # 16 rounds
    for i in range(16):
        L_new = R
        R_new = xor(L, f_function(R, subkeys[i]))
        L = L_new
        R = R_new
    
    # Gabungkan R dan L (reversed)
    combined = R + L
    
    # Final Permutation
    return permute(combined, FP)


def pad_text(text):
    padding_len = 8 - (len(text) % 8)
    padding = chr(padding_len) * padding_len
    return text + padding


def unpad_text(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]


def pad_key(key):
    if len(key) < 8:
        return key + '0' * (8 - len(key))
    return key[:8]


def encrypt_message(plaintext, key):
    """Fungsi utama untuk enkripsi plaintext dengan key"""
    # Padding
    key = pad_key(key)
    plaintext_padded = pad_text(plaintext)
    
    # Konversi ke bits
    key_bits = string_to_bits(key)
    
    # Enkripsi per block (8 bytes = 64 bits)
    ciphertext_bits = []
    for i in range(0, len(plaintext_padded), 8):
        block = plaintext_padded[i:i+8]
        block_bits = string_to_bits(block)
        encrypted_bits = des_encrypt(block_bits, key_bits)
        ciphertext_bits.extend(encrypted_bits)
    
    return ciphertext_bits


def decrypt_message(ciphertext_bits, key):
    """Fungsi utama untuk dekripsi ciphertext dengan key"""
    # Padding key
    key = pad_key(key)
    
    # Konversi ke bits
    key_bits = string_to_bits(key)
    
    # Dekripsi per block
    decrypted_bits = []
    for i in range(0, len(ciphertext_bits), 64):
        block_bits = ciphertext_bits[i:i+64]
        decrypted_block = des_decrypt(block_bits, key_bits)
        decrypted_bits.extend(decrypted_block)
    
    decrypted_text_padded = bits_to_string(decrypted_bits)
    decrypted_text = unpad_text(decrypted_text_padded)
    
    return decrypted_text

