import random

def is_prime(n, k=5):
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def generate_prime(bit_length):
    while True:
        p = random.getrandbits(bit_length)
        p |= (1 << bit_length - 1) | 1
        if is_prime(p): return p

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1

def mod_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    return x % phi if gcd == 1 else None

def generate_rsa_keypair(bit_length=512):
    p, q = generate_prime(bit_length // 2), generate_prime(bit_length // 2)
    n, phi = p * q, (p - 1) * (q - 1)
    e = 65537
    while extended_gcd(e, phi)[0] != 1:
        e = random.randrange(2, phi)
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def rsa_encrypt(plaintext, public_key):
    e, n = public_key
    if isinstance(plaintext, bytes):
        plaintext = int.from_bytes(plaintext, 'big')
    return pow(plaintext, e, n)

def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    plaintext_int = pow(ciphertext, d, n)
    byte_length = (plaintext_int.bit_length() + 7) // 8
    return plaintext_int.to_bytes(byte_length, 'big')
