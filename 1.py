from __future__ import annotations

# Core permutation and substitution tables from the DES specification.
IP = [58, 50, 42, 34, 26, 18, 10, 2,
	  60, 52, 44, 36, 28, 20, 12, 4,
	  62, 54, 46, 38, 30, 22, 14, 6,
	  64, 56, 48, 40, 32, 24, 16, 8,
	  57, 49, 41, 33, 25, 17, 9, 1,
	  59, 51, 43, 35, 27, 19, 11, 3,
	  61, 53, 45, 37, 29, 21, 13, 5,
	  63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
	  39, 7, 47, 15, 55, 23, 63, 31,
	  38, 6, 46, 14, 54, 22, 62, 30,
	  37, 5, 45, 13, 53, 21, 61, 29,
	  36, 4, 44, 12, 52, 20, 60, 28,
	  35, 3, 43, 11, 51, 19, 59, 27,
	  34, 2, 42, 10, 50, 18, 58, 26,
	  33, 1, 41, 9, 49, 17, 57, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9,
	   1, 58, 50, 42, 34, 26, 18,
	   10, 2, 59, 51, 43, 35, 27,
	   19, 11, 3, 60, 52, 44, 36,
	   63, 55, 47, 39, 31, 23, 15,
	   7, 62, 54, 46, 38, 30, 22,
	   14, 6, 61, 53, 45, 37, 29,
	   21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
	   3, 28, 15, 6, 21, 10,
	   23, 19, 12, 4, 26, 8,
	   16, 7, 27, 20, 13, 2,
	   41, 52, 31, 37, 47, 55,
	   30, 40, 51, 45, 33, 48,
	   44, 49, 39, 56, 34, 53,
	   46, 42, 50, 36, 29, 32]

E = [32, 1, 2, 3, 4, 5,
	 4, 5, 6, 7, 8, 9,
	 8, 9, 10, 11, 12, 13,
	 12, 13, 14, 15, 16, 17,
	 16, 17, 18, 19, 20, 21,
	 20, 21, 22, 23, 24, 25,
	 24, 25, 26, 27, 28, 29,
	 28, 29, 30, 31, 32, 1]

SBOXES = [
	[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
	 [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
	 [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
	 [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

	[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
	 [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
	 [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
	 [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

	[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
	 [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
	 [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
	 [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

	[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
	 [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
	 [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
	 [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

	[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
	 [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
	 [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
	 [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

	[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
	 [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
	 [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
	 [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

	[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
	 [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
	 [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
	 [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

	[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
	 [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
	 [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
	 [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

P = [16, 7, 20, 21,
	 29, 12, 28, 17,
	 1, 15, 23, 26,
	 5, 18, 31, 10,
	 2, 8, 24, 14,
	 32, 27, 3, 9,
	 19, 13, 30, 6,
	 22, 11, 4, 25]

SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def permute(block: list[int], table: list[int]) -> list[int]:
	return [block[i - 1] for i in table]


def bitlist_from_bytes(data: bytes) -> list[int]:
	return [(byte >> (7 - bit)) & 1 for byte in data for bit in range(8)]


def bytes_from_bitlist(bits: list[int]) -> bytes:
	chunks = [bits[i:i + 8] for i in range(0, len(bits), 8)]
	return bytes(int("".join(str(bit) for bit in chunk), 2) for chunk in chunks)


def left_shift(bits: list[int], n: int) -> list[int]:
	return bits[n:] + bits[:n]


def xor_bits(a: list[int], b: list[int]) -> list[int]:
	return [x ^ y for x, y in zip(a, b)]


def sbox_substitution(bits: list[int]) -> list[int]:
	output: list[int] = []
	for index in range(8):
		chunk = bits[index * 6:(index + 1) * 6]
		row = (chunk[0] << 1) | chunk[5]
		column = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
		value = SBOXES[index][row][column]
		output.extend([(value >> (3 - bit)) & 1 for bit in range(4)])
	return output


def generate_round_keys(key: bytes) -> list[list[int]]:
	key_bits = bitlist_from_bytes(key)
	permuted = permute(key_bits, PC1)
	c = permuted[:28]
	d = permuted[28:]
	round_keys: list[list[int]] = []
	for shift in SHIFT_SCHEDULE:
		c = left_shift(c, shift)
		d = left_shift(d, shift)
		combined = c + d
		round_keys.append(permute(combined, PC2))
	return round_keys


def feistel(right: list[int], subkey: list[int]) -> list[int]:
	expanded = permute(right, E)
	xored = xor_bits(expanded, subkey)
	substituted = sbox_substitution(xored)
	return permute(substituted, P)


def des_process(block: bytes, round_keys: list[list[int]], encrypt: bool) -> bytes:
	block_bits = bitlist_from_bytes(block)
	permuted = permute(block_bits, IP)
	left = permuted[:32]
	right = permuted[32:]
	keys = round_keys if encrypt else list(reversed(round_keys))
	for subkey in keys:
		new_right = xor_bits(left, feistel(right, subkey))
		left, right = right, new_right
	combined = right + left
	final_bits = permute(combined, FP)
	return bytes_from_bitlist(final_bits)


def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
	padding_len = block_size - (len(data) % block_size)
	return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes) -> bytes:
	if not data:
		raise ValueError("Invalid padding: empty data")
	padding_len = data[-1]
	if padding_len < 1 or padding_len > 8:
		raise ValueError("Invalid padding length")
	if data[-padding_len:] != bytes([padding_len] * padding_len):
		raise ValueError("Invalid padding bytes")
	return data[:-padding_len]


def des_encrypt(plaintext: bytes, key: bytes) -> bytes:
	if len(key) != 8:
		raise ValueError("DES key must be exactly 8 bytes")
	round_keys = generate_round_keys(key)
	padded = pkcs7_pad(plaintext)
	ciphertext_blocks = []
	for offset in range(0, len(padded), 8):
		block = padded[offset:offset + 8]
		ciphertext_blocks.append(des_process(block, round_keys, encrypt=True))
	return b"".join(ciphertext_blocks)


def des_decrypt(ciphertext: bytes, key: bytes) -> bytes:
	if len(key) != 8:
		raise ValueError("DES key must be exactly 8 bytes")
	if len(ciphertext) % 8 != 0:
		raise ValueError("Ciphertext length must be a multiple of 8 bytes")
	round_keys = generate_round_keys(key)
	plaintext_blocks = []
	for offset in range(0, len(ciphertext), 8):
		block = ciphertext[offset:offset + 8]
		plaintext_blocks.append(des_process(block, round_keys, encrypt=False))
	padded_plaintext = b"".join(plaintext_blocks)
	return pkcs7_unpad(padded_plaintext)


def demo():
	testcases = [
		{
			"title": "Plaintext 8 byte",
			"plaintext": b"ABCDEFGH",
			"key": b"SecKey01",
		},
		{
			"title": "Masukan 50 huruf A",
			"plaintext": b"A" * 50,
			"key": b"SecKey01",
		},
		{
			"title": "Plaintext sangat panjang",
			"plaintext": (
				"DES (Data Encryption Standard) adalah block cipher 64-bit yang menjalankan "
				"16 Feistel round. Implementasi ini melakukan padding otomatis sehingga "
				"plaintext sepanjang apapun bisa diproses. ".encode()
			),
			"key": b"SecKey01",
		},
		{
			"title": "Decrypt dengan key berbeda",
			"plaintext": b"Kunci salah menyebabkan hasil acak",
			"key": b"SecKey01",
			"alt_key": b"WrngKey!",
		},
	]

	for index, case in enumerate(testcases, start=1):
		print(f"\n=== Testcase {index}: {case['title']} ===")
		print("Plaintext   :", case["plaintext"])
		ciphertext = des_encrypt(case["plaintext"], case["key"])
		print("Key benar   :", case["key"].decode(errors="ignore"))
		print("Ciphertext  :", ciphertext.hex())
		decrypted = des_decrypt(ciphertext, case["key"])
		print("Decrypt OK  :", decrypted)
		if "alt_key" in case:
			try:
				print("Key berbeda :", case["alt_key"].decode(errors="ignore"))
				wrong = des_decrypt(ciphertext, case["alt_key"])
				print("Decrypt salah:", wrong)
			except ValueError as exc:
				# Invalid padding menandakan key salah karena struktur blok berubah.
				print("Decrypt salah: gagal dengan ValueError", exc)


if __name__ == "__main__":
	demo()

