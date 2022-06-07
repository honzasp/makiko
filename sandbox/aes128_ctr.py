def encrypt_manual(plaintext, key, iv):
    from Crypto.Cipher import AES
    aes = AES.new(key, AES.MODE_ECB)
    counter = int.from_bytes(iv, "big")
    ciphertext = []
    while plaintext:
        plain_block, plaintext = plaintext[:16], plaintext[16:]
        keystream_block = aes.encrypt(counter.to_bytes(16, "big"))
        ciphertext.extend(p ^ k for (p, k) in zip(plain_block, keystream_block))
        counter += 1
    return bytes(ciphertext)

def encrypt_crypto(plaintext, key, iv):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def print_ciphertext(what, ciphertext):
    print(what)
    while ciphertext:
        block, ciphertext = ciphertext[:16], ciphertext[16:]
        print(block.hex(" "))

key = bytes(range(0, 16))
iv = bytes(range(100, 116))
plaintext = ", ".join(["quick brown fox jumps over the lazy dog"] * 4).encode()
print_ciphertext("manual", encrypt_manual(plaintext, key, iv))
print_ciphertext("crypto", encrypt_crypto(plaintext, key, iv))
